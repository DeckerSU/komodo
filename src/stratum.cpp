// Copyright (c) 2020-2021 The Freicoin Developers
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#include "stratum.h"

#include "base58.h"
#include "chainparams.h"
// #include "consensus/merkle.h"
#include "consensus/validation.h"
#include "crypto/sha256.h"
#include "httpserver.h"
#include "miner.h"
#include "netbase.h"
#include "net.h"
// #include "rpc/blockchain.h"
#include "rpc/server.h"
#include "serialize.h"
#include "streams.h"
#include "sync.h"
#include "txmempool.h"
#include "uint256.h"
#include "util.h"
#include "utilstrencodings.h"
// #include "validation.h"

#include <univalue.h>

#include <algorithm> // for std::reverse
#include <string>
#include <vector>

#include <boost/algorithm/string.hpp> // for boost::trim
#include <boost/lexical_cast.hpp>
#include <boost/none.hpp>
#include <boost/optional.hpp>
#include <boost/thread.hpp>

#include <event2/event.h>
#include <event2/listener.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>

#include <errno.h>
#ifdef WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#endif

#include "main.h" // cs_main
#include <boost/foreach.hpp>
#include "ui_interface.h"
#include <memory> // make_unique

#include <locale>
#include <boost/date_time/posix_time/posix_time.hpp>

#include <chrono>
#include <thread>

extern uint16_t ASSETCHAINS_RPCPORT; // don't want to include komodo_globals.h
UniValue blockToJSON(const CBlock& block, const CBlockIndex* blockindex, bool txDetails = false); // rpc/blockchain.cpp
bool DecodeHexTx(CTransaction& tx, const std::string& strHexTx); // src/core_read.cpp

static const bool fstdErrDebugOutput = true;

/**
 * Begin of helper routines,
 * included: missed in httpserver.cpp in our codebase, missed
 * constructors for CSubNet(...), etc.
*/

namespace { // better to use anonymous namespace for helper routines

    // TODO: fix places which using CSubNet(...) constructors with numeric (/8, /16, /24, etc.) mask

    /** Check if a network address is allowed to access the Stratum server */
    bool ClientAllowed(const std::vector<CSubNet>& allowed_subnets, const CNetAddr& netaddr)
    {
        if (!netaddr.IsValid())
            return false;
        for(const CSubNet& subnet : allowed_subnets)
            if (subnet.Match(netaddr))
                return true;
        return false;
    }

    inline bool IsArgSet(const std::string& strArg)
    {
        return mapArgs.count(strArg);
    }

    inline std::vector<std::string> GetArgs(const std::string& strArg)
    {
        if (IsArgSet(strArg))
            return mapMultiArgs.at(strArg);
        return {};
    }

    /** Determine what addresses to bind to */
    bool InitEndpointList(const std::string& which, int defaultPort, std::vector<std::pair<std::string, uint16_t> >& endpoints)
    {
        endpoints.clear();

        // Determine what addresses to bind to
        const std::string opt_allowip = "-" + which + "allowip";
        const std::string opt_bind = "-" + which + "bind";
        if (IsArgSet(opt_allowip)) { // Default to loopback if not allowing external IPs
            endpoints.push_back(std::make_pair("::1", defaultPort));
            endpoints.push_back(std::make_pair("127.0.0.1", defaultPort));
            if (IsArgSet(opt_bind)) {
                LogPrintf("WARNING: option %s was ignored because %s was not specified, refusing to allow everyone to connect\n", opt_bind, opt_allowip);
            }
        } else if (IsArgSet(opt_bind)) { // Specific bind address
            for (const std::string& strRPCBind : GetArgs(opt_bind)) {
                int port = defaultPort;
                std::string host;
                SplitHostPort(strRPCBind, port, host);
                endpoints.push_back(std::make_pair(host, port));
            }
        } else { // No specific bind address specified, bind to any
            endpoints.push_back(std::make_pair("::", defaultPort));
            endpoints.push_back(std::make_pair("0.0.0.0", defaultPort));
        }

        return !endpoints.empty();
    }

    bool LookupHost(const char *pszName, CNetAddr& addr, bool fAllowLookup)
    {
        std::vector<CNetAddr> vIP;
        LookupHost(pszName, vIP, 1, fAllowLookup);
        if(vIP.empty())
            return false;
        addr = vIP.front();
        return true;
    }

    bool LookupSubNet(const char* pszName, CSubNet& ret)
    {
        std::string strSubnet(pszName);
        size_t slash = strSubnet.find_last_of('/');
        std::vector<CNetAddr> vIP;

        std::string strAddress = strSubnet.substr(0, slash);
        if (LookupHost(strAddress.c_str(), vIP, 1, false))
        {
            CNetAddr network = vIP[0];
            if (slash != strSubnet.npos)
            {
                std::string strNetmask = strSubnet.substr(slash + 1);
                int32_t n;
                // IPv4 addresses start at offset 12, and first 12 bytes must match, so just offset n
                if (ParseInt32(strNetmask, &n)) { // If valid number, assume /24 syntax
                    ret = CSubNet(network.ToString()); // TODO: should be CSubNet(const CNetAddr &addr, int32_t mask), where mask = n
                    return ret.IsValid();
                }
                else // If not a valid number, try full netmask syntax
                {
                    // Never allow lookup for netmask
                    if (LookupHost(strNetmask.c_str(), vIP, 1, false)) {
                        //ret = CSubNet(network, vIP[0]);
                        ret = CSubNet(network.ToString()); // TODO: should be CSubNet(const CNetAddr &addr, const CNetAddr &mask), where mask = vIP[0]
                        return ret.IsValid();
                    }
                }
            }
            else
            {
                ret = CSubNet(network.ToString());
                return ret.IsValid();
            }
        }
        return false;
    }

    /** Initialize ACL list for HTTP server */
    bool InitSubnetAllowList(const std::string which, std::vector<CSubNet>& allowed_subnets)
    {
        allowed_subnets.clear();
        CNetAddr localv4;
        CNetAddr localv6;
        LookupHost("127.0.0.1", localv4, false);
        LookupHost("::1", localv6, false);

        allowed_subnets.push_back(CSubNet(localv4.ToString(), false));      // always allow IPv4 local subnet (TODO: should be CSubNet(const CNetAddr &addr, int32_t mask), where mask = 8)
        allowed_subnets.push_back(CSubNet(localv6.ToString(), false));      // always allow IPv6 localhost

        const std::string opt_allowip = "-" + which + "allowip";
        for (const std::string& strAllow : GetArgs(opt_allowip)) {
            CSubNet subnet;
            LookupSubNet(strAllow.c_str(), subnet);
            if (!subnet.IsValid()) {
                uiInterface.ThreadSafeMessageBox(
                    strprintf("Invalid %s subnet specification: %s. Valid are a single IP (e.g. 1.2.3.4), a network/netmask (e.g. 1.2.3.4/255.255.255.0) or a network/CIDR (e.g. 1.2.3.4/24).", opt_allowip, strAllow),
                    "", CClientUIInterface::MSG_ERROR);
                return false;
            }
            allowed_subnets.push_back(subnet);
        }
        return true;
    }

    double GetDifficultyFromBits(uint32_t bits) {

        uint32_t powLimit = UintToArith256(Params().GetConsensus().powLimit).GetCompact();
        int nShift = (bits >> 24) & 0xff;
        int nShiftAmount = (powLimit >> 24) & 0xff;

        double dDiff =
            (double)(powLimit & 0x00ffffff) /
            (double)(bits & 0x00ffffff);

        while (nShift < nShiftAmount)
        {
            dDiff *= 256.0;
            nShift++;
        }
        while (nShift > nShiftAmount)
        {
            dDiff /= 256.0;
            nShift--;
        }

        return dDiff;
    }

    std::string DateTimeStrPrecise() // or we can use standart one, like DateTimeStrFormat("[%Y-%m-%d %H:%M:%S.%f]", GetTime())
    {
        // https://stackoverflow.com/questions/28136660/format-a-posix-time-with-just-3-digits-in-fractional-seconds
        // https://www.boost.org/doc/libs/1_35_0/doc/html/date_time/date_time_io.html#date_time.format_flags

        // std::locale takes ownership of the pointer
        boost::posix_time::ptime const date_time = boost::posix_time::microsec_clock::local_time();
        std::locale loc(std::locale::classic(), new boost::posix_time::time_facet("[%Y-%m-%d %H:%M:%S.%f] "));
        std::stringstream ss;
        ss.imbue(loc);
        // ss << boost::posix_time::from_time_t(nTime);
        ss << date_time;
        return ss.str();
    }


}

namespace ccminer {

    bool hex2bin(void *output, const char *hexstr, size_t len)
    {
        unsigned char *p = (unsigned char *) output;
        char hex_byte[4];
        char *ep;

        hex_byte[2] = '\0';

        while (*hexstr && len) {
            if (!hexstr[1]) {
                LogPrint("stratum", "hex2bin str truncated");
                return false;
            }
            hex_byte[0] = hexstr[0];
            hex_byte[1] = hexstr[1];
            *p = (unsigned char) strtol(hex_byte, &ep, 16);
            if (*ep) {
                LogPrint("stratum", "hex2bin failed on '%s'", hex_byte);
                return false;
            }
            p++;
            hexstr += 2;
            len--;
        }

        return (len == 0 && *hexstr == 0) ? true : false;
    }
    // equi/equi-stratum.cpp

    // ZEC uses a different scale to compute diff...
    // sample targets to diff (stored in the reverse byte order in work->target)
    // 0007fff800000000000000000000000000000000000000000000000000000000 is stratum diff 32
    // 003fffc000000000000000000000000000000000000000000000000000000000 is stratum diff 4
    // 00ffff0000000000000000000000000000000000000000000000000000000000 is stratum diff 1

    double target_to_diff_equi(uint32_t* target)
    {
        unsigned char* tgt = (unsigned char*) target;
        uint64_t m =
            (uint64_t)tgt[30] << 24 |
            (uint64_t)tgt[29] << 16 |
            (uint64_t)tgt[28] << 8  |
            (uint64_t)tgt[27] << 0;

        if (!m)
            return 0.;
        else
            return (double)0xffff0000UL/m;
    }

    void diff_to_target_equi(uint32_t *target, double diff)
    {
        uint64_t m;
        int k;

        for (k = 6; k > 0 && diff > 1.0; k--)
            diff /= 4294967296.0;
        m = (uint64_t)(4294901760.0 / diff);
        if (m == 0 && k == 6)
            memset(target, 0xff, 32);
        else {
            memset(target, 0, 32);
            target[k + 1] = (uint32_t)(m >> 8);
            target[k + 2] = (uint32_t)(m >> 40);
            //memset(target, 0xff, 6*sizeof(uint32_t));
            for (k = 0; k < 28 && ((uint8_t*)target)[k] == 0; k++)
                ((uint8_t*)target)[k] = 0xff;
        }
    }

    /* compute nbits to get the network diff */
    double equi_network_diff(uint32_t nbits)
    {
        //KMD bits: "1e 015971",
        //KMD target: "00 00 015971000000000000000000000000000000000000000000000000000000",
        //KMD bits: "1d 686aaf",
        //KMD target: "00 0000 686aaf0000000000000000000000000000000000000000000000000000",
        // uint32_t nbits = work->data[26];

        uint32_t bits = (nbits & 0xffffff);
        int16_t shift = (/*swab32*/bswap_32(nbits) & 0xff);
        shift = (31 - shift) * 8; // 8 bits shift for 0x1e, 16 for 0x1d
        uint64_t tgt64 = /*swab32*/bswap_32(bits);
        tgt64 = tgt64 << shift;
        // applog_hex(&tgt64, 8);
        uint8_t net_target[32] = { 0 };
        for (int b=0; b<8; b++)
            net_target[31-b] = ((uint8_t*)&tgt64)[b];
        // applog_hex(net_target, 32);
        double d = target_to_diff_equi((uint32_t*)net_target);
        return d;
    }

    double equi_stratum_target_to_diff(const std::string& target)
    {
        uint8_t target_bin[32], target_be[32];

        const char *target_hex = target.c_str();
        if (!target_hex || strlen(target_hex) == 0)
            return false;

        hex2bin(target_bin, target_hex, 32);
        memset(target_be, 0xff, 32);
        int filled = 0;
        for (int i=0; i<32; i++) {
            if (filled == 3) break;
            target_be[31-i] = target_bin[i];
            if (target_bin[i]) filled++;
        }

        double d = target_to_diff_equi((uint32_t*) &target_be);
        return d;
    }


}

/**
 * End of helper routines
*/

struct StratumClient
{
    evconnlistener* m_listener;
    evutil_socket_t m_socket;
    bufferevent* m_bev;
    CService m_from;
    int m_nextid;
    uint256 m_secret;

    CService GetPeer() const
      { return m_from; }

    std::string m_client;

    bool m_authorized;
    CBitcoinAddress m_addr;
    double m_mindiff;

    uint32_t m_version_rolling_mask;

    CBlockIndex* m_last_tip;
    bool m_second_stage;
    bool m_send_work;

    bool m_supports_aux;
    std::set<CBitcoinAddress> m_aux_addr;

    bool m_supports_extranonce;

    StratumClient() : m_listener(0), m_socket(0), m_bev(0), m_nextid(0), m_authorized(false), m_mindiff(0.0), m_version_rolling_mask(0x00000000), m_last_tip(0), m_second_stage(false), m_send_work(false), m_supports_aux(false), m_supports_extranonce(false) { GenSecret(); }
    StratumClient(evconnlistener* listener, evutil_socket_t socket, bufferevent* bev, CService from) : m_listener(listener), m_socket(socket), m_bev(bev), m_nextid(0), m_from(from), m_authorized(false), m_mindiff(0.0), m_version_rolling_mask(0x00000000), m_last_tip(0), m_second_stage(false), m_send_work(false), m_supports_aux(false), m_supports_extranonce(false) { GenSecret(); }

    void GenSecret();
    std::vector<unsigned char> ExtraNonce1(uint256 job_id) const;
};

void StratumClient::GenSecret()
{
    GetRandBytes(m_secret.begin(), 32);
}

std::vector<unsigned char> StratumClient::ExtraNonce1(uint256 job_id) const
{
    CSHA256 nonce_hasher;
    nonce_hasher.Write(m_secret.begin(), 32);

    if (m_supports_extranonce) {
        nonce_hasher.Write(job_id.begin(), 32);
    }

    uint256 job_nonce;
    nonce_hasher.Finalize(job_nonce.begin());
    return {job_nonce.begin(), job_nonce.begin()+8};
}

struct StratumWork {
    CBlockTemplate m_block_template;
    // First we generate the segwit commitment for the miner's coinbase with
    // ComputeFastMerkleBranch.
    std::vector<uint256> m_cb_wit_branch;
    // Then we compute the initial right-branch for the block-tx Merkle tree
    // using ComputeStableMerkleBranch...
    std::vector<uint256> m_bf_branch;
    // ...which is appended to the end of m_cb_branch so we can compute the
    // block's hashMerkleRoot with ComputeMerkleBranch.
    std::vector<uint256> m_cb_branch;
    bool m_is_witness_enabled;

    int32_t nHeight;

    // The cached 2nd-stage auxiliary hash value, if an auxiliary proof-of-work
    // solution has been found.
    boost::optional<uint256> m_aux_hash2;

    StratumWork() : m_is_witness_enabled(false),nHeight(0) { };
    StratumWork(const CBlockTemplate& block_template, bool is_witness_enabled);

    CBlock& GetBlock()
      { return m_block_template.block; }
    const CBlock& GetBlock() const
      { return m_block_template.block; }
};

StratumWork::StratumWork(const CBlockTemplate& block_template, bool is_witness_enabled)
    : m_block_template(block_template)
    , m_is_witness_enabled(is_witness_enabled), nHeight(0)
{
    // Generate the block-witholding secret for the work unit.
    // if (!m_block_template.block.m_aux_pow.IsNull()) {
    //     GetRandBytes((unsigned char*)&m_block_template.block.m_aux_pow.m_secret_lo, 8);
    //     GetRandBytes((unsigned char*)&m_block_template.block.m_aux_pow.m_secret_hi, 8);
    // }
    // How we use the various branch fields depends on whether segregated
    // witness is active.  If segwit is not active, m_cb_branch contains the
    // Merkle proof for the coinbase.  If segwit is active, we also use this
    // field in a different way, so we compute it in both branches.
    std::vector<uint256> leaves;
    for (const auto& tx : m_block_template.block.vtx) {
        leaves.push_back(tx.GetHash());
    }

    // m_cb_branch = ComputeMerkleBranch(leaves, 0);
    // If segwit is not active, we're done.  Otherwise...
    // if (m_is_witness_enabled) {
    //     // The final hash in m_cb_branch is the right-hand branch from
    //     // the root, which contains the block-final transaction (and
    //     // therefore the segwit commitment).
    //     m_cb_branch.pop_back();
    //     // To calculate the initial right-side hash, we need the path
    //     // to the root from the coinbase's position.  Again, the final
    //     // hash won't be known ahead of time because it depends on the
    //     // contents of the coinbase (which depends on both the miner's
    //     // payout address and the specific extranonce2 used).
    //     m_bf_branch = ComputeStableMerkleBranch(leaves, leaves.size()-1).first;
    //     m_bf_branch.pop_back();
    //     // To calculate the segwit commitment for the block-final tx,
    //     // we use a proof from the coinbase's position of the witness
    //     // Merkle tree.
    //     for (int i = 1; i < m_block_template.block.vtx.size()-1; ++i) {
    //         leaves[i] = m_block_template.block.vtx[i]->GetWitnessHash();
    //     }
    //     CMutableTransaction bf(*m_block_template.block.vtx.back());
    //     CScript& scriptPubKey = bf.vout.back().scriptPubKey;
    //     if (scriptPubKey.size() < 37) {
    //         throw std::runtime_error("Expected last output of block-final transaction to have enough room for segwit commitment, but alas.");
    //     }
    //     std::fill_n(&scriptPubKey[scriptPubKey.size()-37], 33, 0x00);
    //     leaves.back() = bf.GetHash();
    //     m_cb_wit_branch = ComputeFastMerkleBranch(leaves, 0).first;
    // }
};

void UpdateSegwitCommitment(const StratumWork& current_work, CMutableTransaction& cb, CMutableTransaction& bf, std::vector<uint256>& cb_branch)
{
    // Calculate witnessroot
    // CMutableTransaction cb2(cb);
    // cb2.vin[0].scriptSig = CScript();
    // cb2.vin[0].nSequence = 0;
    // auto witnessroot = ComputeFastMerkleRootFromBranch(cb2.GetHash(), current_work.m_cb_wit_branch, 0, nullptr);

    // Build block-final tx
    // CScript& scriptPubKey = bf.vout.back().scriptPubKey;
    // scriptPubKey[scriptPubKey.size()-37] = 0x01;
    // std::copy(witnessroot.begin(),
    //           witnessroot.end(),
    //           &scriptPubKey[scriptPubKey.size()-36]);

    // Calculate right-branch
    // auto pathmask = ComputeMerklePathAndMask(current_work.m_bf_branch.size() + 1, current_work.GetBlock().vtx.size() - 1);
    // cb_branch.push_back(ComputeStableMerkleRootFromBranch(bf.GetHash(), current_work.m_bf_branch, pathmask.first, pathmask.second, nullptr));
}

//! Critical seciton guarding access to any of the stratum global state
static CCriticalSection cs_stratum;

//! List of subnets to allow stratum connections from
static std::vector<CSubNet> stratum_allow_subnets;

//! Bound stratum listening sockets
static std::map<evconnlistener*, CService> bound_listeners;

//! Active miners connected to us
static std::map<bufferevent*, StratumClient> subscriptions;

//! Mapping of stratum method names -> handlers
static std::map<std::string, boost::function<UniValue(StratumClient&, const UniValue&)> > stratum_method_dispatch;

//! A mapping of job_id -> work templates
static std::map<uint256, StratumWork> work_templates;

//! The job_id of the first work unit to have its auxiliary proof-of-work solved
//! for the current block, or boost::none if no solution has been returned yet.
static boost::optional<uint256> half_solved_work;

//! A thread to watch for new blocks and send mining notifications
static boost::thread block_watcher_thread;

std::string HexInt4(uint32_t val)
{
    std::vector<unsigned char> vch;
    vch.push_back((val >> 24) & 0xff);
    vch.push_back((val >> 16) & 0xff);
    vch.push_back((val >>  8) & 0xff);
    vch.push_back( val        & 0xff);
    return HexStr(vch);
}

uint32_t ParseHexInt4(const UniValue& hex, const std::string& name)
{
    std::vector<unsigned char> vch = ParseHexV(hex, name);
    if (vch.size() != 4) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, name+" must be exactly 4 bytes / 8 hex");
    }
    uint32_t ret = 0;
    ret |= vch[0] << 24;
    ret |= vch[1] << 16;
    ret |= vch[2] <<  8;
    ret |= vch[3];
    return ret;
}

uint256 ParseUInt256(const UniValue& hex, const std::string& name)
{
    if (!hex.isStr()) {
        throw std::runtime_error(name+" must be a hexidecimal string");
    }
    std::vector<unsigned char> vch = ParseHex(hex.get_str());
    if (vch.size() != 32) {
        throw std::runtime_error(name+" must be exactly 32 bytes / 64 hex");
    }
    uint256 ret;
    std::copy(vch.begin(), vch.end(), ret.begin());
    return ret;
}

static double ClampDifficulty(const StratumClient& client, double diff)
{
    if (client.m_mindiff > 0) {
        diff = client.m_mindiff;
    }
    diff = std::max(diff, 0.001);
    return diff;
}

static std::string GetExtraNonceRequest(StratumClient& client, const uint256& job_id)
{
    std::string ret;
    if (client.m_supports_extranonce) {
        const std::string k_extranonce_req = std::string()
            + "{"
            +     "\"id\":";
        const std::string k_extranonce_req2 = std::string()
            +     ","
            +     "\"method\":\"mining.set_extranonce\","
            +     "\"params\":["
            +         "\"";
        const std::string k_extranonce_req3 = std::string()
            +            "\"," // extranonce1
            +         "4"      // extranonce2.size()
            +     "]"
            + "}"
            + "\n";

        ret = k_extranonce_req
            + strprintf("%d", client.m_nextid++)
            + k_extranonce_req2
            + HexStr(client.ExtraNonce1(job_id))
            + k_extranonce_req3;
    }
    return ret;
}

/**
 * @brief
 *
 * @param client
 * @param current_work
 * @param addr
 * @param extranonce1
 * @param extranonce2
 * @param cb
 * @param bf
 * @param cb_branch
 */
void CustomizeWork(const StratumClient& client, const StratumWork& current_work, const CBitcoinAddress& addr, const std::vector<unsigned char>& extranonce1, const std::vector<unsigned char>& extranonce2, CMutableTransaction& cb, CMutableTransaction& bf, std::vector<uint256>& cb_branch)
{
    if (current_work.GetBlock().vtx.empty()) {
        const std::string msg = strprintf("%s: no transactions in block template; unable to submit work", __func__);
        LogPrint("stratum", "%s\n", msg);
        throw std::runtime_error(msg);
    }

    cb = CMutableTransaction(current_work.GetBlock().vtx[0]);

    if (cb.vin.size() != 1) {
        const std::string msg = strprintf("%s: unexpected number of inputs; is this even a coinbase transaction?", __func__);
        LogPrint("stratum", "%s\n", msg);
        throw std::runtime_error(msg);
    }

    std::vector<unsigned char> nonce(extranonce1);
    if ((nonce.size() + extranonce2.size()) != 32) {
        const std::string msg = strprintf("%s: unexpected combined nonce length: extranonce1(%d) + extranonce2(%d) != 32; unable to submit work", __func__, nonce.size(), extranonce2.size());
        LogPrint("stratum", "%s\n", msg);
        throw std::runtime_error(msg);
    }
    nonce.insert(nonce.end(), extranonce2.begin(),
                              extranonce2.end());

    // nonce = extranonce1 + extranonce2
    // if (fstdErrDebugOutput) {
    //     std::cerr << __func__ << ": " << __FILE__ << "," << __LINE__ << " nonce = " << HexStr(nonce) << std::endl;
    // }

    if (cb.vin.empty()) {
        const std::string msg = strprintf("%s: first transaction is missing coinbase input; unable to customize work to miner", __func__);
        LogPrint("stratum", "%s\n", msg);
        throw std::runtime_error(msg);
    }
    // cb.vin[0].scriptSig =
    //        CScript()
    //     << cb.lock_height
    //     << nonce;

    // if (current_work.m_aux_hash2)
    // {
    //     cb.vin[0].scriptSig.insert(cb.vin[0].scriptSig.end(),
    //                                current_work.m_aux_hash2->begin(),
    //                                current_work.m_aux_hash2->end());
    // } else
    {
        if (cb.vout.empty()) {
            const std::string msg = strprintf("%s: coinbase transaction is missing outputs; unable to customize work to miner", __func__);
            LogPrint("stratum", "%s\n", msg);
            throw std::runtime_error(msg);
        }
        if (cb.vout[0].scriptPubKey == (CScript() << OP_FALSE)) {
            cb.vout[0].scriptPubKey = GetScriptForDestination(addr.Get());
        }
    }

    // cb_branch = current_work.m_cb_branch;
    // if (!current_work.m_aux_hash2 && current_work.m_is_witness_enabled) {
    //     bf = CMutableTransaction(*current_work.GetBlock().vtx.back());
    //     UpdateSegwitCommitment(current_work, cb, bf, cb_branch);
    //     LogPrint("stratum", "Updated segwit commitment in coinbase.\n");
    // }
}

uint256 CustomizeCommitHash(const StratumClient& client, const CBitcoinAddress& addr, const uint256& job_id, const StratumWork& current_work, const uint256& secret)
{
    // CMutableTransaction cb, bf;
    // std::vector<uint256> cb_branch;
    static const std::vector<unsigned char> dummy(4, 0x00); // extranonce2
    // CustomizeWork(client, current_work, addr, client.ExtraNonce1(job_id), dummy, cb, bf, cb_branch);

    // CMutableTransaction cb2(cb);
    // cb2.vin[0].scriptSig = CScript();
    // cb2.vin[0].nSequence = 0;

    // const AuxProofOfWork& aux_pow = current_work.GetBlock().m_aux_pow;

    CBlockHeader blkhdr;
    // blkhdr.nVersion = aux_pow.m_commit_version;
    blkhdr.hashPrevBlock = current_work.GetBlock().hashPrevBlock;
    // blkhdr.hashMerkleRoot = ComputeMerkleRootFromBranch(cb2.GetHash(), cb_branch, 0);
    // blkhdr.nTime = aux_pow.m_commit_time;
    // blkhdr.nBits = aux_pow.m_commit_bits;
    // blkhdr.nNonce = aux_pow.m_commit_nonce;
    uint256 hash = blkhdr.GetHash();

    // MerkleHash_Sha256Midstate(hash, hash, secret);
    return hash;
}

std::string GetWorkUnit(StratumClient& client)
{
    // LOCK(cs_main);

    /* if (!g_connman) {
        throw JSONRPCError(RPC_CLIENT_P2P_DISABLED, "Error: Peer-to-peer functionality missing or disabled");
    } */

    /* if (!Params().MineBlocksOnDemand() && g_connman->GetNodeCount(CConnman::CONNECTIONS_ALL) == 0) {
        throw JSONRPCError(RPC_CLIENT_NOT_CONNECTED, "Komodo is not connected!");
    } */

    bool fvNodesEmpty;
    {
        LOCK(cs_vNodes);
        fvNodesEmpty = vNodes.empty();
    }

    if (Params().MiningRequiresPeers() && fvNodesEmpty)
    {
        throw JSONRPCError(RPC_CLIENT_NOT_CONNECTED, "Komodo is not connected!");
    }

    if (IsInitialBlockDownload()) {
        throw JSONRPCError(RPC_CLIENT_IN_INITIAL_DOWNLOAD, "Komodo is downloading blocks...");
    }

    if (!client.m_authorized && client.m_aux_addr.empty()) {
        throw JSONRPCError(RPC_INVALID_REQUEST, "Stratum client not authorized.  Use mining.authorize first, with a Komodo address as the username.");
    }

    static CBlockIndex* tip = NULL; // pindexPrev
    static uint256 job_id;
    static unsigned int transactions_updated_last = 0;
    static int64_t last_update_time = 0;

    // When merge-mining is active, finding a block is a two-stage process.
    // First the auxiliary proof-of-work is solved, which requires constructing
    // a fake bitcoin block which commits to our Komodo block.  Then the
    // coinbase is updated to commit to the auxiliary proof-of-work solution and
    // the native proof-of-work is solved.
    // if (half_solved_work && (tip != chainActive.Tip() || !work_templates.count(*half_solved_work))) {
    //     half_solved_work = boost::none;
    // }

    // if (half_solved_work) {
    //     job_id = *half_solved_work;
    // } else

    // rpc/mining.cpp -> getblocktemplate -> Update block
    if ( tip != chainActive.Tip() ||
        (mempool.GetTransactionsUpdated() != transactions_updated_last && (GetTime() - last_update_time) > 5) ||
        !work_templates.count(job_id))
    {
        CBlockIndex *tip_new = chainActive.Tip();

        // CPubKey pubkey;
        // const CScript scriptPubKeyIn = CScript() << ToByteVector(pubkey) << OP_CHECKSIG;
        // std::unique_ptr<CBlockTemplate> new_work(CreateNewBlock(pubkey, scriptPubKeyIn, KOMODO_MAXGPUCOUNT, false)); // explicit unique_ptr( pointer p ) noexcept;

        /**
         * We will check script later inside CustomizeWork, if it will be == CScript() << OP_FALSE it will mean
         * that work need to be customized, and in that case cb.vout[0],scriptPubKey will be set to GetScriptForDestination(addr.Get()) .
         * In other words to the address with which stratum client is authorized.
        */
        const CScript scriptDummy = CScript() << OP_FALSE;
        std::unique_ptr<CBlockTemplate> new_work(CreateNewBlock(CPubKey(), scriptDummy, KOMODO_MAXGPUCOUNT, false)); // std::unique_ptr<CBlockTemplate> new_work = BlockAssembler(Params()).CreateNewBlock(script);

        /* test values for debug */
        // new_work->block.nBits = 0x200f0f0f;
        // new_work->block.nTime = 1623567886;
        // new_work->block.hashPrevBlock = uint256S("027e3758c3a65b12aa1046462b486d0a63bfa1beae327897f56c5cfb7daaae71");
        // new_work->block.hashMerkleRoot = uint256S("29f0e769c762b691d81d31bbb603719a94ef04d53d332f7de5e5533ddfd08e19");
        // new_work->block.hashFinalSaplingRoot = uint256S("3e49b5f954aa9d3545bc6c37744661eea48d7c34e3000d82b7f0010c30f4c2fb");
        // DecodeHexTx(new_work->block.vtx[0], "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff03510101ffffffff01aa2ce73b0000000023210325b4ca6736f90679f712be1454c5302050aae6edb51b0d2a051156bc868fec16ac4aabc560");


        if (!new_work) {
            throw JSONRPCError(RPC_OUT_OF_MEMORY, "Out of memory");
        }

        //if (fstdErrDebugOutput) std::cerr << __func__ << ": " << __FILE__ << "," << __LINE__ << "hashMerkleRoot = " << new_work->block.hashMerkleRoot.ToString() << std::endl;

        // So that block.GetHash() is correct
        //new_work->block.hashMerkleRoot = BlockMerkleRoot(new_work->block);
        new_work->block.hashMerkleRoot = new_work->block.BuildMerkleTree();
        // NB! here we have merkle with dummy script in coinbase, after CustomizeWork
        // we should recalculate it (!)

        //if (fstdErrDebugOutput) std::cerr << __func__ << ": " << __FILE__ << "," << __LINE__ << "hashMerkleRoot = " << new_work->block.hashMerkleRoot.ToString() << std::endl;

        job_id = new_work->block.GetHash();
        //work_templates[job_id] = StratumWork(*new_work, new_work->block.vtx[0]->HasWitness());
        work_templates[job_id] = StratumWork(*new_work, false);

        tip = tip_new;

        transactions_updated_last = mempool.GetTransactionsUpdated();
        last_update_time = GetTime();

        LogPrint("stratum", "New stratum block template (%d total): %s\n", work_templates.size(), HexStr(job_id.begin(), job_id.end()));

        // Remove any old templates
        std::vector<uint256> old_job_ids;
        boost::optional<uint256> oldest_job_id = boost::none;
        uint32_t oldest_job_nTime = last_update_time;
        for (const auto& work_template : work_templates) {
            // If, for whatever reason the new work was generated with
            // an old nTime, don't erase it!
            if (work_template.first == job_id) {
                continue;
            }
            // Build a list of outdated work units to free.
            if (work_template.second.GetBlock().nTime < (last_update_time - 900)) {
                old_job_ids.push_back(work_template.first);
            }
            // Track the oldest work unit, in case we have too much
            // recent work.
            if (work_template.second.GetBlock().nTime <= oldest_job_nTime) {
                oldest_job_id = work_template.first;
                oldest_job_nTime = work_template.second.GetBlock().nTime;
            }
        }
        // Remove all outdated work.
        for (const auto& old_job_id : old_job_ids) {
            work_templates.erase(old_job_id);
            LogPrint("stratum", "Removed outdated stratum block template (%d total): %s\n", work_templates.size(), HexStr(old_job_id.begin(), old_job_id.end()));
        }
        // Remove the oldest work unit if we're still over the maximum
        // number of stored work templates.
        if (work_templates.size() > 30 && oldest_job_id) {
            work_templates.erase(oldest_job_id.get());
            LogPrint("stratum", "Removed oldest stratum block template (%d total): %s\n", work_templates.size(), HexStr(oldest_job_id.get().begin(), oldest_job_id.get().end()));
        }
    }

    StratumWork& current_work = work_templates[job_id];


    CBlockIndex tmp_index;
    // Native proof-of-work difficulty
    tmp_index.nBits = current_work.GetBlock().nBits;
    double diff = ClampDifficulty(client, GetDifficulty(&tmp_index));

    // UniValue set_difficulty(UniValue::VOBJ);
    // set_difficulty.push_back(Pair("id", client.m_nextid++));
    // set_difficulty.push_back(Pair("method", "mining.set_difficulty"));
    // UniValue set_difficulty_params(UniValue::VARR);
    // set_difficulty_params.push_back(UniValue(diff));
    // set_difficulty.push_back(Pair("params", set_difficulty_params));

    UniValue set_target(UniValue::VOBJ);
    set_target.push_back(Pair("id", client.m_nextid++));
    set_target.push_back(Pair("method", "mining.set_target"));
    UniValue set_target_params(UniValue::VARR);

    std::string strTarget; // set_target
    {
        arith_uint256 hashTarget; bool fNegative,fOverflow;
        /*
        hashTarget.SetCompact(KOMODO_MINDIFF_NBITS,&fNegative,&fOverflow); // blkhdr.nBits
        hashTarget = UintToArith256(uint256S("0x0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f"));
        hashTarget.SetHex("0x0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f");
        hashTarget.SetHex("00ffff0000000000000000000000000000000000000000000000000000000000"); // komodo_diff = 15.0591, ccminer_diff = 1
        hashTarget.SetHex("003fffc000000000000000000000000000000000000000000000000000000000"); // komodo_diff = 60.2362, ccminer_diff = 4
        hashTarget.SetHex("0007fff800000000000000000000000000000000000000000000000000000000"); // komodo_diff = 481.89, ccminer_diff = 31.9999
        hashTarget.SetHex("c7ff3800ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); // komodo_diff = 0.0752956, ccminer_diff = 1.00303
        hashTarget.SetHex("0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f"); // komodo_diff = 1, ccminer_diff = 16.9956

        hashTarget.SetHex("00ffff0000000000000000000000000000000000000000000000000000000000"); // komodo_diff = 15.0591, ccminer_diff = 1


        */

        arith_uint256 aHashTarget = UintToArith256(uint256S("00ffff0000000000000000000000000000000000000000000000000000000000 ")); // 1.0
        // aHashTarget = aHashTarget / 8704; // komodo_diff = 131074 (NiceHash), ccminer_diff = 8704 (Yiimp)
        hashTarget = aHashTarget;

        strTarget = hashTarget.GetHex();

        if (fstdErrDebugOutput) {

            // bits = GetNextWorkRequired(blockindex, nullptr, Params().GetConsensus());
            // bits = blkhdr.nBits;
            // GetDifficultyFromBits(0x200f0f0f) == 1
            // %g - Use the shortest representation: %e or %f (c) http://www.cplusplus.com/reference/cstdio/printf/

            std::cerr << DateTimeStrPrecise() << __func__ << ": " << __FILE__ << "," << __LINE__ <<
                    strprintf(" target = %s, komodo_diff = %g, ccminer_diff = %g",
                    strTarget, GetDifficultyFromBits(hashTarget.GetCompact(false)), ccminer::equi_stratum_target_to_diff(strTarget)) << std::endl;
        }
    }

    set_target_params.push_back(UniValue(strTarget)); // TODO: send real local diff (!)
    set_target.push_back(Pair("params", set_target_params));

    // const CChainParams& chainparams = Params();
    // const Consensus::Params &consensusParams = chainparams.GetConsensus();
    // CMutableTransaction cb_prepare = CreateNewContextualCMutableTransaction(consensusParams, tip->GetHeight() + 1);

    CMutableTransaction cb, bf;
    std::vector<uint256> cb_branch;

    // if (fstdErrDebugOutput)
    // {
    //     std::cerr << __func__ << ": " << __FILE__ << "," << __LINE__ << " [1] cb = " << CTransaction(cb).ToString() << std::endl;
    //     std::cerr << __func__ << ": " << __FILE__ << "," << __LINE__ << " [1] current_work.GetBlock().vtx[0] = " << current_work.GetBlock().vtx[0].ToString() << std::endl;
    // }

    {
        // TODO: make ExtraNonce1 return 4 bytes values, instead of 8
        std::vector<unsigned char> extranonce1 = client.ExtraNonce1(job_id);
        extranonce1.resize(4);

        static const std::vector<unsigned char> dummy(32-extranonce1.size(), 0x00); // extranonce2
        CustomizeWork(client, current_work, client.m_addr, extranonce1, dummy, cb, bf, cb_branch);

        // current_work.GetBlock().vtx[0] = cb;
        // current_work.GetBlock().hashMerkleRoot = current_work.GetBlock().BuildMerkleTree();
        // current_work.nHeight = tip->GetHeight() + 1;

    }

    // if (fstdErrDebugOutput)
    // {
    //     std::cerr << __func__ << ": " << __FILE__ << "," << __LINE__ << " [2] cb = " << CTransaction(cb).ToString() << std::endl;
    //     std::cerr << __func__ << ": " << __FILE__ << "," << __LINE__ << " [2] current_work.GetBlock().vtx[0] = " << current_work.GetBlock().vtx[0].ToString() << std::endl;
    // }

    CBlockHeader blkhdr;
    // Setup native proof-of-work

    // blkhdr.nVersion = current_work.GetBlock().nVersion;
    // blkhdr.hashPrevBlock = current_work.GetBlock().hashPrevBlock;
    // blkhdr.nTime = current_work.GetBlock().nTime;
    // blkhdr.nBits = current_work.GetBlock().nBits;

    // copy entire blockheader created with CreateNewBlock to blkhdr
    blkhdr = current_work.GetBlock().GetBlockHeader();
    // blkhdr.hashPrevBlock = current_work.GetBlock().hashPrevBlock;
    // blkhdr.hashMerkleRoot = current_work.GetBlock().hashMerkleRoot;


    // CDataStream ds(SER_GETHASH, SERIALIZE_TRANSACTION_NO_WITNESS);
    CDataStream ds(SER_GETHASH, PROTOCOL_VERSION);
    ds << cb;

    // if (fstdErrDebugOutput)
    // {
    //     std::cerr << __func__ << ": " << __FILE__ << "," << __LINE__ << " set_target = "<< set_target.write() << std::endl;
    //     std::cerr << __func__ << ": " << __FILE__ << "," << __LINE__ << " ds = " << HexStr(ds, false) << std::endl;
    //     std::cerr << __func__ << ": " << __FILE__ << "," << __LINE__ << " cb.GetHash().ToString() = " << cb.GetHash().ToString() << std::endl;

    //     CBlockIndex index {blkhdr};
    //     index.SetHeight(tip->GetHeight() + 1);

    //     std::cerr << __func__ << ": " << __FILE__ << "," << __LINE__ << " blkhdr.hashPrevBlock = " << blkhdr.hashPrevBlock.GetHex() << std::endl;
    //     std::cerr << __func__ << ": " << __FILE__ << "," << __LINE__ << " blkhdr = " << blockToJSON(blkhdr, &index).write() << std::endl;
    //     std::cerr << __func__ << ": " << __FILE__ << "," << __LINE__ << " current_work.GetBlock() = " << blockToJSON(current_work.GetBlock(), &index).write() << std::endl;

    // }

    // ds << MakeTransactionRef(std::move(cb));
    // if (ds.size() < (4 + 1 + 32 + 4 + 1)) {
    //     throw std::runtime_error("Serialized transaction is too small to be parsed.  Is this even a coinbase?");
    // }

    // size_t pos = 4 + 1 + 32 + 4 + 1 + ds[4+1+32+4] - (current_work.m_aux_hash2? 32: 0);
    // if (ds.size() < pos) {
    //     throw std::runtime_error("Customized coinbase transaction does not contain extranonce field at expected location.");
    // }

    // std::string cb1 = HexStr(&ds[0], &ds[pos-4-8]);
    // std::string cb2 = HexStr(&ds[pos], &ds[ds.size()]);

    // {"id": null, "method": "mining.notify", "params": ["JOB_ID", "VERSION", "PREVHASH", "MERKLEROOT", "RESERVED", "TIME", "BITS", CLEAN_JOBS]}\n
    // {"id": null, "method": "mining.notify", "params": ["1", "04000000","71aeaa7dfb5c6cf5977832aebea1bf630a6d482b464610aa125ba6c358377e02","198ed0df3d53e5e57d2f333dd504ef949a7103b6bb311dd891b662c769e7f029","fbc2f4300c01f0b7820d00e3347c8da4ee614674376cbc45359daa54f9b5493e","0eaec560","0f0f0f20", true]}

    /*
        HexInt4(blkhdr.nVersion) = 00000004, so we can't use it here, will use swab conversion via 1 of 3 methods:

        (1) params.push_back(HexStr((unsigned char *)&blkhdr.nVersion, (unsigned char *)&blkhdr.nVersion + sizeof(blkhdr.nVersion))); // VERSION
        (2) std::vector<unsigned char> vnVersion(4, 0);
            WriteLE64(&vnVersion[0], blkhdr.nVersion);
            params.push_back(HexStr(vnVersion));
        (3) params.push_back(HexInt4(bswap_32(blkhdr.nVersion)));

            Bytes order, cheatsheet:

            [ need ] fbc2f4300c01f0b7820d00e3347c8da4ee614674376cbc45359daa54f9b5493e - HexStr(ToByteVector(blkhdr.hashFinalSaplingRoot))
            [ need ] fbc2f4300c01f0b7820d00e3347c8da4ee614674376cbc45359daa54f9b5493e - HexStr(blkhdr.hashFinalSaplingRoot)
            [ ---- ] 3e49b5f954aa9d3545bc6c37744661eea48d7c34e3000d82b7f0010c30f4c2fb - blkhdr.hashFinalSaplingRoot.GetHex()
            [ ---- ] 3e49b5f954aa9d3545bc6c37744661eea48d7c34e3000d82b7f0010c30f4c2fb - blkhdr.hashFinalSaplingRoot.ToString()
    */

    /* mining.notify params */
    UniValue params(UniValue::VARR); // mining.notify params
    params.push_back(HexStr(job_id.begin(), job_id.end())); // JOB_ID
    params.push_back(HexInt4(bswap_32(blkhdr.nVersion))); // VERSION (0x4 -> "04000000")
    params.push_back(HexStr(blkhdr.hashPrevBlock));  // PREVHASH
    params.push_back(HexStr(blkhdr.hashMerkleRoot)); // MERKLEROOT
    params.push_back(HexStr(blkhdr.hashFinalSaplingRoot)); // RESERVED -> hashFinalSaplingRoot

    // UpdateTime(&blkhdr, Params().GetConsensus(), tip /* or pindexPrev [tip-1] is needed? */);
    blkhdr.nTime = GetTime();

    params.push_back(HexInt4(bswap_32(blkhdr.nTime))); // TIME
    params.push_back(HexInt4(bswap_32(blkhdr.nBits))); // BITS
    // Clean Jobs. If true, miners should abort their current work and immediately use the new job. If false, they can still use the current job, but should move to the new one after exhausting the current nonce range.

    UniValue clean_jobs(UniValue::VBOOL);
    clean_jobs = client.m_last_tip != tip; // true
    params.push_back(clean_jobs); // CLEAN_JOBS


    // // For reasons of who-the-heck-knows-why, stratum byte-swaps each
    // // 32-bit chunk of the hashPrevBlock.
    // uint256 hashPrevBlock(blkhdr.hashPrevBlock);
    // for (int i = 0; i < 256/32; ++i) {
    //     ((uint32_t*)hashPrevBlock.begin())[i] = bswap_32(
    //     ((uint32_t*)hashPrevBlock.begin())[i]);
    // }
    // params.push_back(HexStr(hashPrevBlock.begin(), hashPrevBlock.end()));
    // params.push_back(cb1);
    // params.push_back(cb2);

    // UniValue branch(UniValue::VARR);
    // for (const auto& hash : cb_branch) {
    //     branch.push_back(HexStr(hash.begin(), hash.end()));
    // }
    // params.push_back(branch);

    // // if (!current_work.m_aux_hash2) {
    // //     int64_t delta = UpdateTime(&blkhdr, Params().GetConsensus(), tip);
    // //     LogPrint("stratum", "Updated the timestamp of block template by %d seconds\n", delta);
    // // }
    // UpdateTime(&blkhdr, Params().GetConsensus(), tip);
    // params.push_back(HexInt4(blkhdr.nVersion));
    // params.push_back(HexInt4(blkhdr.nBits));
    // params.push_back(HexInt4(blkhdr.nTime));
    // params.push_back(UniValue((client.m_last_tip != tip)
    //                        || (client.m_second_stage != bool(current_work.m_aux_hash2))));
    client.m_last_tip = tip;

    // client.m_second_stage = bool(current_work.m_aux_hash2);

    UniValue mining_notify(UniValue::VOBJ);
    mining_notify.push_back(Pair("id", client.m_nextid++));
    mining_notify.push_back(Pair("method", "mining.notify"));
    mining_notify.push_back(Pair("params", params));

    return GetExtraNonceRequest(client, job_id)
         + set_target.write() + "\n"
         + mining_notify.write()  + "\n";
}

/**
 * @brief
 *
 * @param client
 * @param job_id
 * @param current_work
 * @param extranonce1
 * @param extranonce2
 * @param nVersion
 * @param nTime
 * @param sol
 * @return true
 * @return false
 */
bool SubmitBlock(StratumClient& client, const uint256& job_id, const StratumWork& current_work,
                 const std::vector<unsigned char>& extranonce1, const std::vector<unsigned char>& extranonce2,
                 boost::optional<uint32_t> nVersion, uint32_t nTime, const std::vector<unsigned char>& sol)
{

    // if (fstdErrDebugOutput && extranonce1.size() > 3) {
    //     std::string sExtraNonce1 = HexStr(extranonce1);
    //     std::cerr << __func__ << ": " << __FILE__ << "," << __LINE__ << " " << strprintf("client.m_supports_extranonce = %d, [%d, %d, %d, %d], %s", client.m_supports_extranonce, extranonce1[0], extranonce1[1], extranonce1[2], extranonce1[3], sExtraNonce1) << std::endl;
    //     std::cerr << __func__ << ": " << __FILE__ << "," << __LINE__ << " extranonce1.size() = "  << extranonce1.size() << std::endl;
    // }

    if (extranonce1.size() != 4) {
        std::string msg = strprintf("extranonce1 is wrong length (received %d bytes; expected %d bytes", extranonce1.size(), 4);
        LogPrint("stratum", "%s\n", msg);
        throw JSONRPCError(RPC_INVALID_PARAMETER, msg);
    }
    if (extranonce2.size() != 28) {
        std::string msg = strprintf("%s: extranonce2 is wrong length (received %d bytes; expected %d bytes", __func__, extranonce2.size(), 28);
        LogPrint("stratum", "%s\n", msg);
        throw JSONRPCError(RPC_INVALID_PARAMETER, msg);
    }

    // TODO: change hardcoded constants on actual determine of solution size, depends on equihash algo type: 200.9, etc.
    if (sol.size() != 1347) {
        std::string msg = strprintf("%s: solution is wrong length (received %d bytes; expected %d bytes", __func__, extranonce2.size(), 1347);
        LogPrint("stratum", "%s\n", msg);
        throw JSONRPCError(RPC_INVALID_PARAMETER, msg);
    }

    // check equihash solution, VerifyEH (!)

    CMutableTransaction cb, bf;
    std::vector<uint256> cb_branch;
    CustomizeWork(client, current_work, client.m_addr, extranonce1, extranonce2, cb, bf, cb_branch);

    bool res = false;
    // if (!current_work.GetBlock().m_aux_pow.IsNull() && !current_work.m_aux_hash2) {
    //     // Check auxiliary proof-of-work
    //     uint32_t version = current_work.GetBlock().m_aux_pow.m_aux_version;
    //     if (nVersion && client.m_version_rolling_mask) {
    //         version = (version & ~client.m_version_rolling_mask)
    //                 | (*nVersion & client.m_version_rolling_mask);
    //     } else if (nVersion) {
    //         version = *nVersion;
    //     }

    //     CMutableTransaction cb2(cb);
    //     cb2.vin[0].scriptSig = CScript();
    //     cb2.vin[0].nSequence = 0;

    //     CBlockHeader blkhdr(current_work.GetBlock());
    //     blkhdr.m_aux_pow.m_commit_hash_merkle_root = ComputeMerkleRootFromBranch(cb2.GetHash(), cb_branch, 0);
    //     blkhdr.m_aux_pow.m_aux_branch.resize(1);
    //     blkhdr.m_aux_pow.m_aux_branch[0] = cb.GetHash();
    //     blkhdr.m_aux_pow.m_aux_num_txns = 2;
    //     blkhdr.nTime = nTime;
    //     blkhdr.m_aux_pow.m_aux_nonce = nNonce;
    //     blkhdr.m_aux_pow.m_aux_version = version;

    //     const Consensus::Params& params = Params().GetConsensus();
    //     res = CheckAuxiliaryProofOfWork(blkhdr, params);
    //     auto aux_hash = blkhdr.GetAuxiliaryHash(params);
    //     if (res) {
    //         LogPrintf("GOT AUXILIARY BLOCK!!! by %s: %s, %s\n", client.m_addr.ToString(), aux_hash.first.ToString(), aux_hash.second.ToString());
    //         blkhdr.hashMerkleRoot = ComputeMerkleRootFromBranch(cb.GetHash(), cb_branch, 0);
    //         uint256 new_job_id = blkhdr.GetHash();
    //         work_templates[new_job_id] = current_work;
    //         StratumWork& new_work = work_templates[new_job_id];
    //         new_work.GetBlock().vtx[0] = MakeTransactionRef(std::move(cb));
    //         if (new_work.m_is_witness_enabled) {
    //             new_work.GetBlock().vtx.back() = MakeTransactionRef(std::move(bf));
    //         }
    //         new_work.GetBlock().hashMerkleRoot = BlockMerkleRoot(new_work.GetBlock(), nullptr);
    //         new_work.m_cb_branch = cb_branch;
    //         new_work.GetBlock().m_aux_pow.m_commit_hash_merkle_root = blkhdr.m_aux_pow.m_commit_hash_merkle_root;
    //         new_work.GetBlock().m_aux_pow.m_aux_branch = blkhdr.m_aux_pow.m_aux_branch;
    //         new_work.GetBlock().m_aux_pow.m_aux_num_txns = blkhdr.m_aux_pow.m_aux_num_txns;
    //         new_work.GetBlock().nTime = nTime;
    //         new_work.GetBlock().m_aux_pow.m_aux_nonce = nNonce;
    //         new_work.GetBlock().m_aux_pow.m_aux_version = version;
    //         new_work.m_aux_hash2 = aux_hash.second;
    //         if (new_job_id != new_work.GetBlock().GetHash()) {
    //             throw std::runtime_error("First-stage hash does not match expected value.");
    //         }
    //         half_solved_work = new_job_id;
    //     } else {
    //         LogPrintf("NEW AUXILIARY SHARE!!! by %s: %s, %s\n", client.m_addr.ToString(), aux_hash.first.ToString(), aux_hash.second.ToString());
    //     }
    // }

    // else
    {
        // Check native proof-of-work
        uint32_t version = current_work.GetBlock().nVersion;

        // if (nVersion && client.m_version_rolling_mask) {
        //     version = (version & ~client.m_version_rolling_mask)
        //             | (*nVersion & client.m_version_rolling_mask);
        // } else
        if (nVersion) {
            version = *nVersion;
        }

        // if (fstdErrDebugOutput) {
        //     std::cerr << __func__ << ": " << __FILE__ << "," << __LINE__ << " nTime = " << nTime << strprintf(" (%08x)", nTime) << std::endl;
        //     std::cerr << __func__ << ": " << __FILE__ << "," << __LINE__ << " current_work.GetBlock().nTime = " << current_work.GetBlock().nTime << strprintf(" (%08x)", current_work.GetBlock().nTime) << std::endl;
        // }

        // if (fstdErrDebugOutput) {
        //     std::cerr << __func__ << ": " << __FILE__ << "," << __LINE__ << " nTime = " << nTime << strprintf(" (%08x)", nTime) << std::endl;
        //     std::cerr << __func__ << ": " << __FILE__ << "," << __LINE__ << " current_work.GetBlock().nTime = " << current_work.GetBlock().nTime << strprintf(" (%08x)", current_work.GetBlock().nTime) << std::endl;
        // }

        // if (/*!current_work.GetBlock().m_aux_pow.IsNull() &&*/ nTime != current_work.GetBlock().nTime) {
        //     LogPrintf("Error: miner %s returned altered nTime value for native proof-of-work; nTime-rolling is not supported\n", client.m_addr.ToString());
        //     throw JSONRPCError(RPC_INVALID_PARAMETER, "nTime-rolling is not supported");
        // }

        // CBlockHeader blkhdr;
        // CBlock blkhdr;
        CBlockHeader blkhdr(current_work.GetBlock());

        blkhdr.nVersion = version;
        blkhdr.hashPrevBlock = current_work.GetBlock().hashPrevBlock;
        // blkhdr.hashMerkleRoot = ComputeMerkleRootFromBranch(cb.GetHash(), cb_branch, 0);
        // blkhdr.hashMerkleRoot = blkhdr.BuildMerkleTree();
        blkhdr.nTime = nTime;
        blkhdr.nBits = current_work.GetBlock().nBits;

        // (!) should combime extranonce1 and extranonce2

        std::vector<unsigned char> noncerev(extranonce1);
        std::reverse(noncerev.begin(), noncerev.end());
        noncerev.insert(noncerev.begin(), extranonce2.rbegin(), extranonce2.rend());

        std::vector<unsigned char> nonce(extranonce1);
        nonce.insert(nonce.end(), extranonce2.begin(), extranonce2.end());

        // nonce = extranonce1 + extranonce2
        // if (fstdErrDebugOutput) {
        //     std::cerr << __func__ << ": " << __FILE__ << "," << __LINE__ << " nonce = " << HexStr(nonce) << std::endl;
        // }

        // ["WORKER_NAME", "JOB_ID", "TIME", "NONCE_2", "EQUIHASH_SOLUTION"] <- this comes from client (miner)
        // CustomizeWork: stratum.cpp,639 nonce = c2d9dd830000000000000000eacb000002000000000000000000000000000000
        // SubmitBlock: stratum.cpp,1183 blkhdr = c2d9dd830000000000000000eacb000002000000000000000000000000000000

        blkhdr.nSolution = std::vector<unsigned char>(sol.begin() + 3, sol.end());
        blkhdr.hashFinalSaplingRoot = current_work.GetBlock().hashFinalSaplingRoot;
        blkhdr.hashMerkleRoot = current_work.GetBlock().hashMerkleRoot;
        blkhdr.nNonce = nonce;

        //const CChainParams& chainparams = Params();
        // 7261205f5662e508d8cab9f2a3510055a1a5544eb033f0db912ec581ffabbf1c - 7261205f5662e508d8cab9f2a3510055a1a5544eb033f0db912ec581ffabbf1c
        // 7261205f5662e508d8cab9f2a3510055a1a5544eb033f0db912ec581ffabbf1c - 7261205f5662e508d8cab9f2a3510055a1a5544eb033f0db912ec581ffabbf1c
        // 3e49b5f954aa9d3545bc6c37744661eea48d7c34e3000d82b7f0010c30f4c2fb - 3e49b5f954aa9d3545bc6c37744661eea48d7c34e3000d82b7f0010c30f4c2fb

        // if (fstdErrDebugOutput) {
        //     CBlockIndex index {blkhdr};
        //     index.SetHeight(current_work.nHeight);
        //     std::cerr << __func__ << ": " << __FILE__ << "," << __LINE__ << " blkhdr.hashPrevBlock = " << blkhdr.hashPrevBlock.GetHex() << std::endl;
        //     std::cerr << __func__ << ": " << __FILE__ << "," << __LINE__ << " blkhdr = " << blockToJSON(blkhdr, &index).write() << std::endl;
        // }

        {
            // LOCK(cs_main);
            arith_uint256 bnTarget; bool fNegative, fOverflow;
            bnTarget.SetCompact(blkhdr.nBits, &fNegative, &fOverflow);
            // check range
            // if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(params.powLimit))
            //     return false;
            if (UintToArith256(blkhdr.GetHash()) > bnTarget) {
                res = false;
            } else {
                uint8_t pubkey33[33]; int32_t height = current_work.nHeight;
                res = CheckProofOfWork(blkhdr, pubkey33, height, Params().GetConsensus());
            }
            if (fstdErrDebugOutput) std::cerr << DateTimeStrPrecise() << "res[1] = " << res << std::endl;
        }

        uint256 hash = blkhdr.GetHash();

        if (fstdErrDebugOutput)
        {
            // bits = GetNextWorkRequired(blockindex, nullptr, Params().GetConsensus());
            // bits = blkhdr.nBits;
            uint256 hashTarget = ArithToUint256(arith_uint256().SetCompact(blkhdr.nBits));
            std::string strTarget = hashTarget.ToString();

            std::cerr << DateTimeStrPrecise() << __func__ << ": " << __FILE__ << "," << __LINE__ <<
                     strprintf(" [%d] hash = %s, komodo_diff = %g, ccminer_diff = %g", current_work.GetBlock().vtx.size(),
                     blkhdr.GetHash().ToString(),
                     GetDifficultyFromBits(UintToArith256(blkhdr.GetHash()).GetCompact()),
                     ccminer::equi_stratum_target_to_diff(blkhdr.GetHash().ToString())) << std::endl;
        }

        if (res) {

            LogPrintf("GOT BLOCK!!! by %s: %s\n", client.m_addr.ToString(), hash.ToString());

            CBlock block(current_work.GetBlock());
            // block.vtx[0] = MakeTransactionRef(std::move(cb));
            block.vtx[0] = cb;

            // if (!current_work.m_aux_hash2 && current_work.m_is_witness_enabled) {
            //     block.vtx.back() = MakeTransactionRef(std::move(bf));
            // }
            block.nVersion = version;
            // block.hashMerkleRoot = BlockMerkleRoot(block);
            block.hashMerkleRoot = block.BuildMerkleTree();
            //if (fstdErrDebugOutput) std::cerr << "hashMerkleRoot = " << block.hashMerkleRoot.GetHex() << std::endl;

            block.nTime = nTime;
            // block.nNonce = nNonce;
            // nNonce <<= 32; nNonce >>= 16; // clear the top and bottom 16 bits (for local use as thread flags and counters)

            block.nNonce = nonce;
            block.nSolution = std::vector<unsigned char>(sol.begin() + 3, sol.end());


            std::shared_ptr<const CBlock> pblock = std::make_shared<const CBlock>(block);
            // res = ProcessNewBlock(Params(), pblock, true, NULL);
            CValidationState state;

            if(fstdErrDebugOutput) {
                CBlockIndex index {blkhdr};
                index.SetHeight(-1);
                std::cerr << "block = " << blockToJSON(block, &index, true).write(1) << std::endl;
                std::cerr << "CheckEquihashSolution = " << CheckEquihashSolution(&block, Params()) << std::endl;
            }

            res = ProcessNewBlock(0,0,state, NULL, &block, true /* forceProcessing */ , NULL);

            if (fstdErrDebugOutput) std::cerr << DateTimeStrPrecise() << "res[2] = " << res << std::endl;

            if (res) {
                // LOCK(cs_main);
                if (!mapBlockIndex.count(hash)) {
                    LogPrintf("Unable to find new block index entry; cannot prioritise block 0x%s\n", hash.ToString());
                } else
                {
                    CBlockIndex* block_index = mapBlockIndex.at(hash);
                    CValidationState state;
                    // we haven't PreciousBlock, so we can't prioritize the block this way for now

                    // PreciousBlock(state, Params(), block_index);
                    // if (!state.IsValid()) {
                    //     LogPrintf("Database error while prioritising new block 0x%s: %d (%s) %s\n", hash.ToString(), state.GetRejectCode(), state.GetRejectReason(), state.GetDebugMessage());
                    // }
                }
            }
        } else {
            LogPrintf("NEW SHARE!!! by %s: %s\n", client.m_addr.ToString(), hash.ToString());
        }
    }

    if (res) {
        client.m_send_work = true;
    }

    return res;
}

bool SubmitAuxiliaryBlock(StratumClient& client, const CBitcoinAddress& addr, const uint256& job_id, const StratumWork& current_work, CBlockHeader& blkhdr)
{
    // CMutableTransaction cb, bf;
    // std::vector<uint256> cb_branch;
    // static const std::vector<unsigned char> dummy(4, 0x00); // extranonce2
    // CustomizeWork(client, current_work, addr, client.ExtraNonce1(job_id), dummy, cb, bf, cb_branch);

    // CMutableTransaction cb2(cb);
    // cb2.vin[0].scriptSig = CScript();
    // cb2.vin[0].nSequence = 0;

    // blkhdr.m_aux_pow.m_commit_hash_merkle_root = ComputeMerkleRootFromBranch(cb2.GetHash(), cb_branch, 0);

    // const Consensus::Params& params = Params().GetConsensus();
    // auto aux_hash = blkhdr.GetAuxiliaryHash(params);
    // if (!CheckAuxiliaryProofOfWork(blkhdr, params)) {
    //     LogPrintf("NEW AUXILIARY SHARE!!! by %s: %s, %s\n", addr.ToString(), aux_hash.first.ToString(), aux_hash.second.ToString());
    //     return false;
    // }

    // LogPrintf("GOT AUXILIARY BLOCK!!! by %s: %s, %s\n", addr.ToString(), aux_hash.first.ToString(), aux_hash.second.ToString());
    // blkhdr.hashMerkleRoot = ComputeMerkleRootFromBranch(cb.GetHash(), cb_branch, 0);

    // uint256 new_job_id = blkhdr.GetHash();
    // work_templates[new_job_id] = current_work;
    // StratumWork& new_work = work_templates[new_job_id];
    // new_work.GetBlock().vtx[0] = MakeTransactionRef(std::move(cb));
    // if (new_work.m_is_witness_enabled) {
    //     new_work.GetBlock().vtx.back() = MakeTransactionRef(std::move(bf));
    // }
    // new_work.GetBlock().hashMerkleRoot = BlockMerkleRoot(new_work.GetBlock(), nullptr);
    // new_work.m_cb_branch = cb_branch;
    // new_work.GetBlock().m_aux_pow = blkhdr.m_aux_pow;
    // new_work.GetBlock().nTime = blkhdr.nTime;
    // new_work.m_aux_hash2 = aux_hash.second;
    // if (new_job_id != new_work.GetBlock().GetHash()) {
    //     throw std::runtime_error("First-stage hash does not match expected value.");
    // }

    // half_solved_work = new_job_id;
    // client.m_send_work = true;

    return false;
}

void BoundParams(const std::string& method, const UniValue& params, size_t min, size_t max)
{
    if (params.size() < min) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s expects at least %d parameters; received %d", method, min, params.size()));
    }

    if (params.size() > max) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s receives no more than %d parameters; got %d", method, max, params.size()));
    }
}

UniValue stratum_mining_subscribe(StratumClient& client, const UniValue& params)
{
    const std::string method("mining.subscribe");
    BoundParams(method, params, 0, 4);

    if (params.size() >= 1) {
        client.m_client = params[0].get_str();
        LogPrint("stratum", "Received subscription from client %s\n", client.m_client);
    }

    // According to 'Stratum protocol changes for ZCash' - https://github.com/slushpool/poclbm-zcash/wiki/Stratum-protocol-changes-for-ZCash
    // mining.subscribe params looks like following:

    // {"id": 1, "method": "mining.subscribe", "params": ["CONNECT_HOST", CONNECT_PORT, "MINER_USER_AGENT", "SESSION_ID"]}
    // So, params[params.size()-1] should be SESSION_ID, but currently we don't support it.

    // Also we should answer with these:
    // {"id": 1, "result": ["SESSION_ID", "NONCE_1"], "error": null}
    // {"id":1,"result":[null,"81000001"],"error":null}

    // NONCE_1 is first part of the block header nonce (in hex).

    // By protocol, Zcash's nonce is 32 bytes long. The miner will pick NONCE_2 such that len(NONCE_2) = 32 - len(NONCE_1).
    // Please note that Stratum use hex encoding, so you have to convert NONCE_1 from hex to binary before.

    // ["CONNECT_HOST", CONNECT_PORT, "MINER_USER_AGENT", "SESSION_ID"]
    // ["NiceHash/1.0.0", null, "stratum3.decker.host", 18776] // ua, session_id, host, port?
    // ["ccminer/2.3.1"]

    UniValue ret(UniValue::VARR);

    // ExtraNonce1 -> client.m_supports_extranonce is false, so the job_id isn't used
    std::vector<unsigned char> vExtraNonce1 = client.ExtraNonce1(uint256());

    std::string sExtraNonce1 = HexStr(vExtraNonce1.begin(), vExtraNonce1.begin()
        + (vExtraNonce1.size() > 3 ? 4 : vExtraNonce1.size()));

    /**
     * Potentially we can use something like strprintf("%08x", GetRand(std::numeric_limits<uint64_t>::max())
     * here to generate sExtraNonce1, but don't forget that client.ExtraNonce1 method return 8 bytes
     * job_nonce:8 = sha256(client.m_secret:32 + client.job_id:32) , so, somewhere in future we can re-calculate
     * sExtraNonce1 for a given client based on m_secret.
     */

    // if (fstdErrDebugOutput && vExtraNonce1.size() > 3) {
    //     std::cerr << __func__ << ": " << __FILE__ << "," << __LINE__ << " " << strprintf("client.m_supports_extranonce = %d, [%d, %d, %d, %d], %s", client.m_supports_extranonce, vExtraNonce1[0], vExtraNonce1[1], vExtraNonce1[2], vExtraNonce1[3], sExtraNonce1) << std::endl;
    //     // recalc from client.m_secret example
    //     uint256 sha256;
    //     CSHA256().Write(client.m_secret.begin(), 32).Finalize(sha256.begin());
    //     std::cerr << __func__ << ": " << __FILE__ << "," << __LINE__ << " " << HexStr(std::vector<unsigned char>(sha256.begin(), sha256.begin() + 4)) << std::endl;
    // }

    ret.push_back(NullUniValue);
    ret.push_back(sExtraNonce1);

    // On mining.subscribe we don't need ti send anything else, we will send
    // mining.set_target and mining.notify bit later, inside GetWorkUnit.
    // Scheme is the following:
    // 1. stratum_read_cb(bufferevent * bev, void * ctx)
    // 2. if (client.m_send_work) -> GetWorkUnit
    // 3. CustomizeWork (throw if error and exit from GetWorkUnit)
    // 4. set_target
    // 5. ...
    // Last. GetWorkUnit returns string data (!) to send to client ( ... + mining.set_target + mining.notify + ... )


    // Some mining proxies (e.g. Nicehash) reject connections that don't send
    // a reasonable difficulty on first connection.  The actual value will be
    // overridden when the miner is authorized and work is delivered.  Oh, and
    // for reasons unknown it is sent in serialized float format rather than
    // as a numeric value...

    // UniValue msg(UniValue::VARR);
    // UniValue set_difficulty(UniValue::VARR);
    // set_difficulty.push_back("mining.set_difficulty");
    // set_difficulty.push_back("1e+06"); // Will be overriden by later
    // msg.push_back(set_difficulty);     // work delivery messages.

    // UniValue notify(UniValue::VARR);
    // notify.push_back("mining.notify");
    // notify.push_back("ae6812eb4cd7735a302a8a9dd95cf71f");
    // msg.push_back(notify);

    // UniValue ret(UniValue::VARR);
    // ret.push_back(msg);
    // // client.m_supports_extranonce is false, so the job_id isn't used.
    // ret.push_back(HexStr(client.ExtraNonce1(uint256())));
    // ret.push_back(UniValue(4)); // sizeof(extranonce2)

    return ret;
}

UniValue stratum_mining_authorize(StratumClient& client, const UniValue& params)
{
    const std::string method("mining.authorize");
    BoundParams(method, params, 1, 2);

    std::string username = params[0].get_str();
    boost::trim(username);

    // params[1] is the client-provided password.  We do not perform
    // user authorization, so we ignore this value.

    double mindiff = 0.0;
    size_t pos = username.find('+');
    if (pos != std::string::npos) {
        // Extract the suffix and trim it
        std::string suffix(username, pos+1);
        boost::trim_left(suffix);
        // Extract the minimum difficulty request
        mindiff = boost::lexical_cast<double>(suffix);
        // Remove the '+' and everything after
        username.resize(pos);
        boost::trim_right(username);
    }

    CBitcoinAddress addr(username);

    if (!addr.IsValid()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Invalid Komodo address: %s", username));
    }

    client.m_addr = addr;
    client.m_mindiff = mindiff;
    client.m_authorized = true;

    client.m_send_work = true;

    LogPrintf("Authorized stratum miner %s from %s, mindiff=%f\n", addr.ToString(), client.GetPeer().ToString(), mindiff);

    return true;
}

UniValue stratum_mining_aux_authorize(StratumClient& client, const UniValue& params)
{
    const std::string method("mining.aux.authorize");
    BoundParams(method, params, 1, 2);

    std::string username = params[0].get_str();
    boost::trim(username);

    // The second parameter is the password.  We don't actually do any
    // authorization, so we ignore the password field.

    size_t pos = username.find('+');
    if (pos != std::string::npos) {
        // Ignore suffix.
        username.resize(pos);
        boost::trim_right(username);
    }

    CBitcoinAddress addr(username);
    if (!addr.IsValid()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Invalid Komodo address: %s", username));
    }
    if (client.m_aux_addr.count(addr)) {
        LogPrint("stratum", "Client with address %s is already registered for stratum miner %s\n", addr.ToString(), client.GetPeer().ToString());
        return addr.ToString();
    }

    client.m_aux_addr.insert(addr);
    client.m_send_work = true;

    LogPrintf("Authorized client %s of stratum miner %s\n", addr.ToString(), client.GetPeer().ToString());

    return addr.ToString();
}

UniValue stratum_mining_aux_deauthorize(StratumClient& client, const UniValue& params)
{
    const std::string method("mining.aux.deauthorize");
    BoundParams(method, params, 1, 1);

    std::string username = params[0].get_str();
    boost::trim(username);

    size_t pos = username.find('+');
    if (pos != std::string::npos) {
        // Ignore suffix.
        username.resize(pos);
        boost::trim_right(username);
    }

    CBitcoinAddress addr(username);
    if (!addr.IsValid()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Invalid Komodo address: %s", username));
    }
    if (!client.m_aux_addr.count(addr)) {
        LogPrint("stratum", "No client with address %s is currently registered for stratum miner %s\n", addr.ToString(), client.GetPeer().ToString());
        return false;
    }

    client.m_aux_addr.erase(addr);

    LogPrintf("Deauthorized client %s of stratum miner %s\n", addr.ToString(), client.GetPeer().ToString());

    return true;
}

UniValue stratum_mining_configure(StratumClient& client, const UniValue& params)
{
    const std::string method("mining.configure");
    BoundParams(method, params, 2, 2);

    UniValue res(UniValue::VOBJ);

    UniValue extensions = params[0].get_array();
    UniValue config = params[1].get_obj();
    for (int i = 0; i < extensions.size(); ++i) {
        std::string name = extensions[i].get_str();

        if ("version-rolling" == name) {
            uint32_t mask = ParseHexInt4(find_value(config, "version-rolling.mask"), "version-rolling.mask");
            size_t min_bit_count = find_value(config, "version-rolling.min-bit-count").get_int();
            client.m_version_rolling_mask = mask & 0x1fffe000;
            res.push_back(Pair("version-rolling", true));
            res.push_back(Pair("version-rolling.mask", HexInt4(client.m_version_rolling_mask)));
            LogPrint("stratum", "Received version rolling request from %s\n", client.GetPeer().ToString());
        }

        else {
            LogPrint("stratum", "Unrecognized stratum extension '%s' sent by %s\n", name, client.GetPeer().ToString());
        }
    }

    return res;
}

UniValue stratum_mining_submit(StratumClient& client, const UniValue& params)
{
    // {"id": 4, "method": "mining.submit", "params": ["WORKER_NAME", "JOB_ID", "TIME", "NONCE_2", "EQUIHASH_SOLUTION"]}\n

    // NONCE_1 is first part of the block header nonce (in hex).
    // By protocol, Zcash's nonce is 32 bytes long. The miner will pick NONCE_2 such that len(NONCE_2) = 32 - len(NONCE_1). Please note that Stratum use hex encoding, so you have to convert NONCE_1 from hex to binary before.
    // NONCE_2 is the second part of the block header nonce.
    /**
     *
     * {"method":"mining.submit","params":[
        [0] WORKER_NAME "RDeckerSubnU8QVgrhj27apzUvbVK3pnTk",
        [1] JOB_ID "1",
        [2] TIME "0eaec560",
        [3] NONCE_2 "0000000000000000d890000001000000000000000000000000000000",
        [4] EQUIHASH_SOLUTION(1347) "fd400501762fe7c0d228a4b249727f52d85c3d5d989b3f9d07148506820a50e6db2ba3456b4ccfb168d7eb65651c7d7b893d87fb77077b56224a6fc9b9ca283b7a44a25be67d956ee55f9aaeca80eae765076495fd2eb50cf3e279a68dfd15ae6b30e911db6331d6717f352510b5834d3045db3833cdf74d1fe8379ab7b4fe46fe0d855c964085d5779701a25dbcd601ea87fb5d4bbe16c39e9c5fa22c874b4922605ed21411353cef39ce02b954a09961742d8011060a3c45f6b5b316d4a1d75530bd45722945d7a8d4698e75f49b86a485b7f1851b47d10d66d74eebb492c4269d34ca3691a459a80427f79f6d01e469bb250715fc49420d6e87383b598804bdf8b50b8510e44fd0740aa5650ed5ba19543c8657f67b5164d610bbb0ab75da1c48e81e9a8a9861bc119a31c695c5c3530ae271cf9ab4a2fa08d2b4fc851e273c324dc926d6901ca20ba5fed13118f12925760871909e8351d9e944c2959a61bf74238a587dd32826de63ab4819473bb3fad67c9a54baeddd137cb6350a25969531fa055dee51464b36cbdfb6afc4be0cee0f0fe11188c8d70d0238b3ba0c6459cd34d8b7bd8b1cdaa2b7728d51269707a70c54faac778eb4bcb6492e5fcc32406ed87fdfaecc52c9f461af3f4c3c51b529e2ab9a0e15a15b3cdcb35fe3bfe4854952ae975e3171cd2600a54509d386d45ecf668b5a17249b157a13212d0e465bc1796048d63c7b4027cb0850b9607261800e4fe6217e1fba2a28601aec9b524dac787a6c14df668a7c4fabf51f8885be7ed84ca72d0ff9a7491fddae1f5309441d243cb6d5c5c4f45a08b1b858bd15ef4d1ca1565c39000f9298b52e4221723457a0ec2e904aa6cd96e854cd8c1bbd07f1c9237c831d694817227aafe7873c43826e691d3971e82e87b538c42a48603696075b19c72b85c7d20863635621da1939d9024a434f6d840cac7a30058a51650485eabf9c0735163fd9b468249ea5889c62b4f739f58665d7f8c5010a661c1355ea7e9d85b6a18424b0027e86df5aa42b1bc2bb7a38b69c8db620251c4138b69956235640c502e26185d923a045777919984e71558edb77fb54981c6ac3dc979cd0b4f704874f02536daae894da78f31913554f91a30d6badc935fe58cc9d29d152138dde520ddb9906966e077ee3380641ce88fa74a658245202a8183e1807100c3f7d22df6577f309e4d85429e94a6f6f5dbaec3653ca6414bf6ed8794db84b7860be1984cb525b235cdb263cd527c74aa6d336615e1d361f4965ddad1fd191bc4a72fa92acc13a7c92b6e0ee077d70911004f422813e408a49ba38b950ead458b72cacb1ede9e35e2fd002eaaad0ecc2cf62801e4fe010a2cfd7190c51337513f1819acf170dda5f3b23452f36d28c20509a39fedd658f45c5e58a02feb64b0e027e05804350afc3220e53fe1761e93d018f3be9eb3554ecc98fe9fdc584ac06c0dcd63812180e94876f42f2955e242358d590a8b521b641b9729e6c7dcf6164571758ac2b2ee7656f0b0e986abf7f6b569daca304c944ded083ff202a80e8636fe9aeae39707401b321a6094c4a59cc7bcec9852189c746697963f7062304d57335795ec60dd49081a4329d3b1a8c9d55f67d11f36fb54133e67fe8a362a1f8db601aa054d97d3002f898374fd201f10af65393c9c3634e0139551e362da976b7aa0f4f8156aef59620bd24a216663784d205ef5976aa3cf6a9eed571de7cb350a355c35b67c621184608f72357d32d49842e5534f232567ed7ef9a0edc109b3b487e86d1cdd9231969a76e5d7c54bc3e28942e99301a89c13895c2bc5acac2111f53182951183f50c839601dc5fabfd39d95258c79b93a140ab727288179ce1262b13e8cc5a829edf26e7d241fbf6b"
        ],
        "id":10}
     */

    const std::string method("mining.submit");
    BoundParams(method, params, 5,5);
    // First parameter is the client username, which is ignored.

    /* EWBF 31 bytes job_id fix */
    bool fFoundJob = false; uint256 ret;
    if (params[1].isStr()) {
        //std::cerr << "\"" << params[1].get_str() << "\"" << std::endl;
        std::string job_id_str = params[1].get_str();
        const std::string hexDigits = "0123456789abcdef";
        //std::cerr << strprintf("\"%s\" (%d)", job_id_str, job_id_str.length()) << std::endl;
        if (job_id_str.length() == 63) {
            for (int i = 0; i < 15; i++) {
                std::vector<unsigned char> vch = ParseHex(params[1].get_str() + hexDigits[i]);
                std::copy(vch.begin(), vch.end(), ret.begin());
                fFoundJob = work_templates.count(ret);
                //std::cerr << i << ": " << HexStr(ret) << " - " << fFoundJob << std::endl;
                if (fFoundJob) break;
            }
        }
    }

    uint256 job_id;
    if (!fFoundJob)
        job_id = ParseUInt256(params[1], "job_id");
    else
        job_id = ret;

    // uint256 job_id = ParseUInt256(params[1], "job_id");
    if (!work_templates.count(job_id)) {
        LogPrint("stratum", "Received completed share for unknown job_id : %s\n", HexStr(job_id.begin(), job_id.end()));
        return false;
    }

    StratumWork &current_work = work_templates[job_id];

    uint32_t nTime = bswap_32(ParseHexInt4(params[2], "nTime"));

    std::vector<unsigned char> extranonce2 = ParseHexV(params[3], "extranonce2");
    if (extranonce2.size() != 32 - 4) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("extranonce2 is wrong length (received %d bytes; expected %d bytes", extranonce2.size(), 32 - 4));
    }

    std::vector<unsigned char> sol = ParseHexV(params[4], "solution");
    if (sol.size() != 1347) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("extranonce2 is wrong length (received %d bytes; expected %d bytes", sol.size(), 1347));
    }

    std::vector<unsigned char> extranonce1 = client.ExtraNonce1(job_id);
    // client.ExtraNonce1( return 8 bytes, but we need only 4
    extranonce1.resize(4);

    boost::optional<uint32_t> nVersion = 4; // block version always 4

    // TODO: check varint len bytes, should be always 0xfd, 0x40, 0x05
    // TODO: check equihash solution

    // uint32_t nTime = ParseHexInt4(params[3], "nTime");
    // uint32_t nNonce = ParseHexInt4(params[4], "nNonce");
    // boost::optional<uint32_t> nVersion; // (?)
    // if (params.size() > 5) {
    //     nVersion = ParseHexInt4(params[5], "nVersion");
    // }
    // std::vector<unsigned char> extranonce1;
    // if (params.size() > 6) {
    //     extranonce1 = ParseHexV(params[6], "extranonce1");
    //     if (extranonce1.size() != 8) {
    //         throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Expected 8 bytes for extranonce1 field; received %d", extranonce1.size()));
    //     }
    // } else {
    //     extranonce1 = client.ExtraNonce1(job_id);
    // }

    SubmitBlock(client, job_id, current_work, extranonce1, extranonce2, nVersion, nTime, sol);

    return true;
}

UniValue stratum_mining_aux_submit(StratumClient& client, const UniValue& params)
{
    // const std::string method("mining.aux.submit");
    // BoundParams(method, params, 14, 14);

    // std::string username = params[0].get_str();
    // boost::trim(username);

    // size_t pos = username.find('+');
    // if (pos != std::string::npos) {
    //     // Ignore suffix.
    //     username.resize(pos);
    //     boost::trim_right(username);
    // }

    // CBitcoinAddress addr(username);
    // if (!addr.IsValid()) {
    //     throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Invalid Komodo address: %s", username));
    // }
    // if (!client.m_aux_addr.count(addr)) {
    //     LogPrint("stratum", "No user with address %s is currently registered\n", addr.ToString());
    // }

    // uint256 job_id = ParseUInt256(params[1].get_str(), "job_id");
    // if (!work_templates.count(job_id)) {
    //     LogPrint("stratum", "Received completed auxiliary share for unknown job_id : %s\n", HexStr(job_id.begin(), job_id.end()));
    //     return false;
    // }
    // StratumWork &current_work = work_templates[job_id];

    // CBlockHeader blkhdr(current_work.GetBlock());
    // AuxProofOfWork& aux_pow = blkhdr.m_aux_pow;

    // const UniValue& commit_branch = params[2].get_array();
    // aux_pow.m_commit_branch.clear();
    // for (int i = 0; i < commit_branch.size(); ++i) {
    //     const UniValue& inner_hash_node = commit_branch[i].get_array();
    //     if (inner_hash_node.size() != 2) {
    //         throw JSONRPCError(RPC_INVALID_PARAMETER, "commit_branch has unexpected size; must be of the form [[int, uint256]...]");
    //     }
    //     int bits = inner_hash_node[0].get_int();
    //     if (bits < 0 || bits > 255) {
    //         throw JSONRPCError(RPC_INVALID_PARAMETER, "bits parameter within commit_branch does not fit in unsigned char");
    //     }
    //     uint256 hash = ParseUInt256(inner_hash_node[1], "commit_branch");
    //     aux_pow.m_commit_branch.emplace_back((unsigned char)bits, hash);
    // }
    // if (aux_pow.m_commit_branch.size() > MAX_AUX_POW_COMMIT_BRANCH_LENGTH) {
    //     throw JSONRPCError(RPC_INVALID_PARAMETER, "auxiliary proof-of-work Merkle map path is too long");
    // }
    // size_t nbits = 0;
    // for (size_t idx = 0; idx < aux_pow.m_commit_branch.size(); ++idx) {
    //     ++nbits;
    //     nbits += aux_pow.m_commit_branch[idx].first;
    // }
    // if (nbits >= 256) {
    //     throw JSONRPCError(RPC_INVALID_PARAMETER, "auxiliary proof-of-work Merkle map path is greater than 256 bits");
    // }

    // aux_pow.m_midstate_hash = ParseUInt256(params[3], "midstate_hash");
    // if (!params[4].get_str().empty()) {
    //     aux_pow.m_midstate_buffer = ParseHexV(params[4], "midstate_buffer");
    // }
    // if (aux_pow.m_midstate_buffer.size() >= 64) {
    //     throw JSONRPCError(RPC_INVALID_PARAMETER, "auxiliary proof-of-work midstate buffer is too large");
    // }
    // int64_t midstate_length = 0;
    // try {
    //     midstate_length = params[5].get_int64();
    // } catch (...) {
    //     throw JSONRPCError(RPC_INVALID_PARAMETER, "midstate_length is not an integer as expected");
    // }
    // if (midstate_length < 0) {
    //     throw JSONRPCError(RPC_INVALID_PARAMETER, "midstate length cannot be negative");
    // }
    // if (midstate_length >= std::numeric_limits<uint32_t>::max()) {
    //     throw JSONRPCError(RPC_INVALID_PARAMETER, "non-representable midstate length for auxiliary proof-of-work");
    // }
    // aux_pow.m_midstate_length = (uint32_t)midstate_length;
    // if (aux_pow.m_midstate_buffer.size() != aux_pow.m_midstate_length % 64) {
    //     throw JSONRPCError(RPC_INVALID_PARAMETER, "auxiliary proof-of-work midstate buffer doesn't match anticipated length");
    // }

    // aux_pow.m_aux_lock_time = ParseHexInt4(params[6], "lock_time");

    // const UniValue& aux_branch = params[7].get_array();
    // aux_pow.m_aux_branch.clear();
    // for (int i = 0; i < aux_branch.size(); ++i) {
    //     aux_pow.m_aux_branch.push_back(ParseUInt256(aux_branch[i], "aux_branch"));
    // }
    // if (aux_pow.m_aux_branch.size() > MAX_AUX_POW_BRANCH_LENGTH) {
    //     throw JSONRPCError(RPC_INVALID_PARAMETER, "auxiliary proof-of-work Merkle branch is too long");
    // }
    // int64_t num_txns = params[8].get_int64();
    // if (num_txns < 1) {
    //     throw JSONRPCError(RPC_INVALID_PARAMETER, "number of transactions in auxiliary block cannot be less than one");
    // }
    // if (num_txns > std::numeric_limits<uint32_t>::max()) {
    //     throw JSONRPCError(RPC_INVALID_PARAMETER, "non-representable number of transactions in auxiliary block");
    // }
    // aux_pow.m_aux_num_txns = (uint32_t)num_txns;

    // aux_pow.m_aux_hash_prev_block = ParseUInt256(params[10], "hashPrevBlock");
    // blkhdr.nTime = ParseHexInt4(params[11], "nTime");
    // aux_pow.m_aux_bits = ParseHexInt4(params[12], "nBits");
    // aux_pow.m_aux_nonce = ParseHexInt4(params[13], "nNonce");
    // aux_pow.m_aux_version = ParseHexInt4(params[9], "nVersion");

    // SubmitAuxiliaryBlock(client, addr, job_id, current_work, blkhdr);

    return true;
}

UniValue stratum_mining_aux_subscribe(StratumClient& client, const UniValue& params)
{
    // const std::string method("mining.aux.subscribe");
    // BoundParams(method, params, 0, 0);

    // client.m_supports_aux = true;

    // UniValue ret(UniValue::VARR);
    // const uint256& aux_pow_path = Params().GetConsensus().aux_pow_path;
    // ret.push_back(HexStr(aux_pow_path.begin(), aux_pow_path.end()));
    // ret.push_back(UniValue((int)MAX_AUX_POW_COMMIT_BRANCH_LENGTH));
    // ret.push_back(UniValue((int)MAX_AUX_POW_BRANCH_LENGTH));

    const std::string method("mining.aux.subscribe");
    BoundParams(method, params, 0, 0);
    client.m_supports_aux = false;
    UniValue ret(UniValue::VARR);
    return ret;
}

UniValue stratum_mining_extranonce_subscribe(StratumClient& client, const UniValue& params)
{
    const std::string method("mining.extranonce.subscribe");
    BoundParams(method, params, 0, 0);

    client.m_supports_extranonce = true;

    return true;
}

/** Callback to write from a stratum connection. */
static void stratum_write_cb(bufferevent *bev, void *ctx)
{
    /* template */
}

/** Callback to read from a stratum connection. */
static void stratum_read_cb(bufferevent *bev, void *ctx)
{
    evconnlistener *listener = (evconnlistener*)ctx;
    LOCK(cs_stratum);
    // Lookup the client record for this connection
    if (!subscriptions.count(bev)) {
        LogPrint("stratum", "Received read notification for unknown stratum connection 0x%x\n", (size_t)bev);
        return;
    }
    StratumClient& client = subscriptions[bev];
    // Get links to the input and output buffers
    evbuffer *input = bufferevent_get_input(bev);
    assert(input);
    evbuffer *output = bufferevent_get_output(bev);
    assert(output);

    // Process each line of input that we have received
    char *cstr = 0;
    size_t len = 0;
    while ((cstr = evbuffer_readln(input, &len, EVBUFFER_EOL_CRLF))) {
        std::string line(cstr, len);
        free(cstr);
        LogPrint("stratum", "Received stratum request from %s : %s\n", client.GetPeer().ToString(), line);

        //JSONRPCRequest jreq;
        JSONRequest jreq;

        std::string reply;
        try {
            // Parse request
            UniValue valRequest;
            if (!valRequest.read(line)) {
                // Not JSON; is this even a stratum miner?
                throw JSONRPCError(RPC_PARSE_ERROR, "Parse error");
            }
            if (!valRequest.isObject()) {
                // Not a JSON object; don't know what to do.
                throw JSONRPCError(RPC_PARSE_ERROR, "Top-level object parse error");
            }
            if (valRequest.exists("result")) {
                // JSON-RPC reply.  Ignore.
                LogPrint("stratum", "Ignoring JSON-RPC response\n");
                continue;
            }
            jreq.parse(valRequest);

            // Dispatch to method handler
            UniValue result = NullUniValue;
            if (stratum_method_dispatch.count(jreq.strMethod)) {
                result = stratum_method_dispatch[jreq.strMethod](client, jreq.params);
            } else {
                throw JSONRPCError(RPC_METHOD_NOT_FOUND, strprintf("Method '%s' not found", jreq.strMethod));
            }

            // Compose reply
            reply = JSONRPCReply(result, NullUniValue, jreq.id);
        } catch (const UniValue& objError) {
            reply = JSONRPCReply(NullUniValue, objError, jreq.id);
        } catch (const std::exception& e) {
            reply = JSONRPCReply(NullUniValue, JSONRPCError(RPC_INTERNAL_ERROR, e.what()), jreq.id);
        }

        LogPrint("stratum", "Sending stratum response to %s : %s", client.GetPeer().ToString(), reply);
        assert(output);
        if (evbuffer_add(output, reply.data(), reply.size())) {
            LogPrint("stratum", "Sending stratum response failed. (Reason: %d, '%s')\n", errno, evutil_socket_error_to_string(errno));
        }
    }

    // If required, send new work to the client.
    if (client.m_send_work) {
        std::string data;
        try {
            data = GetWorkUnit(client);
        } catch (const UniValue& objError) {
            data = JSONRPCReply(NullUniValue, objError, NullUniValue);
        } catch (const std::exception& e) {
            data = JSONRPCReply(NullUniValue, JSONRPCError(RPC_INTERNAL_ERROR, e.what()), NullUniValue);
        }

        LogPrint("stratum", "Sending requested stratum work unit to %s : %s", client.GetPeer().ToString(), data);
        assert(output);
        if (evbuffer_add(output, data.data(), data.size())) {
            LogPrint("stratum", "Sending stratum work unit failed. (Reason: %d, '%s')\n", errno, evutil_socket_error_to_string(errno));
        }

        client.m_send_work = false;
    }
}

/** Callback to handle unrecoverable errors in a stratum link. */
static void stratum_event_cb(bufferevent *bev, short what, void *ctx)
{
    evconnlistener *listener = (evconnlistener*)ctx;
    LOCK(cs_stratum);
    // Fetch the return address for this connection, for the debug log.
    std::string from("UNKNOWN");
    if (!subscriptions.count(bev)) {
        LogPrint("stratum", "Received event notification for unknown stratum connection 0x%x\n", (size_t)bev);
        return;
    } else {
        from = subscriptions[bev].GetPeer().ToString();
    }
    // Report the reason why we are closing the connection.
    if (what & BEV_EVENT_ERROR) {
        LogPrint("stratum", "Error detected on stratum connection from %s\n", from);
    }
    if (what & BEV_EVENT_EOF) {
        LogPrint("stratum", "Remote disconnect received on stratum connection from %s\n", from);
    }
    // Remove the connection from our records, and tell libevent to
    // disconnect and free its resources.
    if (what & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
        LogPrint("stratum", "Closing stratum connection from %s\n", from);
        subscriptions.erase(bev);
        if (bev) {
            bufferevent_free(bev);
            bev = NULL;
        }
    }
}

/** Callback to accept a stratum connection. */
static void stratum_accept_conn_cb(evconnlistener *listener, evutil_socket_t fd, sockaddr *address, int socklen, void *ctx)
{
    LOCK(cs_stratum);
    // Parse the return address
    CService from;
    from.SetSockAddr(address);
    // Early address-based allow check

    // TODO: Enable restriction !
    // if (!ClientAllowed(stratum_allow_subnets, from))
    // {
    //     evconnlistener_free(listener);
    //     LogPrint("stratum", "Rejected connection from disallowed subnet: %s\n", from.ToString());
    //     return;
    // }

    // Should be the same as EventBase(), but let's get it the official way.
    event_base *base = evconnlistener_get_base(listener);
    // Create a buffer for sending/receiving from this connection.
    bufferevent *bev = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);
    // Disable Nagle's algorithm, so that TCP packets are sent
    // immediately, even if it results in a small packet.
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char*)&one, sizeof(one));
    // Setup the read and event callbacks to handle receiving requests
    // from the miner and error handling.  A write callback isn't
    // needed because we're not sending enough data to fill buffers.
    bufferevent_setcb(bev, stratum_read_cb, NULL, stratum_event_cb, (void*)listener);
    // Enable bidirectional communication on the connection.
    bufferevent_enable(bev, EV_READ|EV_WRITE);
    // Record the connection state
    subscriptions[bev] = StratumClient(listener, fd, bev, from);
    // Log the connection.
    LogPrint("stratum", "Accepted stratum connection from %s\n", from.ToString());
}

/** Setup the stratum connection listening services */
static bool StratumBindAddresses(event_base* base)
{
    int stratumPort = ASSETCHAINS_SYMBOL[0] == 0 ? BaseParams().StratumPort() : ASSETCHAINS_RPCPORT + 1000;
    int defaultPort = GetArg("-stratumport", stratumPort);
    std::vector<std::pair<std::string, uint16_t> > endpoints;

    // Determine what addresses to bind to
    if (!InitEndpointList("stratum", defaultPort, endpoints))
        return false;

    // Bind each addresses
    for (const auto& endpoint : endpoints) {
        LogPrint("stratum", "Binding stratum on address %s port %i\n", endpoint.first, endpoint.second);
        // Use CService to translate string -> sockaddr
        CNetAddr netaddr;
        LookupHost(endpoint.first.c_str(), netaddr, true);
        CService socket(netaddr, endpoint.second);
        union {
            sockaddr     ipv4;
            sockaddr_in6 ipv6;
        } addr;
        socklen_t len = sizeof(addr);
        socket.GetSockAddr((sockaddr*)&addr, &len);
        // Setup an event listener for the endpoint
        evconnlistener *listener = evconnlistener_new_bind(base, stratum_accept_conn_cb, NULL, LEV_OPT_CLOSE_ON_FREE|LEV_OPT_REUSEABLE, -1, (sockaddr*)&addr, len);
        // Only record successful binds
        if (listener) {
            bound_listeners[listener] = socket;
        } else {
            LogPrintf("Binding stratum on address %s port %i failed. (Reason: %d, '%s')\n", endpoint.first, endpoint.second, errno, evutil_socket_error_to_string(errno));
        }
    }

    return !bound_listeners.empty();
}

/** Watches for new blocks and send updated work to miners. */
static bool g_shutdown = false;

void BlockWatcher()
{
    RenameThread("blkwatcher");
    boost::unique_lock<boost::mutex> lock(csBestBlock);
    boost::system_time checktxtime = boost::get_system_time();
    unsigned int txns_updated_last = 0;
    while (true) {
        checktxtime += boost::posix_time::seconds(15);
        if (!cvBlockChange.timed_wait(lock, checktxtime)) {
            // Timeout: Check to see if mempool was updated.

            // if (fstdErrDebugOutput) {
            //     std::cerr << __func__ << ": " << __FILE__ << "," << __LINE__ << DateTimeStrPrecise() << std::endl;
            // }

            unsigned int txns_updated_next = mempool.GetTransactionsUpdated();
            if (txns_updated_last == txns_updated_next)
                continue;
            txns_updated_last = txns_updated_next;
        }

        LOCK(cs_stratum);

        if (g_shutdown) {
            break;
        }

        // Either new block, or updated transactions.  Either way,
        // send updated work to miners.
        for (auto& subscription : subscriptions) {
            bufferevent* bev = subscription.first;

            if (!bev)
                continue;
            evbuffer *output = bufferevent_get_output(bev);
            if (!output)
                continue;

            StratumClient& client = subscription.second;
            // Ignore clients that aren't authorized yet.
            if (!client.m_authorized && client.m_aux_addr.empty()) {
                continue;
            }
            // Ignore clients that are already working on the new block.
            // Typically this is just the miner that found the block, who was
            // immediately sent a work update.  This check avoids sending that
            // work notification again, moments later.  Due to race conditions
            // there could be more than one miner that have already received an
            // update, however.
            if (client.m_last_tip == chainActive.Tip()) {
                continue;
            }

            std::cerr << __func__ << ": " << __FILE__ << "," << __LINE__ << DateTimeStrPrecise() << std::endl;

            // Get new work
            std::string data;
            try {
                data = GetWorkUnit(client);
            } catch (const UniValue& objError) {
                data = JSONRPCReply(NullUniValue, objError, NullUniValue);
            } catch (const std::exception& e) {
                // Some sort of error.  Ignore.
                std::string msg = strprintf("Error generating updated work for stratum client: %s", e.what());
                LogPrint("stratum", "%s\n", msg);
                data = JSONRPCReply(NullUniValue, JSONRPCError(RPC_INTERNAL_ERROR, msg), NullUniValue);
            }
            // Send the new work to the client

            assert(output);
            if (evbuffer_add(output, data.data(), data.size())) {
                LogPrint("stratum", "Sending stratum work unit failed. (Reason: %d, '%s')\n", errno, evutil_socket_error_to_string(errno));
            }
        }
    }
}

void SendKeepAlivePackets()
{
    RenameThread("sockklv");
    while (true) {
        // Run the notifier on an integer second in the steady clock.
        auto now = std::chrono::steady_clock::now().time_since_epoch();
        auto nextFire = std::chrono::duration_cast<std::chrono::seconds>(
            now + std::chrono::seconds(10));
        std::this_thread::sleep_until(
        std::chrono::time_point<std::chrono::steady_clock>(nextFire));

        boost::this_thread::interruption_point();

        // Either new block, or updated transactions.  Either way,
        // send updated work to miners.
        for (auto& subscription : subscriptions) {
            bufferevent* bev = subscription.first;

            if (!bev)
                continue;
            evbuffer *output = bufferevent_get_output(bev);
            if (!output)
                continue;

            StratumClient& client = subscription.second;

            if (fstdErrDebugOutput) {
                std::cerr << __func__ << ": " << __FILE__ << "," << __LINE__ << std::endl <<
                "client.m_authorized = " << client.m_authorized << std::endl <<
                "client.m_aux_addr.size() = " << client.m_aux_addr.size() << std::endl <<
                "client.m_last_tip = " << strprintf("%p", client.m_last_tip) << std::endl <<
                (client.m_last_tip ? strprintf("client.m_last_tip->GetHeight() = %d", client.m_last_tip->GetHeight()) : "") << std::endl <<
                "chainActive.Tip()->GetHeight() = " << chainActive.Tip()->GetHeight() << std::endl <<
                "client.m_supports_extranonce = " << client.m_supports_extranonce << std::endl <<
                "client.m_send_work = " << client.m_send_work << std::endl <<
                std::endl;

                // "client.m_last_tip.GetHeight() = " << client.m_last_tip->GetHeight() <<
            }

            // Ignore clients that aren't authorized yet.
            if (!client.m_authorized && client.m_aux_addr.empty()) {
                continue;
            }

            std::string data = "\r\n"; // JSONRPCReply(NullUniValue, NullUniValue, NullUniValue);
            // to see the socket / connection is alive, we will see bunch of
            // JSON decode failed(1): '[' or '{' expected near end of file
            // on client if will send "\r\n" every second

            assert(output);
            if (evbuffer_add(output, data.data(), data.size())) {
                LogPrint("stratum", "Sending stratum keepalive unit failed. (Reason: %d, '%s')\n", errno, evutil_socket_error_to_string(errno));
            }

            if ( (client.m_last_tip && client.m_last_tip->GetHeight() == chainActive.Tip()->GetHeight()) || (!client.m_last_tip) )
            {
                // trying force send work for "stucked" client
                client.m_send_work = true;
            }
        }

    }

}

/** Configure the stratum server */
bool InitStratumServer()
{
    LOCK(cs_stratum);

    if (!InitSubnetAllowList("stratum", stratum_allow_subnets)) {
        LogPrint("stratum", "Unable to bind stratum server to an endpoint.\n");
        return false;
    }

    std::string strAllowed;
    for (const auto& subnet : stratum_allow_subnets) {
        strAllowed += subnet.ToString() + " ";
    }
    LogPrint("stratum", "Allowing stratum connections from: %s\n", strAllowed);

    event_base* base = EventBase();
    if (!base) {
        LogPrint("stratum", "No event_base object, cannot setup stratum server.\n");
        return false;
    }

    if (!StratumBindAddresses(base)) {
        LogPrintf("Unable to bind any endpoint for stratum server\n");
    } else {
        LogPrint("stratum", "Initialized stratum server\n");
    }

    stratum_method_dispatch["mining.subscribe"] = stratum_mining_subscribe;
    stratum_method_dispatch["mining.authorize"] = stratum_mining_authorize;
    stratum_method_dispatch["mining.configure"] = stratum_mining_configure;
    stratum_method_dispatch["mining.submit"]    = stratum_mining_submit;
    stratum_method_dispatch["mining.aux.submit"] = stratum_mining_aux_submit;
    stratum_method_dispatch["mining.aux.authorize"] =
        stratum_mining_aux_authorize;
    stratum_method_dispatch["mining.aux.deauthorize"] =
        stratum_mining_aux_deauthorize;
    stratum_method_dispatch["mining.aux.subscribe"] =
        stratum_mining_aux_subscribe;
    stratum_method_dispatch["mining.extranonce.subscribe"] =
        stratum_mining_extranonce_subscribe;

    // Start thread to wait for block notifications and send updated
    // work to miners.
    block_watcher_thread = boost::thread(BlockWatcher);
    block_watcher_thread = boost::thread(SendKeepAlivePackets);

    return true;
}

/** Interrupt the stratum server connections */
void InterruptStratumServer()
{
    LOCK(cs_stratum);
    // Stop listening for connections on stratum sockets
    for (const auto& binding : bound_listeners) {
        LogPrint("stratum", "Interrupting stratum service on %s\n", binding.second.ToString());
        evconnlistener_disable(binding.first);
    }
    // Tell the block watching thread to stop
    g_shutdown = true;
}

/** Cleanup stratum server network connections and free resources. */
void StopStratumServer()
{
    LOCK(cs_stratum);
    /* Tear-down active connections. */
    for (const auto& subscription : subscriptions) {
        LogPrint("stratum", "Closing stratum server connection to %s due to process termination\n", subscription.second.GetPeer().ToString());
        bufferevent_free(subscription.first);
    }
    subscriptions.clear();
    /* Un-bind our listeners from their network interfaces. */
    for (const auto& binding : bound_listeners) {
        LogPrint("stratum", "Removing stratum server binding on %s\n", binding.second.ToString());
        evconnlistener_free(binding.first);
    }
    bound_listeners.clear();
    /* Free any allocated block templates. */
    work_templates.clear();
}

// End of File
