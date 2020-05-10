// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2013 The Bitcoin Core developers
// Copyright (c) 2019-2020 Decker

// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/******************************************************************************
 * Copyright © 2014-2020 The SuperNET Developers.                             *
 *                                                                            *
 * See the AUTHORS, DEVELOPER-AGREEMENT and LICENSE files at                  *
 * the top-level directory of this distribution for the individual copyright  *
 * holder information and the developer policies on copyright and licensing.  *
 *                                                                            *
 * Unless otherwise agreed in a custom licensing agreement, no part of the    *
 * SuperNET software, including this file may be copied, modified, propagated *
 * or distributed except according to the terms contained in the LICENSE file *
 *                                                                            *
 * Removal or modification of this copyright notice is prohibited.            *
 *                                                                            *
 ******************************************************************************/

// Use CONFIGURE_FLAGS=--enable-nntools zcutil/build.sh -j$(nproc) to build with these tools.

#include "util.h"
#include "utilstrencodings.h"
#include <boost/filesystem/operations.hpp>
#include <stdio.h>

#include <univalue.h>
#include "rpc/client.h"
#include "rpc/protocol.h"
#include <event2/buffer.h>
#include <event2/keyvalq_struct.h>
#include "support/events.h"

#include "amount.h"
#include "utilmoneystr.h"

using namespace std;

// recipients list to send, if more than one, all generated balance will be divided on equal parts for each recipient
std::vector<std::string> vRecipients = { "RUvf1avoLDMGKpMpKqwptf5ejy9rwaxrbe", "RPmV7hv9DFmw3fRqzSa2Q5J1ufJzLPdTze" };

uint16_t BITCOIND_RPCPORT = 7771;
char ASSETCHAINS_SYMBOL[65]; // this also needed in internal calls, like GetDefaultDataDir(), so we can't use std::string here
static const int DEFAULT_HTTP_CLIENT_TIMEOUT=900;
static const int CONTINUE_EXECUTION=-1;
static const std::string strErrorMsg = "ERROR: ";
int64_t MAX_MONEY = 200000000 * 100000000LL;

//
// Exception thrown on connection error.  This error is used to determine
// when to wait if -rpcwait is given.
//
class CConnectionFailed : public std::runtime_error
{
public:

    explicit inline CConnectionFailed(const std::string& msg) :
        std::runtime_error(msg)
    {}

};

/** Reply structure for request_done to fill in */
struct HTTPReply
{
    HTTPReply(): status(0), error(-1) {}

    int status;
    int error;
    std::string body;
};

const char *http_errorstring(int code)
{
    switch(code) {
    #if LIBEVENT_VERSION_NUMBER >= 0x02010300
        case EVREQ_HTTP_TIMEOUT:
            return "timeout reached";
        case EVREQ_HTTP_EOF:
            return "EOF reached";
        case EVREQ_HTTP_INVALID_HEADER:
            return "error while reading header, or invalid header";
        case EVREQ_HTTP_BUFFER_ERROR:
            return "error encountered while reading or writing";
        case EVREQ_HTTP_REQUEST_CANCEL:
            return "request was canceled";
        case EVREQ_HTTP_DATA_TOO_LONG:
            return "response body is larger than allowed";
    #endif
    default:
        return "unknown";
    }
}

static void http_request_done(struct evhttp_request *req, void *ctx)
{
    HTTPReply *reply = static_cast<HTTPReply*>(ctx);

    if (req == NULL) {
        /* If req is NULL, it means an error occurred while connecting: the
         * error code will have been passed to http_error_cb.
         */
        reply->status = 0;
        return;
    }

    reply->status = evhttp_request_get_response_code(req);

    struct evbuffer *buf = evhttp_request_get_input_buffer(req);
    if (buf)
    {
        size_t size = evbuffer_get_length(buf);
        const char *data = (const char*)evbuffer_pullup(buf, size);
        if (data)
            reply->body = std::string(data, size);
        evbuffer_drain(buf, size);
    }
}

#if LIBEVENT_VERSION_NUMBER >= 0x02010300
static void http_error_cb(enum evhttp_request_error err, void *ctx)
{
    HTTPReply *reply = static_cast<HTTPReply*>(ctx);
    reply->error = err;
}
#endif

UniValue CallRPC(const std::string& strMethod, const UniValue& params)
{
    std::string host = GetArg("-rpcconnect", "127.0.0.1");

    int port = GetArg("-rpcport", 7771 /*BaseParams().RPCPort()*/);
    BITCOIND_RPCPORT = port;

    // Obtain event base
    raii_event_base base = obtain_event_base();

    // Synchronously look up hostname
    raii_evhttp_connection evcon = obtain_evhttp_connection_base(base.get(), host, port);
    evhttp_connection_set_timeout(evcon.get(), GetArg("-rpcclienttimeout", DEFAULT_HTTP_CLIENT_TIMEOUT));

    HTTPReply response;
    raii_evhttp_request req = obtain_evhttp_request(http_request_done, (void*)&response);
    if (req == NULL)
        throw std::runtime_error("create http request failed");
    #if LIBEVENT_VERSION_NUMBER >= 0x02010300
        evhttp_request_set_error_cb(req.get(), http_error_cb);
    #endif

    // Get credentials
    std::string strRPCUserColonPass;
    if (mapArgs["-rpcpassword"] == "") {
        // Try fall back to cookie-based authentication if no password is provided
        if (!GetAuthCookie(&strRPCUserColonPass)) {
            throw std::runtime_error(strprintf(
                _("Could not locate RPC credentials. No authentication cookie could be found,\n"
                  "and no rpcpassword is set in the configuration file (%s)."),
                    GetConfigFile().string().c_str()));

        }
    } else {
        strRPCUserColonPass = mapArgs["-rpcuser"] + ":" + mapArgs["-rpcpassword"];
    }

    struct evkeyvalq* output_headers = evhttp_request_get_output_headers(req.get());
    assert(output_headers);
    evhttp_add_header(output_headers, "Host", host.c_str());
    evhttp_add_header(output_headers, "Connection", "close");
    evhttp_add_header(output_headers, "Authorization", (std::string("Basic ") + EncodeBase64(strRPCUserColonPass)).c_str());

    // Attach request data
    std::string strRequest = JSONRPCRequest(strMethod, params, 1);
    struct evbuffer* output_buffer = evhttp_request_get_output_buffer(req.get());
    assert(output_buffer);
    evbuffer_add(output_buffer, strRequest.data(), strRequest.size());

    int r = evhttp_make_request(evcon.get(), req.get(), EVHTTP_REQ_POST, "/");
    req.release(); // ownership moved to evcon in above call
    if (r != 0) {
        throw CConnectionFailed("send http request failed");
    }

    event_base_dispatch(base.get());

    if (response.status == 0)
        throw CConnectionFailed(strprintf("couldn't connect to server: %s (code %d)\n(make sure server is running and you are connecting to the correct RPC port)", http_errorstring(response.error), response.error));
    else if (response.status == HTTP_UNAUTHORIZED)
        throw std::runtime_error("incorrect rpcuser or rpcpassword (authorization failed)");
    else if (response.status >= 400 && response.status != HTTP_BAD_REQUEST && response.status != HTTP_NOT_FOUND && response.status != HTTP_INTERNAL_SERVER_ERROR)
        throw std::runtime_error(strprintf("server returned HTTP error %d", response.status));
    else if (response.body.empty())
        throw std::runtime_error("no response from server");

    // Parse reply
    UniValue valReply(UniValue::VSTR);
    if (!valReply.read(response.body))
        throw std::runtime_error("couldn't parse reply from server");
    const UniValue& reply = valReply.get_obj();
    if (reply.empty())
        throw std::runtime_error("expected reply to have result, error and id properties");

    return reply;
}

CAmount AmountFromValue(const UniValue& value)
{
    if (!value.isNum() && !value.isStr())
        throw JSONRPCError(RPC_TYPE_ERROR, "Amount is not a number or string");
    CAmount amount;
    if (!ParseFixedPoint(value.getValStr(), 8, &amount))
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount");
    if (!MoneyRange(amount))
        throw JSONRPCError(RPC_TYPE_ERROR, "Amount out of range");
    return amount;
}

static int AppInitRPC(int argc, char* argv[])
{
    static_assert(CONTINUE_EXECUTION != EXIT_FAILURE,
                  "CONTINUE_EXECUTION should be different from EXIT_FAILURE");
    static_assert(CONTINUE_EXECUTION != EXIT_SUCCESS,
                  "CONTINUE_EXECUTION should be different from EXIT_SUCCESS");

    //
    // Parameters
    //
    ParseParameters(argc, argv);
    Astd:string name;
    name = GetArg("-ac_name","");
    if ( !name.empty() )
        strncpy(ASSETCHAINS_SYMBOL,name.c_str(),sizeof(ASSETCHAINS_SYMBOL)-1);

    if (!boost::filesystem::is_directory(GetDataDir(false))) {
        fprintf(stderr, "Error: Specified data directory \"%s\" does not exist.\n", mapArgs["-datadir"].c_str());
        return EXIT_FAILURE;
    }
    try {
        ReadConfigFile(mapArgs, mapMultiArgs);
    } catch (const std::exception& e) {
        fprintf(stderr,"Error reading configuration file: %s\n", e.what());
        return EXIT_FAILURE;
    }

    return CONTINUE_EXECUTION;
}

int main(int argc, char* argv[])
{
    SetupEnvironment();
    if (!SetupNetworking()) {
        std::cerr << "Error: Initializing networking failed" << std::endl;
        return EXIT_FAILURE;
    }

    try {
        int ret = AppInitRPC(argc, argv);
        if (ret != CONTINUE_EXECUTION)
            return ret;
    }
    catch (const std::exception& e) {
        PrintExceptionContinue(&e, "AppInitRPC()");
        return EXIT_FAILURE;
    } catch (...) {
        PrintExceptionContinue(NULL, "AppInitRPC()");
        return EXIT_FAILURE;
    }

    std::cout << "Coin: " << (ASSETCHAINS_SYMBOL[0] ? ASSETCHAINS_SYMBOL : "KMD") << " (" << GetDataDir(false) << ")" << std::endl;

    /*
    // debug for testing params
    for (const auto& kv : mapArgs) {
        std::cout << kv.first << " has value " << kv.second << std::endl;
    }

    for (const auto& kv : mapMultiArgs) {
        std::cout << kv.first << " has values: " << std::endl;
        for (const auto& v : kv.second)
            std::cout << "   --- " << v << std::endl;
    }
    */

    /*
    const vector<string>& addresses = mapMultiArgs["-addr"];
    if (mapArgs.count("-addr") && addresses.size() > 0) {
        std::string strRecepients;
        strRecepients += strprintf("Recepients: %d (", addresses.size());
        for (const auto& addr : addresses) {
            strRecepients += " " + addr + " ";
        }
        strRecepients += ")";
        std::cout << strRecepients << std::endl;
    }
    else
    {
        std::cerr << strErrorMsg << "No recepients specified." << std::endl;
        return EXIT_FAILURE;
    }
    */

   if (vRecipients.size() < 1) {
        std::cerr << strErrorMsg << "No recepients specified." << std::endl;
        return EXIT_FAILURE;
   }

    // request total balance
    CAmount nTotalBalance = 0;
    {
        UniValue reply = CallRPC("getbalance", NullUniValue);
        const UniValue &error = find_value(reply, "error");
        if (!error.isNull())
        {
            fprintf(stderr, "balance request error: %d %s\n", error["code"].get_int(),
                error["message"].get_str().c_str());
            return EXIT_FAILURE;
        }

        const UniValue &result = find_value(reply, "result");
        nTotalBalance = AmountFromValue(result);
    }
    std::cout << "Total balance: " <<  FormatMoney(nTotalBalance) << " " << (ASSETCHAINS_SYMBOL[0] ? ASSETCHAINS_SYMBOL : "KMD") << std::endl;

    CAmount nBalanceToSend = 0;
    UniValue inputs(UniValue::VARR);
    UniValue outputs(UniValue::VOBJ);
    std::string unsigned_hex_raw_tx;
    std::string signed_hex_raw_tx;

    // request utxos
    {
        UniValue params(UniValue::VARR);
        params.push_back(UniValue(1));
        params.push_back(UniValue(9999999));
        UniValue reply = CallRPC("listunspent", params);
        const UniValue &error = find_value(reply, "error");
        if (!error.isNull())
        {
            fprintf(stderr, "listunspent request error: %d %s\n", error["code"].get_int(),
                error["message"].get_str().c_str());
            return EXIT_FAILURE;
        }

        const UniValue &result = find_value(reply, "result");
        if (result.isArray()) {
            UniValue utxos = result.get_array();
            for (size_t idx = 0; idx < utxos.size(); idx++) {
                const UniValue& utxo = utxos[idx];
                if (utxo.isObject()) {
                    const UniValue& o = utxo.get_obj();
                    string txid = find_value(o, "txid").get_str();
                    int nOutput = find_value(o, "vout").get_int();
                    CAmount amount = AmountFromValue(find_value(o, "amount"));
                    bool fSpendable = find_value(o, "spendable").get_bool();
                    bool fGenerated = find_value(o, "generated").get_bool();

                    if (fGenerated && fSpendable) {
                        // TODO: good idea is limit number of inputs here to optimal value,
                        // which can pass tx size limit and other conditions
                        nBalanceToSend += amount;
                        UniValue input(UniValue::VOBJ);
                        input.push_back(Pair("txid", txid));
                        input.push_back(Pair("vout", nOutput));
                        input.push_back(Pair("sequence", -1)); // important, to avoid 0xfffffffe, when locktime set and non-final
                        inputs.push_back(input);
                    }
                    // std::cout << idx << ". " << FormatMoney(amount) << " " << (ASSETCHAINS_SYMBOL[0] ? ASSETCHAINS_SYMBOL : "KMD") << std::endl;
                }
            }
        }

        std::cout << "Balance to send: " <<  FormatMoney(nBalanceToSend) << " " << (ASSETCHAINS_SYMBOL[0] ? ASSETCHAINS_SYMBOL : "KMD") << std::endl;

        if (nBalanceToSend > 0) {
            std::cout << "Inputs: " << inputs.size() << std::endl;
            int64_t rsize = vRecipients.size();

            // as we don't use Komodo internals here, like CMutableTransaction and others,
            // and operating only RPC calls, we should calc fee here somehow, even
            // first approximation with gap will be fine

            // estimated tx size (very rough approximation, even without scriptsig)
            // and without other checks, just to don't use zero fee

            int64_t estimated_tx_size = 4 + /* version */
                                        4 + /* versiongroupid */
                                        1 + /* number of vins */
                                        (32 + 4 + 1 + 4) * inputs.size() + /* each input without sig */
                                        1 + /* number of vouts */
                                        (8 + 1 + 25) * rsize + /* each output, considering P2PKH vouts */
                                        4 + /* locktime */
                                        4 + /* expiry height */
                                        11 /* tail */;

            // consider 5000 sat per Kb (1000 bytes) or 10 sat per byte
            CAmount nFeeNeeded = estimated_tx_size * 5000 / 1000;

            CAmount nAmount = (nBalanceToSend - nFeeNeeded) / rsize;
            if (nAmount < 55)
                nAmount = nBalanceToSend / rsize;

            for (const auto& recipient : vRecipients) {
                outputs.push_back(Pair(recipient, FormatMoney(nAmount))); // sat -> coins amount
            }

            std::cout << "Outputs: " << outputs.size() << std::endl;

            UniValue params(UniValue::VARR);
            params.push_back(inputs);
            params.push_back(outputs);
            params.push_back(GetTime()); // locktime

            UniValue reply = CallRPC("createrawtransaction", params);
            const UniValue &error = find_value(reply, "error");

            if (!error.isNull())
            {
                fprintf(stderr, "createrawtransaction request error: %d %s\n", error["code"].get_int(),
                    error["message"].get_str().c_str());
                return EXIT_FAILURE;
            }

            const UniValue &result = find_value(reply, "result");
            unsigned_hex_raw_tx = result.get_str();
            // std::cout << unsigned_hex_raw_tx << std::endl;

            int64_t unsigned_hex_raw_tx_size = unsigned_hex_raw_tx.length() / 2;
            // std::cout << "Estimated tx size: " << estimated_tx_size << std::endl;
            // std::cout << "Unsigned tx size: " << unsigned_hex_raw_tx_size << std::endl;

            // Signing
            if (unsigned_hex_raw_tx.length() > 0) {
                UniValue params(UniValue::VARR);
                params.push_back(unsigned_hex_raw_tx);
                reply = CallRPC("signrawtransaction", params);
                const UniValue &error = find_value(reply, "error");

                if (!error.isNull())
                {
                    fprintf(stderr, "signrawtransaction request error: %d %s\n", error["code"].get_int(),
                        error["message"].get_str().c_str());
                    return EXIT_FAILURE;
                }

                const UniValue &errors = find_value(reply, "errors");
                if (!errors.isNull()) {
                    // TODO: add parsing and detailed output, which input is bad
                    fprintf(stderr, "signrawtransaction request error, inputs issue");
                    return EXIT_FAILURE;
                }

                if (result["complete"].get_bool() == true) {
                    signed_hex_raw_tx = result["hex"].get_str();
                    // std::cout << signed_hex_raw_tx << std::endl;

                    // if we are here, we are able to broadcast tx
                    bool fBroadcast = true;

                    if (signed_hex_raw_tx.length() > 0 && fBroadcast) {

                        UniValue params(UniValue::VARR);
                        params.push_back(signed_hex_raw_tx);
                        reply = CallRPC("sendrawtransaction", params);
                        const UniValue &error = find_value(reply, "error");

                        if (!error.isNull())
                        {
                            fprintf(stderr, "sendrawtransaction request error: %d %s\n", error["code"].get_int(),
                                error["message"].get_str().c_str());
                            return EXIT_FAILURE;
                        }

                        const UniValue &result = find_value(reply, "result");
                        std::string txid = result.get_str();
                        std::cout << "txid: " << txid << " broadcasted!" << std::endl;
                    }

                } else {
                    fprintf(stderr, "signrawtransaction request error, incomplete issue");
                    return EXIT_FAILURE;
                }

            }
        }
    }

    // try {
    //     throw std::runtime_error("TEST");
    // }
    // catch (const std::exception& e) {
    //     PrintExceptionContinue(&e, "AppInitRPC()");
    //     return EXIT_FAILURE;
    // } catch (...) {
    //     PrintExceptionContinue(NULL, "AppInitRPC()");
    //     return EXIT_FAILURE;
    // }

    return 0;
}