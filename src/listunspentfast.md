## Listunspent Fast Explanation

`listunspentfast` is a highly experimental RPC call for Notary Nodes (for **iguana**), it has following components / parts / rules by default:

- All CPU expensive internal functions calls related to interest and dpow confirmations are removed. Mean, `interest` field in RPC result is absent, also `confirmations` field is equel to `rawconfirmations`. For iguana it should not be a big difference.
- `listunspentfast` used internally `AvailableCoinsFast` method to iterate wallet transactions. It have experimental tx cache inside. All txes with all vouts spent inserting in `setSkipTxids` set to skip it during next iterate (next listunspentfast call) for speed-up iteration loop. Also, `AvailableCoinsFast` used other optimizations, like skipping **5000 sat.** notary proof txes, skipping notarization txes (all vouts in notarization tx anyway belongs to `RXL3YXG2ceaB6C5hfJcN4fvmLH2C34knhA` and can't be part of unspent outputs anyway), range-based for loop (C++11) for iterate instead of standart loop, and others.
- Also, iguana don't need all utxos in listunspent return, so, we using filter. By default `listunspentfast` RPC call returns **not less** than `nP2PK_MaximumCount = 100` notaryvins (if exists), **not less** than 1 p2pkh utxo (if exist) for splitfunds and all coinbase and other type of utxos.

Here is some relatively statistics. For NN `wallet.dat` with size more than 0.5 Gb (500 Mb) standart `listunspent` call took about `0m2.110s` (2080 various utxos approximatelly) and for `listunspentfast`:

- with optimizations only (without caching in `setSkipTxids`) - `0m0.500s` (2080 utxo in result)
- with optimizations and with caching enabled - `0m0.190s` (2080 utxo in result)
- with oprimizations + caching enabled + P2PK/P2PKH filter enabled - `0m0.073s` (125 utxos in result)