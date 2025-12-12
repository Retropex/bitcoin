// Copyright (c) 2012-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <policy/coin_age_priority.h>

#include <coins.h>
#include <primitives/transaction.h>
#include <util/check.h>

unsigned int CalculateModifiedSize(const CTransaction& tx, unsigned int nTxSize)
{
    // In order to avoid disincentivizing cleaning up the UTXO set we don't count
    // the constant overhead for each txin and up to 110 bytes of scriptSig (which
    // is enough to cover a compressed pubkey p2sh redemption) for priority.
    // Providing any more cleanup incentive than making additional inputs free would
    // risk encouraging people to create junk outputs to redeem later.
    Assert(nTxSize > 0);
    for (std::vector<CTxIn>::const_iterator it(tx.vin.begin()); it != tx.vin.end(); ++it)
    {
        unsigned int offset = 41U + std::min(110U, (unsigned int)it->scriptSig.size());
        if (nTxSize > offset)
            nTxSize -= offset;
    }
    return nTxSize;
}

double ComputePriority2(double inputs_coin_age, unsigned int mod_vsize)
{
    if (mod_vsize == 0) return 0.0;

    return inputs_coin_age / mod_vsize;
}

double ReversePriority2(const double coin_age_priority, const unsigned int mod_vsize)
{
    return coin_age_priority * mod_vsize;
}

CoinAgeCache GetCoinAge(const CTransaction &tx, const CCoinsViewCache& view, int nHeight)
{
    CoinAgeCache r{COIN_AGE_CACHE_ZERO};
    if (tx.IsCoinBase()) {
        return r;
    }
    for (const CTxIn& txin : tx.vin)
    {
        const Coin& coin = view.AccessCoin(txin.prevout);
        if (coin.IsSpent()) {
            continue;
        }
        if (coin.nHeight <= nHeight) {
            r.inputs_coin_age += (double)(coin.out.nValue) * (nHeight - coin.nHeight);
            r.in_chain_input_value += coin.out.nValue;
        }
    }
    return r;
}
