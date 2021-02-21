// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2017-2020 The Raven Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "primitives/block.h"

#include "algo/hashx21s.h"
#include <hash.h>
#include "tinyformat.h"
#include "utilstrencodings.h"
#include "crypto/common.h"

uint32_t nKAWPOWActivationTime;

BlockNetwork bNetwork = BlockNetwork();

BlockNetwork::BlockNetwork()
{
    fOnTestnet = false;
    fOnRegtest = false;
}

void BlockNetwork::SetNetwork(const std::string& net)
{
    if (net == "test") {
        fOnTestnet = true;
    } else if (net == "regtest") {
        fOnRegtest = true;
    }
}
uint256 CBlockHeader::GetHash() const
{
    return HashX21S(BEGIN(nVersion), END(nNonce), hashPrevBlock);
}

uint256 CBlockHeader::GetHashFull(uint256& mix_hash) const
{
    return HashX21S(BEGIN(nVersion), END(nNonce), hashPrevBlock);
}

/**
 * @brief This takes a block header, removes the nNonce64 and the mixHash. Then performs a serialized hash of it SHA256D.
 * This will be used as the input to the KAAAWWWPOW hashing function
 * @note Only to be called and used on KAAAWWWPOW block headers
 */
uint256 CBlockHeader::GetKAWPOWHeaderHash() const
{
    CKAWPOWInput input{*this};

    return SerializeHash(input);
}

std::string CBlock::ToString() const
{
    std::stringstream s;
    s << strprintf("CBlock(hash=%s, ver=0x%08x, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u, nNonce64=%u, vtx=%u)\n",
        GetHash().ToString(),
        nVersion,
        hashPrevBlock.ToString(),
        hashMerkleRoot.ToString(),
        nTime, nBits, nNonce, nNonce64,
        vtx.size());
    for (const auto& tx : vtx) {
        s << "  " << tx->ToString() << "\n";
    }
    return s.str();
}
