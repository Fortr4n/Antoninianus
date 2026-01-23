// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2017-2021 The Antoninianus developers
// Copyright (c) 2024 The Antoninianus developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <map>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/obj_mac.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <openssl/encoder.h>
#include <openssl/decoder.h>

#include "key.h"
#include "hash.h"

// Order of secp256k1's generator minus 1.
static const unsigned char vchMaxModOrder[32] = {
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
    0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,
    0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x40
};

// Half of the order of secp256k1's generator minus 1.
static const unsigned char vchMaxModHalfOrder[32] = {
    0x7F,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0x5D,0x57,0x6E,0x73,0x57,0xA4,0x50,0x1D,
    0xDF,0xE9,0x2F,0x46,0x68,0x1B,0x20,0xA0
};

// secp256k1 curve order
static const unsigned char secp256k1_order[32] = {
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
    0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,
    0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x41
};

static const unsigned char vchZero[1] = {0};

/**
 * Create an EVP_PKEY for secp256k1 from raw 32-byte private key
 */
static EVP_PKEY* CreateEVPKeyFromSecret(const unsigned char secret[32]) {
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    OSSL_PARAM_BLD *param_bld = NULL;
    OSSL_PARAM *params = NULL;
    BIGNUM *priv_bn = NULL;
    EC_GROUP *group = NULL;
    EC_POINT *pub_point = NULL;
    BN_CTX *bn_ctx = NULL;
    unsigned char pub_key[65];
    size_t pub_len = 65;
    
    // Create the private key BIGNUM
    priv_bn = BN_bin2bn(secret, 32, NULL);
    if (!priv_bn) goto err;
    
    // Create EC_GROUP for secp256k1
    group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    if (!group) goto err;
    
    // Create the public key point
    pub_point = EC_POINT_new(group);
    if (!pub_point) goto err;
    
    bn_ctx = BN_CTX_new();
    if (!bn_ctx) goto err;
    
    // Calculate public key: pub = secret * G
    if (!EC_POINT_mul(group, pub_point, priv_bn, NULL, NULL, bn_ctx))
        goto err;
    
    // Convert public key to uncompressed format
    pub_len = EC_POINT_point2oct(group, pub_point, POINT_CONVERSION_UNCOMPRESSED,
                                  pub_key, sizeof(pub_key), bn_ctx);
    if (pub_len == 0) goto err;
    
    // Build parameters for EVP_PKEY
    param_bld = OSSL_PARAM_BLD_new();
    if (!param_bld) goto err;
    
    if (!OSSL_PARAM_BLD_push_utf8_string(param_bld, OSSL_PKEY_PARAM_GROUP_NAME, 
                                          SN_secp256k1, 0))
        goto err;
    if (!OSSL_PARAM_BLD_push_BN(param_bld, OSSL_PKEY_PARAM_PRIV_KEY, priv_bn))
        goto err;
    if (!OSSL_PARAM_BLD_push_octet_string(param_bld, OSSL_PKEY_PARAM_PUB_KEY,
                                           pub_key, pub_len))
        goto err;
    
    params = OSSL_PARAM_BLD_to_param(param_bld);
    if (!params) goto err;
    
    // Create EVP_PKEY context and key
    ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    if (!ctx) goto err;
    
    if (EVP_PKEY_fromdata_init(ctx) <= 0)
        goto err;
    
    if (EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_KEYPAIR, params) <= 0) {
        pkey = NULL;
        goto err;
    }

err:
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(param_bld);
    EVP_PKEY_CTX_free(ctx);
    BN_free(priv_bn);
    EC_POINT_free(pub_point);
    EC_GROUP_free(group);
    BN_CTX_free(bn_ctx);
    
    return pkey;
}

/**
 * Create an EVP_PKEY for secp256k1 from raw public key bytes
 */
static EVP_PKEY* CreateEVPKeyFromPubKey(const unsigned char* pubkey, size_t len) {
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    OSSL_PARAM_BLD *param_bld = NULL;
    OSSL_PARAM *params = NULL;
    
    if (len != 33 && len != 65)
        return NULL;
    
    // Build parameters for EVP_PKEY (public key only)
    param_bld = OSSL_PARAM_BLD_new();
    if (!param_bld) goto err;
    
    if (!OSSL_PARAM_BLD_push_utf8_string(param_bld, OSSL_PKEY_PARAM_GROUP_NAME,
                                          SN_secp256k1, 0))
        goto err;
    if (!OSSL_PARAM_BLD_push_octet_string(param_bld, OSSL_PKEY_PARAM_PUB_KEY,
                                           pubkey, len))
        goto err;
    
    params = OSSL_PARAM_BLD_to_param(param_bld);
    if (!params) goto err;
    
    // Create EVP_PKEY context and key
    ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    if (!ctx) goto err;
    
    if (EVP_PKEY_fromdata_init(ctx) <= 0)
        goto err;
    
    if (EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0) {
        pkey = NULL;
        goto err;
    }

err:
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(param_bld);
    EVP_PKEY_CTX_free(ctx);
    
    return pkey;
}

/**
 * Extract raw 32-byte secret from EVP_PKEY
 */
static bool GetSecretFromEVPKey(const EVP_PKEY *pkey, unsigned char vch[32]) {
    BIGNUM *priv_bn = NULL;
    int ret = 0;
    
    if (!EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, &priv_bn))
        return false;
    
    memset(vch, 0, 32);
    int nBytes = BN_num_bytes(priv_bn);
    if (nBytes <= 32) {
        BN_bn2bin(priv_bn, &vch[32 - nBytes]);
        ret = 1;
    }
    
    BN_clear_free(priv_bn);
    return ret == 1;
}

/**
 * Extract public key from EVP_PKEY
 */
static bool GetPubKeyFromEVPKey(const EVP_PKEY *pkey, unsigned char* out, size_t* outlen, bool compressed) {
    size_t len = 0;
    unsigned char buf[65];
    
    if (!EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, 
                                          buf, sizeof(buf), &len))
        return false;
    
    if (compressed && len == 65) {
        // Convert uncompressed to compressed format
        out[0] = (buf[64] & 1) ? 0x03 : 0x02;
        memcpy(out + 1, buf + 1, 32);
        *outlen = 33;
    } else {
        memcpy(out, buf, len);
        *outlen = len;
    }
    
    return true;
}

/**
 * BIP32 HMAC-SHA512 hash function
 */
static void BIP32Hash(const unsigned char chainCode[32], unsigned int nChild, 
                      unsigned char header, const unsigned char data[32], 
                      unsigned char output[64]) {
    unsigned char num[4];
    num[0] = (nChild >> 24) & 0xFF;
    num[1] = (nChild >> 16) & 0xFF;
    num[2] = (nChild >>  8) & 0xFF;
    num[3] = (nChild >>  0) & 0xFF;
    HMAC_SHA512_CTX ctx;
    HMAC_SHA512_Init(&ctx, chainCode, 32);
    HMAC_SHA512_Update(&ctx, &header, 1);
    HMAC_SHA512_Update(&ctx, data, 32);
    HMAC_SHA512_Update(&ctx, num, 4);
    HMAC_SHA512_Final(output, &ctx);
}

/**
 * Compare two big-endian byte arrays
 */
static int CompareBigEndian(const unsigned char *c1, size_t c1len, 
                            const unsigned char *c2, size_t c2len) {
    while (c1len > c2len) {
        if (*c1)
            return 1;
        c1++;
        c1len--;
    }
    while (c2len > c1len) {
        if (*c2)
            return -1;
        c2++;
        c2len--;
    }
    while (c1len > 0) {
        if (*c1 > *c2)
            return 1;
        if (*c2 > *c1)
            return -1;
        c1++;
        c2++;
        c1len--;
    }
    return 0;
}

// ============================================================================
// ECC_InitSanityCheck
// ============================================================================

bool ECC_InitSanityCheck() {
    // Test that we can create a secp256k1 key
    unsigned char secret[32];
    RAND_bytes(secret, 32);
    
    EVP_PKEY *pkey = CreateEVPKeyFromSecret(secret);
    if (!pkey)
        return false;
    
    EVP_PKEY_free(pkey);
    OPENSSL_cleanse(secret, 32);
    return true;
}

// ============================================================================
// ECDSA Key Recovery (SEC1 4.1.6)
// ============================================================================

EVP_PKEY* ECDSA_recover_key(const unsigned char *msg, int msglen,
                             const unsigned char *sig_r, const unsigned char *sig_s,
                             int recid, int check) {
    EVP_PKEY *pkey = NULL;
    BN_CTX *ctx = NULL;
    EC_GROUP *group = NULL;
    EC_POINT *R = NULL, *O = NULL, *Q = NULL;
    BIGNUM *x = NULL, *e = NULL, *order = NULL, *field = NULL;
    BIGNUM *sor = NULL, *eor = NULL, *rr = NULL, *zero = NULL;
    BIGNUM *r = NULL, *s = NULL;
    int ret = 0;
    int i = recid / 2;
    
    ctx = BN_CTX_new();
    if (!ctx) goto err;
    BN_CTX_start(ctx);
    
    group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    if (!group) goto err;
    
    order = BN_CTX_get(ctx);
    if (!EC_GROUP_get_order(group, order, ctx)) goto err;
    
    // Reconstruct r from signature
    r = BN_CTX_get(ctx);
    BN_bin2bn(sig_r, 32, r);
    
    s = BN_CTX_get(ctx);
    BN_bin2bn(sig_s, 32, s);
    
    // Calculate x = r + i * order
    x = BN_CTX_get(ctx);
    if (!BN_copy(x, order)) goto err;
    if (!BN_mul_word(x, i)) goto err;
    if (!BN_add(x, x, r)) goto err;
    
    field = BN_CTX_get(ctx);
    if (!EC_GROUP_get_curve(group, field, NULL, NULL, ctx)) goto err;
    if (BN_cmp(x, field) >= 0) goto err;
    
    // Recover R point
    R = EC_POINT_new(group);
    if (!R) goto err;
    if (!EC_POINT_set_compressed_coordinates(group, R, x, recid % 2, ctx))
        goto err;
    
    // Verify R is on curve and has correct order if check is set
    if (check) {
        O = EC_POINT_new(group);
        if (!O) goto err;
        if (!EC_POINT_mul(group, O, NULL, R, order, ctx)) goto err;
        if (!EC_POINT_is_at_infinity(group, O)) goto err;
    }
    
    // Calculate Q = r^-1 * (s*R - e*G)
    Q = EC_POINT_new(group);
    if (!Q) goto err;
    
    int n = EC_GROUP_get_degree(group);
    e = BN_CTX_get(ctx);
    if (!BN_bin2bn(msg, msglen, e)) goto err;
    if (8 * msglen > n) BN_rshift(e, e, 8 - (n & 7));
    
    zero = BN_CTX_get(ctx);
    BN_zero(zero);
    if (!BN_mod_sub(e, zero, e, order, ctx)) goto err;
    
    rr = BN_CTX_get(ctx);
    if (!BN_mod_inverse(rr, r, order, ctx)) goto err;
    
    sor = BN_CTX_get(ctx);
    if (!BN_mod_mul(sor, s, rr, order, ctx)) goto err;
    
    eor = BN_CTX_get(ctx);
    if (!BN_mod_mul(eor, e, rr, order, ctx)) goto err;
    
    if (!EC_POINT_mul(group, Q, eor, R, sor, ctx)) goto err;
    
    // Convert Q to public key bytes
    unsigned char pub_key[65];
    size_t pub_len = EC_POINT_point2oct(group, Q, POINT_CONVERSION_UNCOMPRESSED,
                                         pub_key, sizeof(pub_key), ctx);
    if (pub_len == 0) goto err;
    
    // Create EVP_PKEY from recovered public key
    pkey = CreateEVPKeyFromPubKey(pub_key, pub_len);
    
err:
    EC_POINT_free(R);
    EC_POINT_free(O);
    EC_POINT_free(Q);
    EC_GROUP_free(group);
    if (ctx) {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    
    return pkey;
}

// ============================================================================
// CECKey Implementation
// ============================================================================

CECKey::CECKey() : pkey(NULL) {
}

CECKey::~CECKey() {
    if (pkey)
        EVP_PKEY_free(pkey);
}

CECKey::CECKey(CECKey&& other) noexcept : pkey(other.pkey) {
    other.pkey = NULL;
}

CECKey& CECKey::operator=(CECKey&& other) noexcept {
    if (this != &other) {
        if (pkey)
            EVP_PKEY_free(pkey);
        pkey = other.pkey;
        other.pkey = NULL;
    }
    return *this;
}

void CECKey::GetSecretBytes(unsigned char vch[32]) const {
    if (!pkey)
        throw key_error("CECKey::GetSecretBytes: key not set");
    
    if (!GetSecretFromEVPKey(pkey, vch))
        throw key_error("CECKey::GetSecretBytes: failed to extract secret");
}

void CECKey::SetSecretBytes(const unsigned char vch[32]) {
    if (pkey) {
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }
    
    pkey = CreateEVPKeyFromSecret(vch);
    if (!pkey)
        throw key_error("CECKey::SetSecretBytes: failed to create key");
}

void CECKey::GetPrivKey(CPrivKey &privkey, bool fCompressed) {
    if (!pkey)
        throw key_error("CECKey::GetPrivKey: key not set");
    
    // Encode private key to DER format
    unsigned char *der = NULL;
    int der_len = 0;
    
    // Use OSSL_ENCODER for DER output
    OSSL_ENCODER_CTX *ectx = OSSL_ENCODER_CTX_new_for_pkey(pkey, 
        EVP_PKEY_KEYPAIR, "DER", "PrivateKeyInfo", NULL);
    if (!ectx)
        throw key_error("CECKey::GetPrivKey: failed to create encoder context");
    
    size_t len = 0;
    if (!OSSL_ENCODER_to_data(ectx, &der, &len)) {
        OSSL_ENCODER_CTX_free(ectx);
        throw key_error("CECKey::GetPrivKey: failed to encode private key");
    }
    
    privkey.resize(len);
    memcpy(&privkey[0], der, len);
    
    OPENSSL_free(der);
    OSSL_ENCODER_CTX_free(ectx);
}

bool CECKey::SetPrivKey(const CPrivKey &privkey, bool fSkipCheck) {
    if (pkey) {
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }
    
    const unsigned char *p = &privkey[0];
    size_t len = privkey.size();
    
    // Decode DER private key using OSSL_DECODER
    OSSL_DECODER_CTX *dctx = OSSL_DECODER_CTX_new_for_pkey(&pkey, "DER", 
        "PrivateKeyInfo", "EC", EVP_PKEY_KEYPAIR, NULL, NULL);
    if (!dctx)
        return false;
    
    if (!OSSL_DECODER_from_data(dctx, &p, &len)) {
        OSSL_DECODER_CTX_free(dctx);
        return false;
    }
    
    OSSL_DECODER_CTX_free(dctx);
    
    if (!fSkipCheck && !pkey)
        return false;
    
    return true;
}

void CECKey::GetPubKey(CPubKey &pubkey, bool fCompressed) {
    if (!pkey)
        throw key_error("CECKey::GetPubKey: key not set");
    
    unsigned char buf[65];
    size_t len = 0;
    
    if (!GetPubKeyFromEVPKey(pkey, buf, &len, fCompressed))
        throw key_error("CECKey::GetPubKey: failed to get public key");
    
    pubkey.Set(buf, buf + len);
}

bool CECKey::SetPubKey(const CPubKey &pubkey) {
    if (pkey) {
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }
    
    pkey = CreateEVPKeyFromPubKey(pubkey.begin(), pubkey.size());
    return pkey != NULL;
}

bool CECKey::Sign(const uint256 &hash, std::vector<unsigned char>& vchSig) {
    if (!pkey)
        return false;
    
    vchSig.clear();
    
    // Create signing context
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx)
        return false;
    
    // Initialize for signing (NULL digest for raw signing)
    EVP_PKEY_CTX *pctx = NULL;
    if (EVP_DigestSignInit_ex(mdctx, &pctx, NULL, NULL, NULL, pkey, NULL) <= 0) {
        EVP_MD_CTX_free(mdctx);
        return false;
    }
    
    // Determine signature size
    size_t siglen = 0;
    if (EVP_DigestSign(mdctx, NULL, &siglen, (unsigned char*)&hash, sizeof(hash)) <= 0) {
        EVP_MD_CTX_free(mdctx);
        return false;
    }
    
    vchSig.resize(siglen);
    
    // Sign the hash
    if (EVP_DigestSign(mdctx, &vchSig[0], &siglen, (unsigned char*)&hash, sizeof(hash)) <= 0) {
        EVP_MD_CTX_free(mdctx);
        vchSig.clear();
        return false;
    }
    
    vchSig.resize(siglen);
    EVP_MD_CTX_free(mdctx);
    
    // Enforce low S values (BIP 62)
    // Parse the DER signature to get r and s
    const unsigned char* p = &vchSig[0];
    ECDSA_SIG *sig = d2i_ECDSA_SIG(NULL, &p, vchSig.size());
    if (sig) {
        const BIGNUM *r_bn, *s_bn;
        ECDSA_SIG_get0(sig, &r_bn, &s_bn);
        
        BIGNUM *order = BN_new();
        BIGNUM *halforder = BN_new();
        BN_bin2bn(secp256k1_order, 32, order);
        BN_rshift1(halforder, order);
        
        if (BN_cmp(s_bn, halforder) > 0) {
            // s = order - s
            BIGNUM *new_s = BN_new();
            BN_sub(new_s, order, s_bn);
            ECDSA_SIG_set0(sig, BN_dup(r_bn), new_s);
            
            // Re-encode the signature
            int newlen = i2d_ECDSA_SIG(sig, NULL);
            vchSig.resize(newlen);
            unsigned char *pos = &vchSig[0];
            i2d_ECDSA_SIG(sig, &pos);
        }
        
        BN_free(order);
        BN_free(halforder);
        ECDSA_SIG_free(sig);
    }
    
    return true;
}

bool CECKey::Verify(const uint256 &hash, const std::vector<unsigned char>& vchSig) {
    if (!pkey)
        return false;
    
    // Create verification context
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx)
        return false;
    
    // Initialize for verification (NULL digest for raw verification)
    EVP_PKEY_CTX *pctx = NULL;
    if (EVP_DigestVerifyInit_ex(mdctx, &pctx, NULL, NULL, NULL, pkey, NULL) <= 0) {
        EVP_MD_CTX_free(mdctx);
        return false;
    }
    
    // Verify the signature
    int ret = EVP_DigestVerify(mdctx, &vchSig[0], vchSig.size(), 
                                (unsigned char*)&hash, sizeof(hash));
    EVP_MD_CTX_free(mdctx);
    
    return ret == 1;
}

bool CECKey::SignCompact(const uint256 &hash, unsigned char *p64, int &rec) {
    if (!pkey)
        return false;
    
    std::vector<unsigned char> vchSig;
    if (!Sign(hash, vchSig))
        return false;
    
    // Parse DER signature
    const unsigned char* p = &vchSig[0];
    ECDSA_SIG *sig = d2i_ECDSA_SIG(NULL, &p, vchSig.size());
    if (!sig)
        return false;
    
    const BIGNUM *r_bn, *s_bn;
    ECDSA_SIG_get0(sig, &r_bn, &s_bn);
    
    int nBitsR = BN_num_bits(r_bn);
    int nBitsS = BN_num_bits(s_bn);
    
    if (nBitsR > 256 || nBitsS > 256) {
        ECDSA_SIG_free(sig);
        return false;
    }
    
    memset(p64, 0, 64);
    BN_bn2bin(r_bn, &p64[32 - (nBitsR + 7) / 8]);
    BN_bn2bin(s_bn, &p64[64 - (nBitsS + 7) / 8]);
    
    // Find the recovery parameter
    CPubKey pubkey;
    GetPubKey(pubkey, true);
    
    bool fOk = false;
    for (int i = 0; i < 4; i++) {
        EVP_PKEY *recovered = ECDSA_recover_key((unsigned char*)&hash, sizeof(hash),
                                                 &p64[0], &p64[32], i, 1);
        if (recovered) {
            unsigned char rec_pub[65];
            size_t rec_len = 0;
            if (GetPubKeyFromEVPKey(recovered, rec_pub, &rec_len, true)) {
                CPubKey pubkeyRec(rec_pub, rec_pub + rec_len);
                if (pubkeyRec == pubkey) {
                    rec = i;
                    fOk = true;
                }
            }
            EVP_PKEY_free(recovered);
            if (fOk) break;
        }
    }
    
    ECDSA_SIG_free(sig);
    return fOk;
}

bool CECKey::Recover(const uint256 &hash, const unsigned char *p64, int rec) {
    if (rec < 0 || rec >= 4)
        return false;
    
    if (pkey) {
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }
    
    pkey = ECDSA_recover_key((unsigned char*)&hash, sizeof(hash),
                              &p64[0], &p64[32], rec, 0);
    return pkey != NULL;
}

bool CECKey::TweakSecret(unsigned char vchSecretOut[32], const unsigned char vchSecretIn[32], 
                          const unsigned char vchTweak[32]) {
    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) return false;
    
    BN_CTX_start(ctx);
    BIGNUM *bnSecret = BN_CTX_get(ctx);
    BIGNUM *bnTweak = BN_CTX_get(ctx);
    BIGNUM *bnOrder = BN_CTX_get(ctx);
    
    BN_bin2bn(secp256k1_order, 32, bnOrder);
    BN_bin2bn(vchTweak, 32, bnTweak);
    
    bool ret = true;
    if (BN_cmp(bnTweak, bnOrder) >= 0)
        ret = false; // extremely unlikely
    
    if (ret) {
        BN_bin2bn(vchSecretIn, 32, bnSecret);
        BN_add(bnSecret, bnSecret, bnTweak);
        BN_nnmod(bnSecret, bnSecret, bnOrder, ctx);
        
        if (BN_is_zero(bnSecret))
            ret = false; // ridiculously unlikely
        
        if (ret) {
            memset(vchSecretOut, 0, 32);
            int nBits = BN_num_bits(bnSecret);
            BN_bn2bin(bnSecret, &vchSecretOut[32 - (nBits + 7) / 8]);
        }
    }
    
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    return ret;
}

bool CECKey::TweakPublic(const unsigned char vchTweak[32]) {
    if (!pkey)
        return false;
    
    // Get current public key
    unsigned char pub_key[65];
    size_t pub_len = 0;
    if (!EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY,
                                          pub_key, sizeof(pub_key), &pub_len))
        return false;
    
    // Create EC_GROUP and EC_POINT
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    if (!group) return false;
    
    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) {
        EC_GROUP_free(group);
        return false;
    }
    
    EC_POINT *point = EC_POINT_new(group);
    if (!point) {
        BN_CTX_free(ctx);
        EC_GROUP_free(group);
        return false;
    }
    
    bool ret = false;
    
    // Convert public key bytes to point
    if (EC_POINT_oct2point(group, point, pub_key, pub_len, ctx)) {
        BIGNUM *bnOrder = BN_new();
        BIGNUM *bnTweak = BN_new();
        BIGNUM *bnOne = BN_new();
        
        EC_GROUP_get_order(group, bnOrder, ctx);
        BN_bin2bn(vchTweak, 32, bnTweak);
        BN_one(bnOne);
        
        if (BN_cmp(bnTweak, bnOrder) < 0) {
            // point = tweak * G + 1 * point
            EC_POINT_mul(group, point, bnTweak, point, bnOne, ctx);
            
            if (!EC_POINT_is_at_infinity(group, point)) {
                // Convert back to bytes
                pub_len = EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED,
                                              pub_key, sizeof(pub_key), ctx);
                if (pub_len > 0) {
                    // Create new EVP_PKEY with tweaked public key
                    EVP_PKEY_free(pkey);
                    pkey = CreateEVPKeyFromPubKey(pub_key, pub_len);
                    ret = (pkey != NULL);
                }
            }
        }
        
        BN_free(bnOrder);
        BN_free(bnTweak);
        BN_free(bnOne);
    }
    
    EC_POINT_free(point);
    BN_CTX_free(ctx);
    EC_GROUP_free(group);
    
    return ret;
}

// ============================================================================
// CKey Implementation
// ============================================================================

bool CKey::Check(const unsigned char *vch) {
    bool fIsZero = true;
    for (int i = 0; i < 32 && fIsZero; i++)
        if (vch[i] != 0)
            fIsZero = false;
    if (fIsZero)
        return false;
    for (int i = 0; i < 32; i++) {
        if (vch[i] < vchMaxModOrder[i])
            return true;
        if (vch[i] > vchMaxModOrder[i])
            return false;
    }
    return true;
}

CKey::CKey() : fValid(false), fCompressed(false) {
    LockObject(vch);
    memset(vch, 0, sizeof(vch));
}

CKey::CKey(const CKey& b) : fValid(b.fValid), fCompressed(b.fCompressed) {
    LockObject(vch);
    memcpy(vch, b.vch, sizeof(vch));
}

CKey::~CKey() {
    OPENSSL_cleanse(vch, sizeof(vch));
    UnlockObject(vch);
}

bool CKey::IsValid() const {
    return fValid;
}

bool CKey::IsCompressed() const {
    return fCompressed;
}

bool CKey::SetPubKey(const CPubKey& vchPubKey) {
    // This function validates that we can load the public key
    CECKey key;
    return key.SetPubKey(vchPubKey);
}

bool CKey::SetPrivKey(const CPrivKey &privkey, bool fCompressedIn) {
    CECKey key;
    if (!key.SetPrivKey(privkey))
        return false;
    key.GetSecretBytes(vch);
    fCompressed = fCompressedIn;
    fValid = true;
    return true;
}

bool CKey::SetSecret(const CSecret& vchSecret, bool fCompressedIn) {
    if (vchSecret.size() != 32)
        return false;
    memcpy(vch, &vchSecret[0], 32);
    fValid = Check(vch);
    fCompressed = fCompressedIn;
    return fValid;
}

CSecret CKey::GetSecret(bool &fCompressedOut) const {
    CSecret vchRet;
    vchRet.resize(32);
    memcpy(&vchRet[0], vch, 32);
    fCompressedOut = fCompressed;
    return vchRet;
}

void CKey::MakeNewKey(bool fCompressedIn) {
    RandAddSeedPerfmon();
    do {
        RAND_bytes(vch, sizeof(vch));
    } while (!Check(vch));
    fValid = true;
    fCompressed = fCompressedIn;
}

CPrivKey CKey::GetPrivKey() const {
    assert(fValid);
    CPrivKey privkey;
    CECKey key;
    key.SetSecretBytes(vch);
    key.GetPrivKey(privkey, fCompressed);
    return privkey;
}

CPubKey CKey::GetPubKey() const {
    assert(fValid);
    CPubKey pubkey;
    CECKey key;
    key.SetSecretBytes(vch);
    key.GetPubKey(pubkey, fCompressed);
    return pubkey;
}

bool CKey::Sign(uint256 hash, std::vector<unsigned char>& vchSig) const {
    if (!fValid)
        return false;
    CECKey key;
    key.SetSecretBytes(vch);
    return key.Sign(hash, vchSig);
}

bool CKey::SignCompact(const uint256 &hash, std::vector<unsigned char>& vchSig) const {
    if (!fValid)
        return false;
    vchSig.resize(65);
    int rec = -1;
    CECKey key;
    key.SetSecretBytes(vch);
    if (!key.SignCompact(hash, &vchSig[1], rec))
        return false;
    assert(rec != -1);
    vchSig[0] = 27 + rec + (fCompressed ? 4 : 0);
    return true;
}

bool CKey::Derive(CKey& keyChild, unsigned char ccChild[32], unsigned int nChild, 
                  const unsigned char cc[32]) const {
    assert(IsValid());
    assert(IsCompressed());
    unsigned char out[64];
    LockObject(out);
    if ((nChild >> 31) == 0) {
        CPubKey pubkey = GetPubKey();
        assert(pubkey.begin() + 33 == pubkey.end());
        BIP32Hash(cc, nChild, *pubkey.begin(), pubkey.begin() + 1, out);
    } else {
        assert(begin() + 32 == end());
        BIP32Hash(cc, nChild, 0, begin(), out);
    }
    memcpy(ccChild, out + 32, 32);
    bool ret = CECKey::TweakSecret((unsigned char*)keyChild.begin(), begin(), out);
    UnlockObject(out);
    keyChild.fCompressed = true;
    keyChild.fValid = ret;
    return ret;
}

bool CKey::Load(CPrivKey &privkey, CPubKey &vchPubKey, bool fSkipCheck) {
    CECKey key;
    if (!key.SetPrivKey(privkey, fSkipCheck))
        return false;

    key.GetSecretBytes(vch);
    fCompressed = vchPubKey.IsCompressed();
    fValid = true;

    if (fSkipCheck)
        return true;

    if (GetPubKey() != vchPubKey)
        return false;

    return true;
}

bool CKey::CheckSignatureElement(const unsigned char *vchElem, int len, bool half) {
    return CompareBigEndian(vchElem, len, vchZero, 0) > 0 &&
           CompareBigEndian(vchElem, len, half ? vchMaxModHalfOrder : vchMaxModOrder, 32) <= 0;
}

bool CKey::ReserealizeSignature(std::vector<unsigned char>& vchSig) {
    if (vchSig.empty())
        return false;

    const unsigned char *pos = &vchSig[0];
    ECDSA_SIG *sig = d2i_ECDSA_SIG(NULL, &pos, vchSig.size());
    if (sig == NULL)
        return false;

    bool ret = false;
    int nSize = i2d_ECDSA_SIG(sig, NULL);
    if (nSize > 0) {
        vchSig.resize(nSize);
        unsigned char *pout = &vchSig[0];
        i2d_ECDSA_SIG(sig, &pout);
        ret = true;
    }

    ECDSA_SIG_free(sig);
    return ret;
}

// ============================================================================
// CPubKey Implementation
// ============================================================================

bool CPubKey::Verify(const uint256 &hash, const std::vector<unsigned char>& vchSig) const {
    if (!IsValid())
        return false;
    CECKey key;
    if (!key.SetPubKey(*this))
        return false;
    if (!key.Verify(hash, vchSig))
        return false;
    return true;
}

bool CPubKey::RecoverCompact(const uint256 &hash, const std::vector<unsigned char>& vchSig) {
    if (vchSig.size() != 65)
        return false;
    int recid = (vchSig[0] - 27) & 3;
    bool fComp = (vchSig[0] - 27) & 4;
    CECKey key;
    if (!key.Recover(hash, &vchSig[1], recid))
        return false;
    key.GetPubKey(*this, fComp);
    return true;
}

bool CPubKey::VerifyCompact(const uint256 &hash, const std::vector<unsigned char>& vchSig) const {
    if (!IsValid())
        return false;
    if (vchSig.size() != 65)
        return false;
    int recid = (vchSig[0] - 27) & 3;
    CPubKey pubkeyRec;
    CECKey key;
    if (!key.Recover(hash, &vchSig[1], recid))
        return false;
    key.GetPubKey(pubkeyRec, IsCompressed());
    if (*this != pubkeyRec)
        return false;
    return true;
}

bool CPubKey::IsFullyValid() const {
    if (!IsValid())
        return false;
    CECKey key;
    if (!key.SetPubKey(*this))
        return false;
    return true;
}

bool CPubKey::Decompress() {
    if (!IsValid())
        return false;
    CECKey key;
    if (!key.SetPubKey(*this))
        return false;
    key.GetPubKey(*this, false);
    return true;
}

bool CPubKey::Derive(CPubKey& pubkeyChild, unsigned char ccChild[32], unsigned int nChild, 
                     const unsigned char cc[32]) const {
    assert(IsValid());
    assert((nChild >> 31) == 0);
    assert(begin() + 33 == end());
    unsigned char out[64];
    BIP32Hash(cc, nChild, *begin(), begin() + 1, out);
    memcpy(ccChild, out + 32, 32);
    CECKey key;
    bool ret = key.SetPubKey(*this);
    ret &= key.TweakPublic(out);
    key.GetPubKey(pubkeyChild, true);
    return ret;
}

// ============================================================================
// CExtKey / CExtPubKey Implementation
// ============================================================================

void CExtKey::Encode(unsigned char code[74]) const {
    code[0] = nDepth;
    memcpy(code + 1, vchFingerprint, 4);
    code[5] = (nChild >> 24) & 0xFF;
    code[6] = (nChild >> 16) & 0xFF;
    code[7] = (nChild >> 8) & 0xFF;
    code[8] = (nChild >> 0) & 0xFF;
    memcpy(code + 9, vchChainCode, 32);
    code[41] = 0;
    assert(key.size() == 32);
    memcpy(code + 42, key.begin(), 32);
}

void CExtKey::Decode(const unsigned char code[74]) {
    nDepth = code[0];
    memcpy(vchFingerprint, code + 1, 4);
    nChild = (code[5] << 24) | (code[6] << 16) | (code[7] << 8) | code[8];
    memcpy(vchChainCode, code + 9, 32);
    key.Set(code + 42, code + 74, true);
}

bool CExtKey::Derive(CExtKey &out, unsigned int nChild) const {
    out.nDepth = nDepth + 1;
    CKeyID id = key.GetPubKey().GetID();
    memcpy(&out.vchFingerprint[0], &id, 4);
    out.nChild = nChild;
    return key.Derive(out.key, out.vchChainCode, nChild, vchChainCode);
}

CExtPubKey CExtKey::Neuter() const {
    CExtPubKey ret;
    ret.nDepth = nDepth;
    memcpy(&ret.vchFingerprint[0], &vchFingerprint[0], 4);
    ret.nChild = nChild;
    ret.pubkey = key.GetPubKey();
    memcpy(&ret.vchChainCode[0], &vchChainCode[0], 32);
    return ret;
}

void CExtKey::SetMaster(const unsigned char *seed, unsigned int nSeedLen) {
    static const unsigned char hashkey[] = {'B', 'i', 't', 'c', 'o', 'i', 'n', ' ', 's', 'e', 'e', 'd'};
    unsigned char out[64];
    LockObject(out);
    HMAC_SHA512_CTX ctx;
    HMAC_SHA512_Init(&ctx, hashkey, sizeof(hashkey));
    HMAC_SHA512_Update(&ctx, seed, nSeedLen);
    HMAC_SHA512_Final(out, &ctx);
    key.Set(out, out + 32, true);
    memcpy(vchChainCode, out + 32, 32);
    UnlockObject(out);
    nDepth = 0;
    nChild = 0;
    memset(vchFingerprint, 0, sizeof(vchFingerprint));
}

void CExtPubKey::Encode(unsigned char code[74]) const {
    code[0] = nDepth;
    memcpy(code + 1, vchFingerprint, 4);
    code[5] = (nChild >> 24) & 0xFF;
    code[6] = (nChild >> 16) & 0xFF;
    code[7] = (nChild >> 8) & 0xFF;
    code[8] = (nChild >> 0) & 0xFF;
    memcpy(code + 9, vchChainCode, 32);
    assert(pubkey.size() == 33);
    memcpy(code + 41, pubkey.begin(), 33);
}

void CExtPubKey::Decode(const unsigned char code[74]) {
    nDepth = code[0];
    memcpy(vchFingerprint, code + 1, 4);
    nChild = (code[5] << 24) | (code[6] << 16) | (code[7] << 8) | code[8];
    memcpy(vchChainCode, code + 9, 32);
    pubkey.Set(code + 41, code + 74);
}

bool CExtPubKey::Derive(CExtPubKey &out, unsigned int nChild) const {
    out.nDepth = nDepth + 1;
    CKeyID id = pubkey.GetID();
    memcpy(&out.vchFingerprint[0], &id, 4);
    out.nChild = nChild;
    return pubkey.Derive(out.pubkey, out.vchChainCode, nChild, vchChainCode);
}

// Global tweak function
bool TweakSecret(unsigned char vchSecretOut[32], const unsigned char vchSecretIn[32], 
                 const unsigned char vchTweak[32]) {
    return CECKey::TweakSecret(vchSecretOut, vchSecretIn, vchTweak);
}