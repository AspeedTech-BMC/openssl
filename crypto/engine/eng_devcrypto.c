/*
 * Copyright 2017-2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "e_os.h"
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <assert.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/engine.h>
#include <openssl/objects.h>
#include <openssl/ecdsa.h>
#include <crypto/cryptodev.h>

#include "crypto/engine.h"

/* #define ENGINE_DEVCRYPTO_DEBUG */

#if CRYPTO_ALGORITHM_MIN < CRYPTO_ALGORITHM_MAX
# define CHECK_BSD_STYLE_MACROS
#endif

/*
 * ONE global file descriptor for all sessions.  This allows operations
 * such as digest session data copying (see digest_copy()), but is also
 * saner...  why re-open /dev/crypto for every session?
 */
static int cfd;

static int clean_devcrypto_session(struct session_op *sess) {
    if (ioctl(cfd, CIOCFSESSION, &sess->ses) < 0) {
        SYSerr(SYS_F_IOCTL, errno);
        return 0;
    }
    memset(sess, 0, sizeof(struct session_op));
    return 1;
}

/******************************************************************************
 *
 * Ciphers
 *
 * Because they all do the same basic operation, we have only one set of
 * method functions for them all to share, and a mapping table between
 * NIDs and cryptodev IDs, with all the necessary size data.
 *
 *****/

struct cipher_ctx {
    struct session_op sess;
    int op;                      /* COP_ENCRYPT or COP_DECRYPT */
    unsigned long mode;          /* EVP_CIPH_*_MODE */

    /* to handle ctr mode being a stream cipher */
    unsigned char partial[EVP_MAX_BLOCK_LENGTH];
    unsigned int blocksize, num;
};

static const struct cipher_data_st {
    int nid;
    int blocksize;
    int keylen;
    int ivlen;
    int flags;
    int devcryptoid;
} cipher_data[] = {
#ifndef OPENSSL_NO_DES
    { NID_des_cbc, 8, 8, 8, EVP_CIPH_CBC_MODE, CRYPTO_DES_CBC },
    { NID_des_ede3_cbc, 8, 24, 8, EVP_CIPH_CBC_MODE, CRYPTO_3DES_CBC },
#endif
#ifndef OPENSSL_NO_BF
    { NID_bf_cbc, 8, 16, 8, EVP_CIPH_CBC_MODE, CRYPTO_BLF_CBC },
#endif
#ifndef OPENSSL_NO_CAST
    { NID_cast5_cbc, 8, 16, 8, EVP_CIPH_CBC_MODE, CRYPTO_CAST_CBC },
#endif
    { NID_aes_128_cbc, 16, 128 / 8, 16, EVP_CIPH_CBC_MODE, CRYPTO_AES_CBC },
    { NID_aes_192_cbc, 16, 192 / 8, 16, EVP_CIPH_CBC_MODE, CRYPTO_AES_CBC },
    { NID_aes_256_cbc, 16, 256 / 8, 16, EVP_CIPH_CBC_MODE, CRYPTO_AES_CBC },
#ifndef OPENSSL_NO_RC4
    { NID_rc4, 1, 16, 0, EVP_CIPH_STREAM_CIPHER, CRYPTO_ARC4 },
#endif
#if !defined(CHECK_BSD_STYLE_MACROS) || defined(CRYPTO_AES_CTR)
    { NID_aes_128_ctr, 16, 128 / 8, 16, EVP_CIPH_CTR_MODE, CRYPTO_AES_CTR },
    { NID_aes_192_ctr, 16, 192 / 8, 16, EVP_CIPH_CTR_MODE, CRYPTO_AES_CTR },
    { NID_aes_256_ctr, 16, 256 / 8, 16, EVP_CIPH_CTR_MODE, CRYPTO_AES_CTR },
#endif
#if 0                            /* Not yet supported */
    { NID_aes_128_xts, 16, 128 / 8 * 2, 16, EVP_CIPH_XTS_MODE, CRYPTO_AES_XTS },
    { NID_aes_256_xts, 16, 256 / 8 * 2, 16, EVP_CIPH_XTS_MODE, CRYPTO_AES_XTS },
#endif
#if !defined(CHECK_BSD_STYLE_MACROS) || defined(CRYPTO_AES_ECB)
    { NID_aes_128_ecb, 16, 128 / 8, 0, EVP_CIPH_ECB_MODE, CRYPTO_AES_ECB },
    { NID_aes_192_ecb, 16, 192 / 8, 0, EVP_CIPH_ECB_MODE, CRYPTO_AES_ECB },
    { NID_aes_256_ecb, 16, 256 / 8, 0, EVP_CIPH_ECB_MODE, CRYPTO_AES_ECB },
#endif
#if 0                            /* Not yet supported */
    { NID_aes_128_gcm, 16, 128 / 8, 16, EVP_CIPH_GCM_MODE, CRYPTO_AES_GCM },
    { NID_aes_192_gcm, 16, 192 / 8, 16, EVP_CIPH_GCM_MODE, CRYPTO_AES_GCM },
    { NID_aes_256_gcm, 16, 256 / 8, 16, EVP_CIPH_GCM_MODE, CRYPTO_AES_GCM },
#endif
#ifndef OPENSSL_NO_CAMELLIA
    { NID_camellia_128_cbc, 16, 128 / 8, 16, EVP_CIPH_CBC_MODE,
      CRYPTO_CAMELLIA_CBC },
    { NID_camellia_192_cbc, 16, 192 / 8, 16, EVP_CIPH_CBC_MODE,
      CRYPTO_CAMELLIA_CBC },
    { NID_camellia_256_cbc, 16, 256 / 8, 16, EVP_CIPH_CBC_MODE,
      CRYPTO_CAMELLIA_CBC },
#endif
};

static size_t get_cipher_data_index(int nid)
{
    size_t i;

    for (i = 0; i < OSSL_NELEM(cipher_data); i++)
        if (nid == cipher_data[i].nid)
            return i;

    /*
     * Code further down must make sure that only NIDs in the table above
     * are used.  If any other NID reaches this function, there's a grave
     * coding error further down.
     */
    assert("Code that never should be reached" == NULL);
    return -1;
}

static const struct cipher_data_st *get_cipher_data(int nid)
{
    return &cipher_data[get_cipher_data_index(nid)];
}

/*
 * Following are the three necessary functions to map OpenSSL functionality
 * with cryptodev.
 */

static int cipher_init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                       const unsigned char *iv, int enc)
{
    struct cipher_ctx *cipher_ctx =
        (struct cipher_ctx *)EVP_CIPHER_CTX_get_cipher_data(ctx);
    const struct cipher_data_st *cipher_d =
        get_cipher_data(EVP_CIPHER_CTX_nid(ctx));

    /* cleanup a previous session */
    if (cipher_ctx->sess.ses != 0 &&
        clean_devcrypto_session(&cipher_ctx->sess) == 0)
        return 0;

    cipher_ctx->sess.cipher = cipher_d->devcryptoid;
    cipher_ctx->sess.keylen = cipher_d->keylen;
    cipher_ctx->sess.key = (void *)key;
    cipher_ctx->op = enc ? COP_ENCRYPT : COP_DECRYPT;
    cipher_ctx->mode = cipher_d->flags & EVP_CIPH_MODE;
    cipher_ctx->blocksize = cipher_d->blocksize;
    if (ioctl(cfd, CIOCGSESSION, &cipher_ctx->sess) < 0) {
        SYSerr(SYS_F_IOCTL, errno);
        return 0;
    }

    return 1;
}

static int cipher_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                            const unsigned char *in, size_t inl)
{
    struct cipher_ctx *cipher_ctx =
        (struct cipher_ctx *)EVP_CIPHER_CTX_get_cipher_data(ctx);
    struct crypt_op cryp;
    unsigned char *iv = EVP_CIPHER_CTX_iv_noconst(ctx);
#if !defined(COP_FLAG_WRITE_IV)
    unsigned char saved_iv[EVP_MAX_IV_LENGTH];
    const unsigned char *ivptr;
    size_t nblocks, ivlen;
#endif

    memset(&cryp, 0, sizeof(cryp));
    cryp.ses = cipher_ctx->sess.ses;
    cryp.len = inl;
    cryp.src = (void *)in;
    cryp.dst = (void *)out;
    cryp.iv = (void *)iv;
    cryp.op = cipher_ctx->op;
#if !defined(COP_FLAG_WRITE_IV)
    cryp.flags = 0;

    ivlen = EVP_CIPHER_CTX_iv_length(ctx);
    if (ivlen > 0)
        switch (cipher_ctx->mode) {
        case EVP_CIPH_CBC_MODE:
            assert(inl >= ivlen);
            if (!EVP_CIPHER_CTX_encrypting(ctx)) {
                ivptr = in + inl - ivlen;
                memcpy(saved_iv, ivptr, ivlen);
            }
            break;

        case EVP_CIPH_CTR_MODE:
            break;

        default: /* should not happen */
            return 0;
        }
#else
    cryp.flags = COP_FLAG_WRITE_IV;
#endif

    if (ioctl(cfd, CIOCCRYPT, &cryp) < 0) {
        SYSerr(SYS_F_IOCTL, errno);
        return 0;
    }

#if !defined(COP_FLAG_WRITE_IV)
    if (ivlen > 0)
        switch (cipher_ctx->mode) {
        case EVP_CIPH_CBC_MODE:
            assert(inl >= ivlen);
            if (EVP_CIPHER_CTX_encrypting(ctx))
                ivptr = out + inl - ivlen;
            else
                ivptr = saved_iv;

            memcpy(iv, ivptr, ivlen);
            break;

        case EVP_CIPH_CTR_MODE:
            nblocks = (inl + cipher_ctx->blocksize - 1)
                      / cipher_ctx->blocksize;
            do {
                ivlen--;
                nblocks += iv[ivlen];
                iv[ivlen] = (uint8_t) nblocks;
                nblocks >>= 8;
            } while (ivlen);
            break;

        default: /* should not happen */
            return 0;
        }
#endif

    return 1;
}

static int ctr_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                         const unsigned char *in, size_t inl)
{
    struct cipher_ctx *cipher_ctx =
        (struct cipher_ctx *)EVP_CIPHER_CTX_get_cipher_data(ctx);
    size_t nblocks, len;

    /* initial partial block */
    while (cipher_ctx->num && inl) {
        (*out++) = *(in++) ^ cipher_ctx->partial[cipher_ctx->num];
        --inl;
        cipher_ctx->num = (cipher_ctx->num + 1) % cipher_ctx->blocksize;
    }

    /* full blocks */
    if (inl > (unsigned int) cipher_ctx->blocksize) {
        nblocks = inl/cipher_ctx->blocksize;
        len = nblocks * cipher_ctx->blocksize;
        if (cipher_do_cipher(ctx, out, in, len) < 1)
            return 0;
        inl -= len;
        out += len;
        in += len;
    }

    /* final partial block */
    if (inl) {
        memset(cipher_ctx->partial, 0, cipher_ctx->blocksize);
        if (cipher_do_cipher(ctx, cipher_ctx->partial, cipher_ctx->partial,
            cipher_ctx->blocksize) < 1)
            return 0;
        while (inl--) {
            out[cipher_ctx->num] = in[cipher_ctx->num]
                                   ^ cipher_ctx->partial[cipher_ctx->num];
            cipher_ctx->num++;
        }
    }

    return 1;
}

static int cipher_ctrl(EVP_CIPHER_CTX *ctx, int type, int p1, void* p2)
{
    struct cipher_ctx *cipher_ctx =
        (struct cipher_ctx *)EVP_CIPHER_CTX_get_cipher_data(ctx);
    EVP_CIPHER_CTX *to_ctx = (EVP_CIPHER_CTX *)p2;
    struct cipher_ctx *to_cipher_ctx;

    switch (type) {
    case EVP_CTRL_COPY:
        if (cipher_ctx == NULL)
            return 1;
        /* when copying the context, a new session needs to be initialized */
        to_cipher_ctx =
            (struct cipher_ctx *)EVP_CIPHER_CTX_get_cipher_data(to_ctx);
        memset(&to_cipher_ctx->sess, 0, sizeof(to_cipher_ctx->sess));
        return cipher_init(to_ctx, cipher_ctx->sess.key, EVP_CIPHER_CTX_iv(ctx),
                           (cipher_ctx->op == COP_ENCRYPT));

    case EVP_CTRL_INIT:
        memset(&cipher_ctx->sess, 0, sizeof(cipher_ctx->sess));
        return 1;

    default:
        break;
    }

    return -1;
}

static int cipher_cleanup(EVP_CIPHER_CTX *ctx)
{
    struct cipher_ctx *cipher_ctx =
        (struct cipher_ctx *)EVP_CIPHER_CTX_get_cipher_data(ctx);

    return clean_devcrypto_session(&cipher_ctx->sess);
}

/*
 * Keep a table of known nids and associated methods.
 * Note that known_cipher_nids[] isn't necessarily indexed the same way as
 * cipher_data[] above, which known_cipher_methods[] is.
 */
static int known_cipher_nids[OSSL_NELEM(cipher_data)];
static int known_cipher_nids_amount = -1; /* -1 indicates not yet initialised */
static EVP_CIPHER *known_cipher_methods[OSSL_NELEM(cipher_data)] = { NULL, };

static void prepare_cipher_methods(void)
{
    size_t i;
    struct session_op sess;
    unsigned long cipher_mode;

    memset(&sess, 0, sizeof(sess));
    sess.key = (void *)"01234567890123456789012345678901234567890123456789";

    for (i = 0, known_cipher_nids_amount = 0;
         i < OSSL_NELEM(cipher_data); i++) {

        /*
         * Check that the algo is really availably by trying to open and close
         * a session.
         */
        sess.cipher = cipher_data[i].devcryptoid;
        sess.keylen = cipher_data[i].keylen;
        if (ioctl(cfd, CIOCGSESSION, &sess) < 0
            || ioctl(cfd, CIOCFSESSION, &sess.ses) < 0)
            continue;

        cipher_mode = cipher_data[i].flags & EVP_CIPH_MODE;

        if ((known_cipher_methods[i] =
                 EVP_CIPHER_meth_new(cipher_data[i].nid,
                                     cipher_mode == EVP_CIPH_CTR_MODE ? 1 :
                                                    cipher_data[i].blocksize,
                                     cipher_data[i].keylen)) == NULL
            || !EVP_CIPHER_meth_set_iv_length(known_cipher_methods[i],
                                              cipher_data[i].ivlen)
            || !EVP_CIPHER_meth_set_flags(known_cipher_methods[i],
                                          cipher_data[i].flags
                                          | EVP_CIPH_CUSTOM_COPY
                                          | EVP_CIPH_CTRL_INIT
                                          | EVP_CIPH_FLAG_DEFAULT_ASN1)
            || !EVP_CIPHER_meth_set_init(known_cipher_methods[i], cipher_init)
            || !EVP_CIPHER_meth_set_do_cipher(known_cipher_methods[i],
                                     cipher_mode == EVP_CIPH_CTR_MODE ?
                                              ctr_do_cipher :
                                              cipher_do_cipher)
            || !EVP_CIPHER_meth_set_ctrl(known_cipher_methods[i], cipher_ctrl)
            || !EVP_CIPHER_meth_set_cleanup(known_cipher_methods[i],
                                            cipher_cleanup)
            || !EVP_CIPHER_meth_set_impl_ctx_size(known_cipher_methods[i],
                                                  sizeof(struct cipher_ctx))) {
            EVP_CIPHER_meth_free(known_cipher_methods[i]);
            known_cipher_methods[i] = NULL;
        } else {
            known_cipher_nids[known_cipher_nids_amount++] =
                cipher_data[i].nid;
        }
    }
}

static const EVP_CIPHER *get_cipher_method(int nid)
{
    size_t i = get_cipher_data_index(nid);

    if (i == (size_t)-1)
        return NULL;
    return known_cipher_methods[i];
}

static int get_cipher_nids(const int **nids)
{
    *nids = known_cipher_nids;
    return known_cipher_nids_amount;
}

static void destroy_cipher_method(int nid)
{
    size_t i = get_cipher_data_index(nid);

    EVP_CIPHER_meth_free(known_cipher_methods[i]);
    known_cipher_methods[i] = NULL;
}

static void destroy_all_cipher_methods(void)
{
    size_t i;

    for (i = 0; i < OSSL_NELEM(cipher_data); i++)
        destroy_cipher_method(cipher_data[i].nid);
}

static int devcrypto_ciphers(ENGINE *e, const EVP_CIPHER **cipher,
                             const int **nids, int nid)
{
    if (cipher == NULL)
        return get_cipher_nids(nids);

    *cipher = get_cipher_method(nid);

    return *cipher != NULL;
}

/*
 * We only support digests if the cryptodev implementation supports multiple
 * data updates and session copying.  Otherwise, we would be forced to maintain
 * a cache, which is perilous if there's a lot of data coming in (if someone
 * wants to checksum an OpenSSL tarball, for example).
 */
#if defined(CIOCCPHASH) && defined(COP_FLAG_UPDATE) && defined(COP_FLAG_FINAL)
#define IMPLEMENT_DIGEST

/******************************************************************************
 *
 * Digests
 *
 * Because they all do the same basic operation, we have only one set of
 * method functions for them all to share, and a mapping table between
 * NIDs and cryptodev IDs, with all the necessary size data.
 *
 *****/

struct digest_ctx {
    struct session_op sess;
    /* This signals that the init function was called, not that it succeeded. */
    int init_called;
};

static const struct digest_data_st {
    int nid;
    int blocksize;
    int digestlen;
    int devcryptoid;
} digest_data[] = {
#ifndef OPENSSL_NO_MD5
    { NID_md5, /* MD5_CBLOCK */ 64, 16, CRYPTO_MD5 },
#endif
    { NID_sha1, SHA_CBLOCK, 20, CRYPTO_SHA1 },
#ifndef OPENSSL_NO_RMD160
# if !defined(CHECK_BSD_STYLE_MACROS) || defined(CRYPTO_RIPEMD160)
    { NID_ripemd160, /* RIPEMD160_CBLOCK */ 64, 20, CRYPTO_RIPEMD160 },
# endif
#endif
#if !defined(CHECK_BSD_STYLE_MACROS) || defined(CRYPTO_SHA2_224)
    { NID_sha224, SHA256_CBLOCK, 224 / 8, CRYPTO_SHA2_224 },
#endif
#if !defined(CHECK_BSD_STYLE_MACROS) || defined(CRYPTO_SHA2_256)
    { NID_sha256, SHA256_CBLOCK, 256 / 8, CRYPTO_SHA2_256 },
#endif
#if !defined(CHECK_BSD_STYLE_MACROS) || defined(CRYPTO_SHA2_384)
    { NID_sha384, SHA512_CBLOCK, 384 / 8, CRYPTO_SHA2_384 },
#endif
#if !defined(CHECK_BSD_STYLE_MACROS) || defined(CRYPTO_SHA2_512)
    { NID_sha512, SHA512_CBLOCK, 512 / 8, CRYPTO_SHA2_512 },
#endif
};

static size_t get_digest_data_index(int nid)
{
    size_t i;

    for (i = 0; i < OSSL_NELEM(digest_data); i++)
        if (nid == digest_data[i].nid)
            return i;

    /*
     * Code further down must make sure that only NIDs in the table above
     * are used.  If any other NID reaches this function, there's a grave
     * coding error further down.
     */
    assert("Code that never should be reached" == NULL);
    return -1;
}

static const struct digest_data_st *get_digest_data(int nid)
{
    return &digest_data[get_digest_data_index(nid)];
}

/*
 * Following are the four necessary functions to map OpenSSL functionality
 * with cryptodev.
 */

static int digest_init(EVP_MD_CTX *ctx)
{
    struct digest_ctx *digest_ctx =
        (struct digest_ctx *)EVP_MD_CTX_md_data(ctx);
    const struct digest_data_st *digest_d =
        get_digest_data(EVP_MD_CTX_type(ctx));

    digest_ctx->init_called = 1;

    memset(&digest_ctx->sess, 0, sizeof(digest_ctx->sess));
    digest_ctx->sess.mac = digest_d->devcryptoid;
    if (ioctl(cfd, CIOCGSESSION, &digest_ctx->sess) < 0) {
        SYSerr(SYS_F_IOCTL, errno);
        return 0;
    }

    return 1;
}

static int digest_op(struct digest_ctx *ctx, const void *src, size_t srclen,
                     void *res, unsigned int flags)
{
    struct crypt_op cryp;

    memset(&cryp, 0, sizeof(cryp));
    cryp.ses = ctx->sess.ses;
    cryp.len = srclen;
    cryp.src = (void *)src;
    cryp.dst = NULL;
    cryp.mac = res;
    cryp.flags = flags;
    return ioctl(cfd, CIOCCRYPT, &cryp);
}

static int digest_update(EVP_MD_CTX *ctx, const void *data, size_t count)
{
    struct digest_ctx *digest_ctx =
        (struct digest_ctx *)EVP_MD_CTX_md_data(ctx);

    if (count == 0)
        return 1;

    if (digest_ctx == NULL)
        return 0;

    if (digest_op(digest_ctx, data, count, NULL, COP_FLAG_UPDATE) < 0) {
        SYSerr(SYS_F_IOCTL, errno);
        return 0;
    }

    return 1;
}

static int digest_final(EVP_MD_CTX *ctx, unsigned char *md)
{
    struct digest_ctx *digest_ctx =
        (struct digest_ctx *)EVP_MD_CTX_md_data(ctx);

    if (md == NULL || digest_ctx == NULL)
        return 0;
    if (digest_op(digest_ctx, NULL, 0, md, COP_FLAG_FINAL) < 0) {
        SYSerr(SYS_F_IOCTL, errno);
        return 0;
    }

    return 1;
}

static int digest_copy(EVP_MD_CTX *to, const EVP_MD_CTX *from)
{
    struct digest_ctx *digest_from =
        (struct digest_ctx *)EVP_MD_CTX_md_data(from);
    struct digest_ctx *digest_to =
        (struct digest_ctx *)EVP_MD_CTX_md_data(to);
    struct cphash_op cphash;

    if (digest_from == NULL || digest_from->init_called != 1)
        return 1;

    if (!digest_init(to)) {
        SYSerr(SYS_F_IOCTL, errno);
        return 0;
    }

    cphash.src_ses = digest_from->sess.ses;
    cphash.dst_ses = digest_to->sess.ses;
    if (ioctl(cfd, CIOCCPHASH, &cphash) < 0) {
        SYSerr(SYS_F_IOCTL, errno);
        return 0;
    }
    return 1;
}

static int digest_cleanup(EVP_MD_CTX *ctx)
{
    struct digest_ctx *digest_ctx =
        (struct digest_ctx *)EVP_MD_CTX_md_data(ctx);

    if (digest_ctx == NULL)
        return 1;

    return clean_devcrypto_session(&digest_ctx->sess);
}

static int devcrypto_test_digest(size_t digest_data_index)
{
    struct session_op sess1, sess2;
    struct cphash_op cphash;
    int ret=0;

    memset(&sess1, 0, sizeof(sess1));
    memset(&sess2, 0, sizeof(sess2));
    sess1.mac = digest_data[digest_data_index].devcryptoid;
    if (ioctl(cfd, CIOCGSESSION, &sess1) < 0)
        return 0;
    /* Make sure the driver is capable of hash state copy */
    sess2.mac = sess1.mac;
    if (ioctl(cfd, CIOCGSESSION, &sess2) >= 0) {
        cphash.src_ses = sess1.ses;
        cphash.dst_ses = sess2.ses;
        if (ioctl(cfd, CIOCCPHASH, &cphash) >= 0)
            ret = 1;
        ioctl(cfd, CIOCFSESSION, &sess2.ses);
    }
    ioctl(cfd, CIOCFSESSION, &sess1.ses);
    return ret;
}

/*
 * Keep a table of known nids and associated methods.
 * Note that known_digest_nids[] isn't necessarily indexed the same way as
 * digest_data[] above, which known_digest_methods[] is.
 */
static int known_digest_nids[OSSL_NELEM(digest_data)];
static int known_digest_nids_amount = -1; /* -1 indicates not yet initialised */
static EVP_MD *known_digest_methods[OSSL_NELEM(digest_data)] = { NULL, };

static void prepare_digest_methods(void)
{
    size_t i;

    for (i = 0, known_digest_nids_amount = 0; i < OSSL_NELEM(digest_data);
         i++) {

        /*
         * Check that the algo is usable
         */
        if (!devcrypto_test_digest(i))
            continue;

        if ((known_digest_methods[i] = EVP_MD_meth_new(digest_data[i].nid,
                                                       NID_undef)) == NULL
            || !EVP_MD_meth_set_input_blocksize(known_digest_methods[i],
                                                digest_data[i].blocksize)
            || !EVP_MD_meth_set_result_size(known_digest_methods[i],
                                            digest_data[i].digestlen)
            || !EVP_MD_meth_set_init(known_digest_methods[i], digest_init)
            || !EVP_MD_meth_set_update(known_digest_methods[i], digest_update)
            || !EVP_MD_meth_set_final(known_digest_methods[i], digest_final)
            || !EVP_MD_meth_set_copy(known_digest_methods[i], digest_copy)
            || !EVP_MD_meth_set_cleanup(known_digest_methods[i], digest_cleanup)
            || !EVP_MD_meth_set_app_datasize(known_digest_methods[i],
                                             sizeof(struct digest_ctx))) {
            EVP_MD_meth_free(known_digest_methods[i]);
            known_digest_methods[i] = NULL;
        } else {
            known_digest_nids[known_digest_nids_amount++] = digest_data[i].nid;
        }
    }
}

static const EVP_MD *get_digest_method(int nid)
{
    size_t i = get_digest_data_index(nid);

    if (i == (size_t)-1)
        return NULL;
    return known_digest_methods[i];
}

static int get_digest_nids(const int **nids)
{
    *nids = known_digest_nids;
    return known_digest_nids_amount;
}

static void destroy_digest_method(int nid)
{
    size_t i = get_digest_data_index(nid);

    EVP_MD_meth_free(known_digest_methods[i]);
    known_digest_methods[i] = NULL;
}

static void destroy_all_digest_methods(void)
{
    size_t i;

    for (i = 0; i < OSSL_NELEM(digest_data); i++)
        destroy_digest_method(digest_data[i].nid);
}

static int devcrypto_digests(ENGINE *e, const EVP_MD **digest,
                             const int **nids, int nid)
{
    if (digest == NULL)
        return get_digest_nids(nids);

    *digest = get_digest_method(nid);

    return *digest != NULL;
}

#endif

/******************************************************************************
 *
 * Asymmetric
 *
 *****/

static u_int32_t cryptodev_asymfeat = 0;

static RSA_METHOD *devcrypto_rsa;
static EC_KEY_METHOD *devcrypto_ec;

int (*sign)(int type, const unsigned char *dgst,
            int dlen, unsigned char *sig,
            unsigned int *siglen,
            const BIGNUM *kinv, const BIGNUM *r,
            EC_KEY *eckey);
int (*sign_setup)(EC_KEY *eckey, BN_CTX *ctx_in, 
                  BIGNUM **kinvp, BIGNUM **rp);
ECDSA_SIG *(*sign_sig)(const unsigned char *dgst,
                       int dgst_len,
                       const BIGNUM *in_kinv,
                       const BIGNUM *in_r,
                       EC_KEY *eckey);

int (*verify)(int type, const unsigned
              char *dgst, int dgst_len,
              const unsigned char *sigbuf,
              int sig_len, EC_KEY *eckey);
int (*verify_sig)(const unsigned char *dgst,
                  int dgst_len,
                  const ECDSA_SIG *sig,
                  EC_KEY *eckey);

static int bn2crparam(const BIGNUM *a, struct crparam *crp);
static int crparam2bn(struct crparam *crp, BIGNUM *a);
static int cryptodev_asym(struct crypt_kop *kop, int rlen, BIGNUM *r,
                          int slen, BIGNUM *s);
static void zapparams(struct crypt_kop *kop);

/*
 * Convert a BIGNUM to the representation that /dev/crypto needs.
 * Upon completion of use, the caller is responsible for freeing
 * crp->crp_p.
 */
static int bn2crparam(const BIGNUM *a, struct crparam *crp)
{
    ssize_t bytes, bits;
    u_char *b;

    crp->crp_p = NULL;
    crp->crp_nbits = 0;

    bits = BN_num_bits(a);
    bytes = BN_num_bytes(a);

    b = OPENSSL_zalloc(bytes);
    if (b == NULL)
        return (1);

    crp->crp_p = (__u8 *) b;
    crp->crp_nbits = bits;

    BN_bn2bin(a, b);
    return (0);
}

/* Convert a /dev/crypto parameter to a BIGNUM */
static int crparam2bn(struct crparam *crp, BIGNUM *a)
{
    u_int8_t *pd;
    int i, bytes;

    bytes = (crp->crp_nbits + 7) / 8;

    if (bytes == 0)
        return (-1);

    if ((pd = OPENSSL_malloc(bytes)) == NULL)
        return (-1);

    for (i = 0; i < bytes; i++)
        pd[i] = crp->crp_p[bytes - i - 1];

    BN_bin2bn(pd, bytes, a);
    free(pd);

    return (0);
}

static void zapparams(struct crypt_kop *kop)
{
    int i;

    for (i = 0; i < kop->crk_iparams + kop->crk_oparams; i++) {
        OPENSSL_free(kop->crk_param[i].crp_p);
        kop->crk_param[i].crp_p = NULL;
        kop->crk_param[i].crp_nbits = 0;
    }
}

static int bin2crparam(const unsigned char *a, int a_len, struct crparam *crp)
{
    // ssize_t bytes, bits;
    unsigned char *b;

    crp->crp_p = NULL;
    crp->crp_nbits = 0;

    b = OPENSSL_zalloc(a_len);
    if (b == NULL)
        return (1);

    memcpy(b, a, a_len);

    crp->crp_p = (__u8 *) b;
    crp->crp_nbits = a_len * 8;

    return (0);
}

static int
cryptodev_asym(struct crypt_kop *kop, int rlen, BIGNUM *r, int slen,
               BIGNUM *s)
{
    int ret = -1;

    if (r) {
        kop->crk_param[kop->crk_iparams].crp_p = OPENSSL_zalloc(rlen);
        if (kop->crk_param[kop->crk_iparams].crp_p == NULL)
            return ret;
        kop->crk_param[kop->crk_iparams].crp_nbits = rlen * 8;
        kop->crk_oparams++;
    }
    if (s) {
        kop->crk_param[kop->crk_iparams + 1].crp_p =
            OPENSSL_zalloc(slen);
        /* No need to free the kop->crk_iparams parameter if it was allocated,
         * callers of this routine have to free allocated parameters through
         * zapparams both in case of success and failure
         */
        if (kop->crk_param[kop->crk_iparams+1].crp_p == NULL)
            return ret;
        kop->crk_param[kop->crk_iparams + 1].crp_nbits = slen * 8;
        kop->crk_oparams++;
    }

    ret = ioctl(cfd, CIOCKEY, kop);

    if (ret == 0) {
        if (r)
            crparam2bn(&kop->crk_param[kop->crk_iparams], r);
        if (s)
            crparam2bn(&kop->crk_param[kop->crk_iparams + 1], s);
    }

    return ret;
}

static int
cryptodev_bn_mod_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
                     const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *in_mont)
{
    struct crypt_kop kop;
    int ret = 1;

    /*
     * Currently, we know we can do mod exp iff we can do any asymmetric
     * operations at all.
     */
    if (cryptodev_asymfeat == 0) {
        ret = BN_mod_exp(r, a, p, m, ctx);
        return (ret);
    }

    memset(&kop, 0, sizeof(kop));
    kop.crk_op = CRK_MOD_EXP;

    /* inputs: a^p % m */
    if (bn2crparam(a, &kop.crk_param[0]))
        goto err;
    if (bn2crparam(p, &kop.crk_param[1]))
        goto err;
    if (bn2crparam(m, &kop.crk_param[2]))
        goto err;
    kop.crk_iparams = 3;

    if (cryptodev_asym(&kop, BN_num_bytes(m), r, 0, NULL)) {
        const RSA_METHOD *meth = RSA_PKCS1_OpenSSL();
        // asym process failed, Running in software
        ret = RSA_meth_get_bn_mod_exp(meth)(r, a, p, m, ctx, in_mont);

    }
    /* else cryptodev operation worked ok ==> ret = 1 */

 err:
    zapparams(&kop);
    return (ret);
}

static char cryptodev_ecdsa_supported_curve(int curve_NID, char *curv_id)
{
    switch(curve_NID) {
    case NID_X9_62_prime192v1:
        *curv_id = CRYPTO_ECC_CURVE_NIST_P192;
        return 24;
    case NID_secp224r1:
        *curv_id = CRYPTO_ECC_CURVE_NIST_P224;
        return 28;
    case NID_X9_62_prime256v1:
        *curv_id = CRYPTO_ECC_CURVE_NIST_P256;
        return 32;
    case NID_secp384r1:
        *curv_id = CRYPTO_ECC_CURVE_NIST_P384;
        return 48;
    default:
        return 0;
    }
}

static ECDSA_SIG *
cryptodev_ecdsa_sign_sig(const unsigned char *dgst, int dgst_len, 
                         const BIGNUM *in_kinv, const BIGNUM *in_r, 
                         EC_KEY *eckey)
{
    struct crypt_kop kop;
    ECDSA_SIG *ret;
    BIGNUM *r, *s;
    const EC_GROUP *group;
    const BIGNUM *priv_key;
    char curv_id;
    int n_len;

    group = EC_KEY_get0_group(eckey);
    priv_key = EC_KEY_get0_private_key(eckey);
    if (group == NULL || priv_key == NULL) {
        return NULL;
    }

    ret = ECDSA_SIG_new();
    if (ret == NULL) {
        return NULL;
    }

    r = BN_new();
    s = BN_new();
    if (r == NULL || s == NULL) {
        goto err;
    }

    n_len = cryptodev_ecdsa_supported_curve(EC_GROUP_get_curve_name(group), &curv_id);

    if (!n_len){
        fprintf(stderr, "curve id not supported by devcrypto\n");
        goto err;
    }

    memset(&kop, 0, sizeof(kop));
    kop.crk_op = CRK_ECDSA_SIGN;

    if (bin2crparam((const unsigned char*) &curv_id, 1, &kop.crk_param[0]))
        goto err;
    if (bin2crparam(dgst, dgst_len, &kop.crk_param[1]))
        goto err;
    if (bn2crparam(priv_key, &kop.crk_param[2]))
        goto err;
    kop.crk_iparams = 3;

    if (cryptodev_asym(&kop, n_len, r, n_len, s)) {
        goto err;
    }

    ECDSA_SIG_set0(ret, r, s);

    return ret;
err:
    BN_clear_free(r);
    BN_clear_free(s);

    printf("HW err, using SW");

    return sign_sig(dgst, dgst_len, in_kinv, in_r, eckey);
}

int cryptodev_ecdsa_verify_sig(const unsigned char *dgst, int dgst_len,
                               const ECDSA_SIG *sig, EC_KEY *eckey)
{
    struct crypt_kop kop;
    BN_CTX *ctx = NULL;
    BIGNUM *x, *y;
    const BIGNUM *r = NULL;
    const BIGNUM *s = NULL;
    const EC_GROUP *group;
    const EC_POINT *public_key;
    char curv_id;
    int ret;
    // size_t ec_key_len;


    group = EC_KEY_get0_group(eckey);
    public_key = EC_KEY_get0_public_key(eckey);
    if (group == NULL || public_key == NULL) {
        return -1;
    }
    // ec_key_len = (EC_GROUP_order_bits(group) + 7) / 8;

    if ((ctx = BN_CTX_new()) == NULL) {
        return -1;
    }

    x = BN_new();
    y = BN_new();
    if (x == NULL || y == NULL) {
        goto err;
    }

    ECDSA_SIG_get0(sig, &r, &s);

    if (!cryptodev_ecdsa_supported_curve(EC_GROUP_get_curve_name(group), &curv_id)) {
        fprintf(stderr, "curve id not supported by devcrypto\n");
        goto err;
    }

    if (!EC_POINT_get_affine_coordinates(group, public_key, x, y, ctx)) {
        return -1;
    }

    memset(&kop, 0, sizeof(kop));
    kop.crk_op = CRK_ECDSA_VERIFY;

    if (bin2crparam((const unsigned char *)&curv_id, 1, &kop.crk_param[0]))
        goto err;
    if (bin2crparam(dgst, dgst_len, &kop.crk_param[1]))
        goto err;
    if (bn2crparam(r, &kop.crk_param[2]))
        goto err;
    if (bn2crparam(s, &kop.crk_param[3]))
        goto err;
    if (bn2crparam(x, &kop.crk_param[4]))
        goto err;
    if (bn2crparam(y, &kop.crk_param[5]))
        goto err;
    kop.crk_iparams = 6;


    ret = cryptodev_asym(&kop, 0, NULL, 0, NULL);
    if (ret == -EBADMSG) {
        return 0;
    } else if (ret == 0) {
        return 1;
    }

err:
    printf("HW err, using SW");
    return verify_sig(dgst, dgst_len, sig, eckey);
}

static void prepare_asym_cipher_methods(void)
{
    if ((devcrypto_rsa = RSA_meth_dup(RSA_PKCS1_OpenSSL())) == NULL
        || !RSA_meth_set1_name(devcrypto_rsa, "cryptodev RSA method")
        || !RSA_meth_set_flags(devcrypto_rsa, 0)
        ) {
        RSA_meth_free(devcrypto_rsa);
        devcrypto_rsa = NULL;
        return;
    } else {
        if (cryptodev_asymfeat & CRF_MOD_EXP) {
            RSA_meth_set_bn_mod_exp(devcrypto_rsa, cryptodev_bn_mod_exp);
        }
    }

    if ((devcrypto_ec = EC_KEY_METHOD_new(EC_KEY_OpenSSL())) == NULL)
    {
        EC_KEY_METHOD_free(devcrypto_ec);
        devcrypto_ec = NULL;
        return;
    } else {
        if (cryptodev_asymfeat & CRF_ECDSA_SIGN) {
            EC_KEY_METHOD_get_sign(devcrypto_ec, &sign, &sign_setup, &sign_sig);
            EC_KEY_METHOD_set_sign(devcrypto_ec, sign, sign_setup, cryptodev_ecdsa_sign_sig);
        }
        if (cryptodev_asymfeat & CRF_ECDSA_VERIFY) {
            EC_KEY_METHOD_get_verify(devcrypto_ec, &verify, &verify_sig);
            EC_KEY_METHOD_set_verify(devcrypto_ec, verify, cryptodev_ecdsa_verify_sig);
        }

    }

}

static void destroy_all_asym_cipher_methods(void)
{
    RSA_meth_free(devcrypto_rsa);
    devcrypto_rsa = NULL;
}

/******************************************************************************
 *
 * LOAD / UNLOAD
 *
 *****/

static int devcrypto_unload(ENGINE *e)
{
    destroy_all_cipher_methods();
#ifdef IMPLEMENT_DIGEST
    destroy_all_digest_methods();
#endif
    destroy_all_asym_cipher_methods();

    close(cfd);

    return 1;
}
/*
 * This engine is always built into libcrypto, so it doesn't offer any
 * ability to be dynamically loadable.
 */
void engine_load_devcrypto_int()
{
    ENGINE *e = NULL;

    if ((cfd = open("/dev/crypto", O_RDWR, 0)) < 0) {
#ifndef ENGINE_DEVCRYPTO_DEBUG
        if (errno != ENOENT)
#endif
            fprintf(stderr, "Could not open /dev/crypto: %s\n", strerror(errno));
        return;
    }

    if ((e = ENGINE_new()) == NULL
        || !ENGINE_set_destroy_function(e, devcrypto_unload)) {
        ENGINE_free(e);
        /*
         * We know that devcrypto_unload() won't be called when one of the
         * above two calls have failed, so we close cfd explicitly here to
         * avoid leaking resources.
         */
        close(cfd);
        return;
    }

    /*
     * find out what asymmetric crypto algorithms we support
     */
    if (ioctl(cfd, CIOCASYMFEAT, &cryptodev_asymfeat) == -1) {
        ENGINE_free(e);
        return;
    }

    prepare_cipher_methods();
#ifdef IMPLEMENT_DIGEST
    prepare_digest_methods();
#endif
    prepare_asym_cipher_methods();

    if (!ENGINE_set_id(e, "devcrypto")
        || !ENGINE_set_name(e, "/dev/crypto engine")
        || !ENGINE_set_RSA(e, devcrypto_rsa)
        || !ENGINE_set_EC(e, devcrypto_ec)
        || !ENGINE_set_ciphers(e, devcrypto_ciphers)
#ifdef IMPLEMENT_DIGEST
        || !ENGINE_set_digests(e, devcrypto_digests)
#endif
        ) {
        ENGINE_free(e);
        return;
    }

    ENGINE_add(e);
    ENGINE_free(e);          /* Loose our local reference */
    ERR_clear_error();
}
