from libc.stdlib cimport malloc, free


cdef extern from "openssl/ec.h" nogil:
    ctypedef struct EC_builtin_curve:
        int nid
        const char *comment

    size_t EC_get_builtin_curves(EC_builtin_curve *r, size_t nitems)

    # pre-defined NIST curves
    int NID_sect163r2, NID_sect233r1, NID_sect283r1, NID_sect409r1, NID_sect571r1
    int NID_sect163k1, NID_sect233k1, NID_sect283k1, NID_sect409k1, NID_sect571k1
    int NID_X9_62_prime192v1, NID_secp224r1, NID_X9_62_prime256v1, NID_secp384r1
    int NID_secp521r1

from  evp_h cimport *

'''
cdef class EC_PublicKey:
    cdef EVP_PKEY* pkey

    def __cinit__(self, curve, keybytes):


        EC_POINT_oct2point()


cdef class EC_KeyPair:
    cdef EVP_PKEY *pkey

    def __cinit__(self, curve, key):
        pass
'''


cdef class EllipticCurve:
    cdef int nid


cdef class PublicKey:
    cdef EVP_PKEY *key


def ecdh(PublicKey pubkey, EllipticCurve curve):
    cdef:
        EVP_PKEY_CTX *ctx = NULL
        EVP_PKEY *pkey = NULL
        EVP_PKEY *peerkey = NULL
        size_t secret_len

    try:
        pkey = ec_keypair_generate(curve)
        ctx = EVP_PKEY_CTX_new(pkey, NULL)
        assert ctx != NULL
        assert EVP_PKEY_derive_init(ctx) == 1
        assert EVP_PKEY_derive_set_peer(ctx, pubkey.key) == 1
        assert EVP_PKEY_derive(ctx, NULL, &secret_len) == 1
        secret = bytearray(secret_len)
        assert EVP_PKEY_derive(ctx, secret, &secret_len) == 1
    finally:
        if ctx:
            EVP_PKEY_CTX_free(ctx)
        if peerkey:
            EVP_PKEY_free(peerkey)
        if pkey:
            EVP_PKEY_free(pkey)
    return secret


cdef EVP_PKEY* ec_keypair_generate(EllipticCurve curve) except NULL:
    cdef:
        EVP_PKEY_CTX *pctx = NULL
        EVP_PKEY_CTX *kctx = NULL
        EVP_PKEY *params = NULL
        EVP_PKEY *pkey = NULL

    try:
        pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL)
        assert pctx != NULL
        assert EVP_PKEY_paramgen_init(pctx) == 1
        assert EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, curve.nid) == 1
        assert EVP_PKEY_paramgen(pctx, &params) != 0
        kctx = EVP_PKEY_CTX_new(params, NULL)
        assert kctx != NULL
        assert EVP_PKEY_keygen_init(kctx) == 1
        assert EVP_PKEY_keygen(kctx, &pkey) == 1
        assert pkey != NULL
    finally:
        if kctx:
            EVP_PKEY_CTX_free(kctx)
        if params:
            EVP_PKEY_free(params)
        if pctx:
            EVP_PKEY_CTX_free(pctx)
    return pkey



CURVES_BY_NAME = {
    "B-163": NID_sect163r2,
    "B-233": NID_sect233r1,
    "B-283": NID_sect283r1,
    "B-409": NID_sect409r1,
    "B-571": NID_sect571r1,
    "K-163": NID_sect163k1,
    "K-233": NID_sect233k1,
    "K-283": NID_sect283k1,
    "K-409": NID_sect409k1,
    "K-571": NID_sect571k1,
    "P-192": NID_X9_62_prime192v1,
    "P-224": NID_secp224r1,
    "P-256": NID_X9_62_prime256v1,
    "P-384": NID_secp384r1,
    "P-521": NID_secp521r1}

CURVES_BY_DESCRIPTION = {}


cdef init_builtin_curves():
    cdef size_t nitems
    cdef EC_builtin_curve *curves

    nitems = EC_get_builtin_curves(NULL, 0)
    curves = <EC_builtin_curve*>malloc(nitems * sizeof(EC_builtin_curve))
    assert curves is not NULL
    EC_get_builtin_curves(curves, nitems)

    for i in range(nitems):
        CURVES_BY_DESCRIPTION[curves[i].comment] = curves[i].nid

    free(curves)


init_builtin_curves()
