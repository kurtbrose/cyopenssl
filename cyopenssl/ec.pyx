from libc.stdlib cimport malloc, free


cdef extern from "openssl/bn.h" nogil:
    ctypedef struct BIGNUM:
        pass

    ctypedef struct BN_CTX:
        pass

    BN_CTX *BN_CTX_new()
    void BN_CTX_free(BN_CTX *ctx)

    int BN_hex2bn(BIGNUM **a, const char *str)


cdef extern from "openssl/ec.h" nogil:
    ctypedef struct EC_KEY:
        pass

    ctypedef struct EC_POINT:
        pass

    ctypedef struct EC_GROUP:
        pass

    ctypedef struct EC_builtin_curve:
        int nid
        const char *comment

    size_t EC_get_builtin_curves(EC_builtin_curve *r, size_t nitems)

    # pre-defined NIST curves
    int NID_sect163r2, NID_sect233r1, NID_sect283r1, NID_sect409r1, NID_sect571r1
    int NID_sect163k1, NID_sect233k1, NID_sect283k1, NID_sect409k1, NID_sect571k1
    int NID_X9_62_prime192v1, NID_secp224r1, NID_X9_62_prime256v1, NID_secp384r1
    int NID_secp521r1

    EC_KEY *EC_KEY_new()

    void EC_KEY_free(EC_KEY *key)

    int EC_KEY_set_private_key(EC_KEY *key, const BIGNUM *prv)
    int EC_KEY_set_public_key(EC_KEY *key, const EC_POINT *pub)

    EC_POINT *EC_POINT_new(const EC_GROUP *group)

    int EC_POINT_oct2point(const EC_GROUP *group, EC_POINT *p,
                        const unsigned char *buf, size_t len, BN_CTX *ctx)

    int EC_POINT_mul(const EC_GROUP *group, EC_POINT *r, const BIGNUM *n, 
        const EC_POINT *q, const BIGNUM *m, BN_CTX *ctx)

    EC_GROUP *EC_GROUP_new_by_curve_name(int nid)



from  evp_h cimport *


cdef BN_CTX *GLOBAL_BN_CTX = BN_CTX_new()
if GLOBAL_BN_CTX is NULL:
    raise MemoryError()  # could not allocate BN_CTX


cdef class EllipticCurve:
    cdef int nid
    cdef char *name
    cdef char *description
    cdef EC_GROUP *ec_group

    def __cinit__(self, nid, name, description):
        self.nid = nid
        self.name = name
        self.description = description
        self.ec_group = EC_GROUP_new_by_curve_name(nid)
        if self.ec_group is NULL:
            raise ValueError("nid {0} is not a known elliptic curve".format(nid))

    def get_description(self):
        return self.description

    def __repr__(self):
        return "<EllipticCurve {0}>".format(self.name)


cdef EVP_PKEY *ec2evp_pkey(EC_POINT *pub_point, BIGNUM *priv_n) except NULL:
    '''
    Wraps an EC_POINT into an EVP_PKEY structure with that point
    as the public key; the EVP_PKEY assumes ownership of the EC_POINT
    (optionally can also set private key)
    '''
    cdef:
        EC_KEY *ec_key
        EVP_PKEY *evp_pkey

    ec_key = EC_KEY_new()
    if ec_key is NULL:
        raise MemoryError()  # could not allocate EC_KEY
    EC_KEY_set_public_key(ec_key, pub_point)
    if priv_n is not NULL:
        if EC_KEY_set_private_key(ec_key, priv_n) == 0:
            raise ValueError("EC_KEY_set_private_key() error")
    evp_pkey = EVP_PKEY_new()
    if evp_pkey is NULL:
        EC_KEY_free(ec_key)
        raise MemoryError()  # could not allocate EVP_PKEY
    EVP_PKEY_assign_EC_KEY(evp_pkey, ec_key)
    return evp_pkey


cdef class PublicKey:
    cdef EVP_PKEY *key

    def __cinit__(self, bytes sec_point, EllipticCurve curve):
        'creates an openssl EC public key from sec serialized point'
        cdef:
            EC_GROUP *ec_group
            EC_POINT *pub_point

        pub_point = EC_POINT_new(curve.ec_group)
        if pub_point is NULL:
            raise MemoryError()  # could not allocate EC_POINT
        if EC_POINT_oct2point(
                curve.ec_group, pub_point, sec_point, len(sec_point), GLOBAL_BN_CTX) != 1:
            raise ValueError("unable to parse EC_POINT")  # TODO: parse openssl error
        self.key = ec2evp_pkey(pub_point, NULL)

    def __dealloc__(self):
        if self.key is not NULL:
            EVP_PKEY_free(self.key)


cdef class KeyPair:
    cdef EVP_PKEY *keypair

    def __dealloc__(self):
        if self.keypair is not NULL:
            EVP_PKEY_free(self.keypair)


def int2keypair(n, EllipticCurve curve):
    cdef:
        BIGNUM *priv_n
        EC_POINT *pub_point
        EVP_PKEY *keypair

    priv_n = NULL
    pub_point = NULL

    buf = "{0:X}".format(n)
    assert BN_hex2bn(&priv_n, buf) == len(buf)

    pubpoint = EC_POINT_new(curve.ec_group)
    if pubpoint is NULL:
        raise MemoryError()  # could not allocate EC_POINT

    assert EC_POINT_mul(curve.ec_group, pub_point, priv_n, NULL, NULL, GLOBAL_BN_CTX) == 1
    keypair = ec2evp_pkey(pub_point, priv_n)
    
    ret = KeyPair()
    ret.keypair = keypair
    return ret


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


CURVES = {}


cdef init_builtin_curves():
    cdef size_t nitems
    cdef EC_builtin_curve *curves

    nitems = EC_get_builtin_curves(NULL, 0)
    curves = <EC_builtin_curve*>malloc(nitems * sizeof(EC_builtin_curve))
    assert curves is not NULL

    nid2desc = {}
    EC_get_builtin_curves(curves, nitems)

    for i in range(nitems):
        nid2desc[curves[i].nid] = curves[i].comment

    free(curves)

    curves_by_name = {
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

    for name, nid in curves_by_name.items():
        CURVES[name] = EllipticCurve(nid, name, nid2desc[nid])


init_builtin_curves()
