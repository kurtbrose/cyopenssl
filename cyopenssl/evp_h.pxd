cdef extern from "openssl/ec.h" nogil:
    ctypedef struct EC_KEY:
        pass


cdef extern from "openssl/rsa.h" nogil:
    ctypedef struct RSA:
        pass


cdef extern from "openssl/evp.h" nogil:
    void OpenSSL_add_all_algorithms()

    ctypedef struct EVP_CIPHER_CTX:
        pass

    ctypedef struct EVP_CIPHER:
        pass

    ctypedef struct EVP_PKEY_CTX:
        pass

    ctypedef struct EVP_PKEY:
        pass

    ctypedef struct ENGINE:
        pass

    EVP_CIPHER_CTX* EVP_CIPHER_CTX_new()
    void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX*)

    int EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
        ENGINE *impl, unsigned char *key, unsigned char *iv)

    int EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
        ENGINE *impl, unsigned char *key, unsigned char *iv)

    int EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
         int *outl, unsigned char *inp, int inl)

    int EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
         int *outl, unsigned char *inp, int inl)

    int EVP_EncryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl)

    int EVP_DecryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl)

    EVP_PKEY_CTX* EVP_PKEY_CTX_new_id(int id, ENGINE *engine)
    EVP_PKEY_CTX* EVP_PKEY_CTX_new(EVP_PKEY *pkey, ENGINE *e)
    void EVP_PKEY_CTX_free(EVP_PKEY_CTX *ctx)
    int EVP_PKEY_CTX_set_ec_paramgen_curve_nid(EVP_PKEY_CTX *ctx, int nid)

    int EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr)

    int EVP_PKEY_derive_init(EVP_PKEY_CTX *ctx)
    int EVP_PKEY_derive(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen)
    int EVP_PKEY_derive_set_peer(EVP_PKEY_CTX *ctx, EVP_PKEY *peer)
    int EVP_PKEY_keygen_init(EVP_PKEY_CTX *ctx)
    int EVP_PKEY_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY **ppkey)
    int EVP_PKEY_paramgen_init(EVP_PKEY_CTX *ctx)
    int EVP_PKEY_paramgen(EVP_PKEY_CTX *ctx, EVP_PKEY **ppkey)

    int EVP_PKEY_assign_EC_KEY(EVP_PKEY *pkey,EC_KEY *key)
    EC_KEY *EVP_PKEY_get1_EC_KEY(EVP_PKEY *pkey)

    RSA *EVP_PKEY_get1_RSA(EVP_PKEY *pkey)

    EVP_PKEY *EVP_PKEY_new()

    void EVP_PKEY_free(EVP_PKEY *key)

    const EVP_CIPHER* EVP_aes_128_gcm()
    const EVP_CIPHER* EVP_aes_192_gcm()
    const EVP_CIPHER* EVP_aes_256_gcm()
    const EVP_CIPHER* EVP_des_ede3_cbc()

    EVP_PKEY *d2i_AutoPrivateKey(EVP_PKEY **a, const unsigned char **pp, long length)

    # #define constants
    int EVP_CTRL_GCM_SET_IVLEN
    int EVP_CTRL_GCM_GET_TAG
    int EVP_CTRL_GCM_SET_TAG
    int EVP_PKEY_EC
