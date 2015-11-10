

cdef extern from "openssl/evp.h":
    ctypedef struct EVP_CIPHER_CTX:
        pass

    ctypedef struct EVP_CIPHER:
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

    int EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr)

    const EVP_CIPHER* EVP_aes_128_gcm()
    const EVP_CIPHER* EVP_aes_192_gcm()
    const EVP_CIPHER* EVP_aes_256_gcm()

    # #define constants
    int EVP_CTRL_GCM_SET_IVLEN
    int EVP_CTRL_GCM_GET_TAG
    int EVP_CTRL_GCM_SET_TAG

    EVP_PKEY


cdef extern from "openssl/bio.h":
    ctypedef struct BIO:
        pass


cdef extern from "openssl/x509.h":
    ctypedef struct X509:
        pass

    ctypedef struct X509_STORE:
        pass

    X509 *d2i_X509(X509 **px, const unsigned char **in, int len)
    int i2d_X509(X509 *x, unsigned char **out)

    X509_STORE *X509_STORE_new()
    void X509_STORE_free(X509_STORE *x509_store)
    int X509_STORE_add_cert(X509_STORE *x509_store, X509 *cert)


cdef extern from "openssl/x509_vfy.h":
    ctypedef struct X509_STORE_CTX:
        pass


cdef extern from "openssl/ssl.h":
    int SSL_library_init()
    void SSL_load_error_strings()

    ctypedef struct SSL:
        pass

    ctypedef struct SSL_CTX:
        pass

    ctypedef struct SSL_SESSION:
        pass

    ctypedef struct SSL_CIPHER:
        pass

    ctypedef struct SSL_METHOD:
        pass

    # STACKs are used via STACK_OF() macro
    ctypedef struct STACK:
        pass

    SSL *SSL_new(SSL_CTX *ctx)
    void SSL_free(SSL *ssl)
    int SSL_get_error(const SSL *ssl, int ret)
    int SSL_write(SSL *ssl, const void *buf, int num)
    int SSL_read(SSL *ssl, void *buf, int num)
    int SSL_pending(const SSL *ssl)
    int SSL_set_fd(SSL *ssl, int fd)
    int SSL_set_session(SSL *ssl, SSL_SESSION *session)
    BIO *SSL_get_rbio(SSL *ssl)
    BIO *SSL_get_wbio(SSL *ssl)
    long SSL_get_verify_result(const SSL *ssl)
    X509 *SSL_get_peer_certificate(const SSL *ssl)
    SSL_CIPHER *SSL_get_current_cipher(const SSL *ssl)
    STACK *SSL_load_client_CA_file(char *file)
    int SSL_set_cipher_list(SSL *ssl, char *str)
    long SSL_ctrl(SSL *ssl, int cmd, long larg, char *parg)

    SSL_CTX *SSL_CTX_new(const SSL_METHOD *method)
    int SSL_CTX_set_session_id_context(SSL_CTX *ctx,
        const unsigned char *sid_ctx, unsigned int sid_ctx_len)
    int SSL_CTX_use_certificate(SSL_CTX *ctx, X509 *x)
    int SSL_CTX_use_certificate_chain_file(SSL_CTX *ctx, const char *file)
    void SSL_CTX_set_verify(SSL_CTX *ctx, int mode,
        int (*verify_callback)(int, X509_STORE_CTX *))
    void SSL_CTX_set_cert_store(SSL_CTX *ctx, X509_STORE *store)
    X509_STORE *SSL_CTX_get_cert_store(const SSL_CTX *ctx)
    int SSL_CTX_use_PrivateKey(SSL_CTX *ctx, EVP_PKEY *pkey)
    int SSL_CTX_use_PrivateKey_file(SSL_CTX *ctx, char *file, int type)
    ctypedef int pem_passwd_cb(char *buf, int size, int rwflag, void *userdata)
    void SSL_CTX_set_default_passwd_cb(SSL_CTX *ctx, pem_passwd_cb)
    STACK *SSL_CTX_get_client_CA_list(const SSL_CTX *ctx)
    void SSL_CTX_set_client_CA_list(SSL_CTX *ctx, STACK *list)
    int SSL_CTX_add_client_CA(SSL_CTX *ctx, X509 *x)
    int SSL_CTX_set_cipher_list(SSL_CTX *ctx, char *str)
    int SSL_CTX_add_session(SSL_CTX *ctx, SSL_SESSION *c)
    int SSL_CTX_load_verify_locations(SSL_CTX *ctx, char *CAfile, char *CApath)
    long SSL_CTX_ctrl(SSL_CTX *ctx, int cmd, long larg, char *parg)

    const char *SSL_CIPHER_get_name(SSL_CIPHER *cipher)
    char *SSL_CIPHER_get_version(SSL_CIPHER *cipher)
    char *SSL_CIPHER_description(SSL_CIPHER *cipher, char *buf, int len)
    int SSL_CIPHER_get_bits(SSL_CIPHER *cipher, int *alg_bits)

    const SSL_METHOD *TLSv1_method(void)

    SSL_SESSION *d2i_SSL_SESSION(SSL_SESSION **a, const unsigned char **pp, long length)


from cpython.mem cimport PyMem_Malloc, PyMem_Free


def aes_gcm_encrypt(bytes plaintext, bytes key, bytes iv, bytes authdata=None, int tagsize=16):
    cdef:
        EVP_CIPHER_CTX *ctx = NULL
        unsigned char *outbuf = NULL
        int outlen
        int tmplen
        char tagbuf[16]
    try:
        ctx = EVP_CIPHER_CTX_new()
        outbuf = <unsigned char*>PyMem_Malloc(len(plaintext))
        if outbuf == NULL:
            raise MemoryError()
        EVP_EncryptInit_ex(ctx, get_aes_gcm_cipher(len(key)), NULL, NULL, NULL)
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, len(iv), NULL)
        EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)
        if authdata is not None:
            EVP_EncryptUpdate(ctx, None, &outlen, authdata, len(authdata))
        EVP_EncryptUpdate(ctx, outbuf, &outlen, plaintext, len(plaintext))
        EVP_EncryptFinal_ex(ctx, outbuf + outlen, &tmplen)
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tagsize, tagbuf)
        return bytes(outbuf[:outlen]), bytes(tagbuf[:tagsize])
    finally:
        if ctx:
            EVP_CIPHER_CTX_free(ctx)
        if outbuf:
            PyMem_Free(outbuf)


def aes_gcm_decrypt(bytes ciphertext, bytes key, bytes iv, bytes tag, bytes authdata=None):
    cdef:
        EVP_CIPHER_CTX *ctx = NULL
        unsigned char *outbuf = NULL
        int outlen
        int tmplen
        int authenticated
    try:
        ctx = EVP_CIPHER_CTX_new()
        outbuf = <unsigned char*>PyMem_Malloc(len(ciphertext))
        if outbuf == NULL:
            raise MemoryError()
        EVP_DecryptInit_ex(ctx, get_aes_gcm_cipher(len(key)), NULL, NULL, NULL)  # set CIPHER
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, len(iv), NULL)  # set IV-len
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, len(tag), <char*>tag)  # set TAG
        EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)  # set IV
        if authdata:
            EVP_DecryptUpdate(ctx, NULL, &outlen, authdata, len(authdata))
        EVP_DecryptUpdate(ctx, outbuf, &outlen, ciphertext, len(ciphertext))
        authenticated = EVP_DecryptFinal_ex(ctx, outbuf + outlen, &tmplen)
        if not authenticated:
            raise ValueError("message authentication failed (tag does not match)"
                " decrypt {0} bytes of data".format(int(outlen)))
        return bytes(outbuf[:outlen])
    finally:
        if ctx:
            EVP_CIPHER_CTX_free(ctx)
        if outbuf:
            PyMem_Free(outbuf)


cdef const EVP_CIPHER* get_aes_gcm_cipher(int keylen):
    if keylen == 128 / 8:
        return EVP_aes_128_gcm()
    elif keylen == 192 / 8:
        return EVP_aes_192_gcm()
    elif keylen == 256 / 8:
        return EVP_aes_256_gcm()


cdef _library_init():
    SSL_load_error_strings()
    SSL_library_init()


_library_init()


def test():
    import timeit
    dur = timeit.timeit(lambda: aes_gcm_encrypt('abc', 'a' * 16, 'a' * 12), number=1000)
    print dur * 1000, "us per aes gcm encrypt"

    plaintext = "hello world!"
    ciphertext, tag = aes_gcm_encrypt(plaintext, 'a' * 16, 'a' * 12)
    assert plaintext == aes_gcm_decrypt(ciphertext, 'a' * 16, 'a' * 12, tag)

    dur2 = timeit.timeit(lambda: aes_gcm_decrypt(ciphertext, 'a' * 16, 'a' * 12, tag), number=1000)
    print dur2 * 1000, "us per aes gcm decrypt"

