cdef extern from "openssl/ssl.h" nogil:
    int SSL_library_init()
    void SSL_load_error_strings()

    ctypedef struct SSL:
        pass

    ctypedef struct SSL_CTX:
        pass

    ctypedef struct SSL_SESSION:
        int references

    ctypedef struct SSL_CIPHER:
        pass

    ctypedef struct SSL_METHOD:
        pass

    SSL *SSL_new(SSL_CTX *ctx)
    void SSL_free(SSL *ssl)
    int SSL_get_error(const SSL *ssl, int ret)
    int SSL_write(SSL *ssl, const void *buf, int num)
    int SSL_read(SSL *ssl, void *buf, int num)
    int SSL_do_handshake(SSL *ssl)
    int SSL_shutdown(SSL *ssl)
    int SSL_get_shutdown(const SSL *ssl)
    int SSL_pending(const SSL *ssl)
    int SSL_set_fd(SSL *ssl, int fd)
    int SSL_set_session(SSL *ssl, SSL_SESSION *session)
    SSL_SESSION *SSL_get_session(SSL *ssl)
    void SSL_set_connect_state(SSL *ssl)
    void SSL_set_accept_state(SSL *ssl)
    BIO *SSL_get_rbio(SSL *ssl)
    BIO *SSL_get_wbio(SSL *ssl)
    void SSL_set_bio(SSL *ssl, BIO *rbio, BIO *wbio)
    long SSL_get_verify_result(const SSL *ssl)
    X509 *SSL_get_peer_certificate(const SSL *ssl)
    SSL_CIPHER *SSL_get_current_cipher(const SSL *ssl)
    stack_st_X509_NAME *SSL_load_client_CA_file(char *file)
    int SSL_set_cipher_list(SSL *ssl, char *str)
    long SSL_ctrl(SSL *ssl, int cmd, long larg, char *parg)
    const char *SSL_state_string(const SSL *ssl)
    const char *SSL_state_string_long(const SSL *ssl)
    long SSL_set_mode(SSL *ssl, long mode)
    long SSL_get_mode(SSL *ssl)
    long SSL_session_reused(SSL *ssl)

    void SSL_set_info_callback(SSL *ssl, void (*callback)(SSL*, int, int))

    const char *SSL_alert_type_string(int value)
    const char *SSL_alert_type_string_long(int value)

    const char *SSL_alert_desc_string(int value)
    const char *SSL_alert_desc_string_long(int value)

    SSL_CTX *SSL_CTX_new(const SSL_METHOD *method)
    void SSL_CTX_free(SSL_CTX *ctx)
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
    stack_st_X509_NAME *SSL_CTX_get_client_CA_list(const SSL_CTX *ctx)
    void SSL_CTX_set_client_CA_list(SSL_CTX *ctx, stack_st_X509_NAME *list)
    int SSL_CTX_add_client_CA(SSL_CTX *ctx, X509 *x)
    int SSL_CTX_set_cipher_list(SSL_CTX *ctx, char *str)
    int SSL_CTX_add_session(SSL_CTX *ctx, SSL_SESSION *c)
    int SSL_CTX_load_verify_locations(SSL_CTX *ctx, char *CAfile, char *CApath)
    long SSL_CTX_ctrl(SSL_CTX *ctx, int cmd, long larg, char *parg)
    long SSL_CTX_set_session_cache_mode(SSL_CTX *ctx, long mode)
    long SSL_CTX_get_session_cache_mode(SSL_CTX *ctx)
    long SSL_CTX_set_options(SSL_CTX *ctx, long options)
    long SSL_CTX_get_options(SSL_CTX *ctx)
    long SSL_CTX_add_extra_chain_cert(SSL_CTX *ctx, X509 *x509)
    int SSL_CTX_check_private_key(const SSL_CTX *ctx)

    void SSL_CTX_set_default_passwd_cb(SSL_CTX *ctx, pem_password_cb *cb)
    void SSL_CTX_set_default_passwd_cb_userdata(SSL_CTX *ctx, void *u)

    const char *SSL_CIPHER_get_name(SSL_CIPHER *cipher)
    char *SSL_CIPHER_get_version(SSL_CIPHER *cipher)
    char *SSL_CIPHER_description(SSL_CIPHER *cipher, char *buf, int len)
    int SSL_CIPHER_get_bits(SSL_CIPHER *cipher, int *alg_bits)

    const SSL_METHOD *TLSv1_method()
    const SSL_METHOD *TLSv1_1_method()
    const SSL_METHOD *SSLv23_method()

    SSL_SESSION *d2i_SSL_SESSION(SSL_SESSION **a, const unsigned char **pp, long length)
    int i2d_SSL_SESSION(SSL_SESSION *in_, unsigned char **pp)
    void SSL_SESSION_free(SSL_SESSION* sess)

    # set_verify parameters
    int SSL_VERIFY_NONE, SSL_VERIFY_PEER, SSL_VERIFY_FAIL_IF_NO_PEER_CERT
    int SSL_VERIFY_CLIENT_ONCE

    # SSL error codes
    int SSL_ERROR_NONE, SSL_ERROR_SSL, SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE
    int SSL_ERROR_ZERO_RETURN, SSL_ERROR_SYSCALL, SSL_ERROR_WANT_CONNECT
    int SSL_ERROR_WANT_X509_LOOKUP, SSL_ERROR_WANT_ACCEPT

    int SSL_FILETYPE_PEM, SSL_FILETYPE_ASN1

    # session cache options
    long SSL_SESS_CACHE_OFF, SSL_SESS_CACHE_CLIENT, SSL_SESS_CACHE_SERVER
    long SSL_SESS_CACHE_BOTH, SSL_SESS_CACHE_NO_AUTO_CLEAR, SSL_SESS_CACHE_NO_INTERNAL_LOOKUP
    long SSL_SESS_CACHE_NO_INTERNAL_STORE, SSL_SESS_CACHE_NO_INTERNAL

    # SSL mode flags
    long SSL_MODE_ENABLE_PARTIAL_WRITE, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER
    long SSL_MODE_AUTO_RETRY, SSL_MODE_RELEASE_BUFFERS
    long SSL_MODE_RELEASE_BUFFERS, SSL_MODE_SEND_FALLBACK_SCSV

    # SSL callback flags
    int SSL_CB_LOOP, SSL_CB_EXIT, SSL_CB_READ, SSL_CB_WRITE, SSL_CB_ALERT

    # SSL states
    int SSL_ST_MASK, SSL_ST_CONNECT, SSL_ST_ACCEPT

    # SSL shutdown states
    int SSL_SENT_SHUTDOWN, SSL_RECEIVED_SHUTDOWN

    # version flags
    long SSL_OP_NO_SSLv2, SSL_OP_NO_SSLv3
    long SSL_OP_NO_TICKET
