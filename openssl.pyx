from libc cimport string


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

    void EVP_PKEY_free(EVP_PKEY *key)

    #const EVP_CIPHER* EVP_aes_128_gcm()
    #const EVP_CIPHER* EVP_aes_192_gcm()
    #const EVP_CIPHER* EVP_aes_256_gcm()

    EVP_PKEY *d2i_AutoPrivateKey(EVP_PKEY **a, const unsigned char **pp, long length)

    # #define constants
    int EVP_CTRL_GCM_SET_IVLEN
    int EVP_CTRL_GCM_GET_TAG
    int EVP_CTRL_GCM_SET_TAG


cdef extern from "openssl/bio.h":
    ctypedef struct BIO:
        pass

    long BIO_set_nbio(BIO *b, long n)


cdef extern from "openssl/x509.h":
    ctypedef struct X509:
        pass

    ctypedef struct X509_STORE:
        pass

    X509 *d2i_X509(X509 **px, const unsigned char **inp, int len)
    int i2d_X509(X509 *x, unsigned char **out)
    X509 *X509_new()
    void X509_free(X509 *a)

    X509_STORE *X509_STORE_new()
    void X509_STORE_free(X509_STORE *x509_store)
    int X509_STORE_add_cert(X509_STORE *x509_store, X509 *cert)

    struct stack_st_X509_NAME:
        pass


cdef extern from "openssl/x509_vfy.h":
    ctypedef struct X509_STORE_CTX:
        pass


cdef extern from "openssl/pem.h":
    ctypedef int pem_password_cb(char *buf, int size, int rwflag, void *userdata)
    EVP_PKEY *PEM_read_bio_PrivateKey(
        BIO *bp, EVP_PKEY **x, pem_password_cb *cb, void *u)


cdef extern from "openssl/bio.h":
    ctypedef struct BIO:
        pass

    BIO *BIO_new_mem_buf(void *buf, int len)
    int BIO_free(BIO *a)


cdef extern from "openssl/ssl.h" nogil:
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

    SSL *SSL_new(SSL_CTX *ctx)
    void SSL_free(SSL *ssl)
    int SSL_get_error(const SSL *ssl, int ret)
    int SSL_write(SSL *ssl, const void *buf, int num)
    int SSL_read(SSL *ssl, void *buf, int num)
    int SSL_do_handshake(SSL *ssl)
    int SSL_pending(const SSL *ssl)
    int SSL_set_fd(SSL *ssl, int fd)
    int SSL_set_session(SSL *ssl, SSL_SESSION *session)
    void SSL_set_connect_state(SSL *ssl)
    void SSL_set_accept_state(SSL *ssl)
    BIO *SSL_get_rbio(SSL *ssl)
    BIO *SSL_get_wbio(SSL *ssl)
    long SSL_get_verify_result(const SSL *ssl)
    X509 *SSL_get_peer_certificate(const SSL *ssl)
    SSL_CIPHER *SSL_get_current_cipher(const SSL *ssl)
    stack_st_X509_NAME *SSL_load_client_CA_file(char *file)
    int SSL_set_cipher_list(SSL *ssl, char *str)
    long SSL_ctrl(SSL *ssl, int cmd, long larg, char *parg)

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
    long SSL_CTX_add_extra_chain_cert(SSL_CTX *ctx, X509 *x509)
    int SSL_CTX_check_private_key(const SSL_CTX *ctx)

    void SSL_CTX_set_default_passwd_cb(SSL_CTX *ctx, pem_password_cb *cb)
    void SSL_CTX_set_default_passwd_cb_userdata(SSL_CTX *ctx, void *u)

    const char *SSL_CIPHER_get_name(SSL_CIPHER *cipher)
    char *SSL_CIPHER_get_version(SSL_CIPHER *cipher)
    char *SSL_CIPHER_description(SSL_CIPHER *cipher, char *buf, int len)
    int SSL_CIPHER_get_bits(SSL_CIPHER *cipher, int *alg_bits)

    const SSL_METHOD *TLSv1_method()

    SSL_SESSION *d2i_SSL_SESSION(SSL_SESSION **a, const unsigned char **pp, long length)
    void SSL_SESSION_free(SSL_SESSION* sess)

    # set_verify parameters
    int SSL_VERIFY_NONE
    int SSL_VERIFY_PEER
    int SSL_VERIFY_FAIL_IF_NO_PEER_CERT
    int SSL_VERIFY_CLIENT_ONCE

    # SSL error codes
    int SSL_ERROR_NONE, SSL_ERROR_SSL, SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE
    int SSL_ERROR_ZERO_RETURN, SSL_ERROR_SYSCALL, SSL_ERROR_WANT_CONNECT
    int SSL_ERROR_WANT_X509_LOOKUP, SSL_ERROR_WANT_ACCEPT

    int SSL_FILETYPE_PEM
    int SSL_FILETYPE_ASN1

    # session cache options
    long SSL_SESS_CACHE_OFF
    long SSL_SESS_CACHE_CLIENT
    long SSL_SESS_CACHE_SERVER
    long SSL_SESS_CACHE_BOTH
    long SSL_SESS_CACHE_NO_AUTO_CLEAR
    long SSL_SESS_CACHE_NO_INTERNAL_LOOKUP
    long SSL_SESS_CACHE_NO_INTERNAL_STORE
    long SSL_SESS_CACHE_NO_INTERNAL


cdef extern from "openssl/err.h":
    unsigned long ERR_get_error()
    char *ERR_error_string(unsigned long e, char *buf)
    const char *ERR_lib_error_string(unsigned long e)
    const char *ERR_func_error_string(unsigned long e)
    const char *ERR_reason_error_string(unsigned long e)


from cpython.mem cimport PyMem_Malloc, PyMem_Free
from cpython cimport bool, PyErr_SetExcFromWindowsErr, PyErr_SetFromErrno


cdef class Context:
    cdef:
        SSL_CTX *ctx
        bytes password

    def __cinit__(self, method, bool verify=True, bytes certfile=None, bytes keyfile=None,
                  bytes ca_certs=None, bytes passphrase=None):
        self.ctx = NULL
        if method == "TLSv1":
            self.ctx = SSL_CTX_new(TLSv1_method())
        else:
            raise ValueError("only TLSv1 supported")
        if self.ctx == NULL:
            raise ValueError("SSL context creation failed")
        if not verify:
            SSL_CTX_set_verify(self.ctx, SSL_VERIFY_NONE, NULL)

    def set_session_id(self, bytes id_str):
        if not SSL_CTX_set_session_id_context(self.ctx, id_str, len(id_str)):
            raise ValueError("set_session_id() string too long: " + str(len(id_str)))

    def set_session_cache_mode(self, mode):
        SSL_CTX_set_session_cache_mode(self.ctx, mode)

    def set_options(self, options):
        SSL_CTX_set_options(self.ctx, options)

    def add_session(self, Session session not None):
        SSL_CTX_add_session(self.ctx, session.sess)
        session.sess = NULL

    def set_verify(self, flags, verify_func):
        '''
        flags parameter should be generated by bitwise-oring together of
        SSL_VERIFY_* values.
        verify_func should accept two parameters: an integer, and an X509 object
        pointer.
        See https://www.openssl.org/docs/ssl/SSL_CTX_set_verify.html
        '''
        raise ValueError("IOU set_verify")
        # need to figure out how to create a "dynamic" C callback here
        # ... this is a bit tricky, there is no passed parameter

    def use_certificate_chain_file(self, bytes certfile):
        '''
        Load and use the certificate file at location certfile
        '''
        if not SSL_CTX_use_certificate_chain_file(self.ctx, certfile):
            raise ValueError("error using certificate file " +
                repr(certfile) + "\n" + _pop_and_format_error_list())

    def load_client_CA_list(self, certfile_or_certs):
        '''
        Load the certificate file at location certfile into client CA list,
        or the list of Certificates
        '''
        cdef stack_st_X509_NAME *ca_list_p = NULL

        if isinstance(certfile_or_certs, basestring):
            ca_list_p = SSL_load_client_CA_file(certfile_or_certs)
            if ca_list_p == NULL:
                raise ValueError("error loading certificate file " + 
                    repr(certfile_or_certs) + "\n" + _pop_and_format_error_list)
            SSL_CTX_set_client_CA_list(self.ctx, ca_list_p)
        else:
            for cert in certfile_or_certs:
                if not SSL_CTX_add_client_CA(self.ctx, (<Certificate?>cert).cert):
                    raise ValueError("error loading certificate " +
                        repr(cert) + "\n" + _pop_and_format_error_list())

    def use_certificate(self, Certificate cert not None):
        if not SSL_CTX_use_certificate(self.ctx, cert.cert):
            raise _ssleay_err2value_err() or ValueError("SSL_CTX_use_certificate() error")

    def set_cert_store(self, CertStore cert_store not None):
        SSL_CTX_set_cert_store(self.ctx, cert_store.cert_store)
        cert_store.cert_store = NULL

    def add_extra_chain_cert(self, Certificate cert not None):
        if not SSL_CTX_add_extra_chain_cert(self.ctx, cert.cert):
            raise _ssleay_err2value_err() or ValueError("SSL_CTX_add_extra_chain_cert() failed")

    def use_privatekey(self, PrivateKey private_key not None):
        if not SSL_CTX_use_PrivateKey(self.ctx, private_key.private_key):
            raise _ssleay_err2value_err() or ValueError("SSL_CTX_use_PrivateKey() failed")

    def use_privatekey_file(self, bytes keyfile not None, int filetype=SSL_FILETYPE_PEM):
        if not SSL_CTX_use_PrivateKey_file(self.ctx, keyfile, filetype):
            raise ValueError("error using private key from " + repr(keyfile) +
                _pop_and_format_error_list())

    def set_password(self, bytes password not None):
        self.password = password
        SSL_CTX_set_default_passwd_cb_userdata(self.ctx, <void *>self.password)
        SSL_CTX_set_default_passwd_cb(self.ctx, passwd_cb_passthru)

    def check_privatekey(self):
        if not SSL_CTX_check_private_key(self.ctx):
            raise ValueError("private key and public cert do not match")

    def load_verify_locations(self, bytes pemfile not None):
        if not SSL_CTX_load_verify_locations(self.ctx, pemfile, NULL):
            raise ValueError("error using load_verify_locations(" + repr(pemfile) + ")"
                + _pop_and_format_error_list())

    def set_cipher_list(self, bytes cipher_list not None):
        if not SSL_CTX_set_cipher_list(self.ctx, cipher_list):
            raise ValueError("no usable ciphers in " + repr(cipher_list))

    def __dealloc__(self):
        if self.ctx:
            SSL_CTX_free(self.ctx)


cdef int passwd_cb_passthru(char *buf, int size, int rwflag, void *userdata):
    strdata = <bytes>userdata
    string.strncpy(buf, <char *>strdata, len(strdata))
    return len(strdata)


cdef class Session:
    cdef:
        SSL_SESSION* sess

    def __cinit__(self, data):
        self.sess = NULL
        cdef const unsigned char* data_ptr
        data_ptr = data
        self.sess = d2i_SSL_SESSION(NULL, &data_ptr, len(data))
        if self.sess == NULL:
            raise ValueError("d2i_SSL_SESSION error")

    def __dealloc__(self):
        if self.sess:
            SSL_SESSION_free(self.sess)


cdef class PrivateKey:
    cdef:
        EVP_PKEY *private_key

    def __cinit__(self, data, passphrase=None):
        self.private_key = NULL
        cdef const unsigned char *data_ptr = data
        cdef BIO *data_bio = NULL
        if passphrase is None:
            self.private_key = d2i_AutoPrivateKey(NULL, &data_ptr, len(data))
        else:
            data_bio = BIO_new_mem_buf(data_ptr, len(data))
            self.private_key = PEM_read_bio_PrivateKey(
                data_bio, NULL, NULL, <unsigned char*>passphrase)
            BIO_free(data_bio)
        if self.private_key == NULL:
            raise _ssleay_err2value_err() or ValueError("PrivateKey init error")

    def __dealloc__(self):
        if self.private_key:
            EVP_PKEY_free(self.private_key)


cdef class Certificate:
    cdef:
        X509 *cert

    def __init__(self):
        self.cert = NULL
        self.cert = X509_new()

    def __dealloc__(self):
        if self.cert:
            X509_free(self.cert)

cdef class CertStore:
    cdef:
        X509_STORE *cert_store

    def __init__(self):
        self.cert_store = X509_STORE_new()

    def add_cert(self, Certificate cert not None):
        if not X509_STORE_add_cert(self.cert_store, cert.cert):
            raise _ssleay_err2value_err() or ValueError("error adding cert to cert store")

    def __dealloc__(self):
        if self.cert_store:
            X509_STORE_free(self.cert_store)


cdef object _ssleay_err2value_err():
    cdef int code
    code = ERR_get_error()
    if code:
        return ValueError(<bytes>ERR_error_string(code, None))


cdef bytes _pop_and_format_error_list():
    cdef:
        int err
        list err_list

    err_list = []
    err = ERR_get_error()
    while err:
        err_list.append((
            <bytes>ERR_lib_error_string(err),
            <bytes>ERR_func_error_string(err),
            <bytes>ERR_reason_error_string(err)))
        err = ERR_get_error()
    return b"-".join([b":".join(e) for e in err_list])


import socket


cdef enum SSL_OP:
    DO_SSL_WRITE
    DO_SSL_READ
    DO_SSL_HANDSHAKE


cdef class Socket:
    cdef:
        SSL *ssl
        bint server_side, do_handshake_on_connect, suppress_ragged_eofs
        object sock
        int fileno
        double timeout

    def __cinit__(self, sock, Context context not None, bool server_side=False,
            bool do_handshake_on_connect=True, bool suppress_ragged_eofs=True,
            Session session=None, bytes cipherlist=b''):

        self.ssl = SSL_new(context.ctx)
        self.server_side = server_side
        self.do_handshake_on_connect = do_handshake_on_connect
        self.suppress_ragged_eofs = suppress_ragged_eofs
        self.fileno = sock.fileno()
        print "fileno", self.fileno
        self.sock = sock
        if cipherlist:
            if not SSL_set_cipher_list(self.ssl, cipherlist):
                raise ValueError("no ciphers matched " + repr(cipherlist))
        if not SSL_set_fd(self.ssl, self.fileno):
            raise socket.error("SSL_set_fd failed " + _pop_and_format_error_list())
        if self.server_side:
            SSL_set_accept_state(self.ssl)
        else:
            SSL_set_connect_state(self.ssl)
            if session is not None:
                SSL_set_session(self.ssl, session.sess)
        timeout = sock.gettimeout()
        if timeout is None:
            timeout = socket.getdefaulttimeout()
            if timeout is None:
                timeout = -1
        self.set_timeout(timeout)
        if self.do_handshake_on_connect:
            try:
                self.sock.getpeername()
            except:
                pass
            else:
                self.do_handshake()

    def send(self, bytes data not None, int flags=0, double timeout=-1):
        if flags:
            raise ValueError("flags not supported for SSL socket")
        return self._do_ssl(DO_SSL_WRITE, data, len(data), timeout)

    def recv(self, int size, int flags=0, double timeout=-1):
        cdef char *buf
        cdef int read
        if flags:
            raise ValueError("flags not supported for SSL socket")
        buf = <char *>PyMem_Malloc(size)
        read = self._do_ssl(DO_SSL_READ, buf, size, timeout)
        response = <bytes>buf[:read]
        PyMem_Free(buf)
        return response

    def do_handshake(self, double timeout=-1):
        cdef int result = self._do_ssl(DO_SSL_HANDSHAKE, NULL, 0, timeout)
        if result <= 0:
            # sometimes when handshake fails, SSL_get_error still returns 0
            raise SSLError('SSL handshake failed: {0}'.format(result))
        return result

    def set_timeout(self, double timeout):
        'timeout value in seconds (e.g. 0.1 = 100ms); timeout value < 0 means non-blocking'
        cdef long nonblocking

        self.timeout = timeout
        nonblocking = self.timeout <= 0.0  # 0 for blocking IO, 1 for nonblocking IO
        BIO_set_nbio(SSL_get_rbio(self.ssl), nonblocking)
        BIO_set_nbio(SSL_get_wbio(self.ssl), nonblocking)

    cdef int _do_ssl(self, SSL_OP op, char* data, int size, double timeout) except *:
        cdef:
            int ret = 0, err = 0
            SSL *ssl

        if timeout < 0:
            timeout = self.timeout  # TODO: timeouts that do anything... heh...
        while 1:
            ssl = self.ssl
            with nogil:
                if op == DO_SSL_WRITE:
                    ret = SSL_write(ssl, data, size)
                elif op == DO_SSL_READ:
                    ret = SSL_read(ssl, data, size)
                elif op == DO_SSL_HANDSHAKE:
                    ret = SSL_do_handshake(ssl)
            err = SSL_get_error(self.ssl, ret)
            if err == SSL_ERROR_NONE:
                return ret
            elif err == SSL_ERROR_SSL:
                raise SSLError("SSL_ERROR_SSL")
            elif err == SSL_ERROR_WANT_READ:
                raise SSLWantRead()
            elif err == SSL_ERROR_WANT_WRITE:
                raise SSLWantWrite()
            elif err == SSL_ERROR_WANT_X509_LOOKUP:
                raise SSLError("SSL_ERROR_WANT_X509_LOOKUP")
            elif err == SSL_ERROR_SYSCALL:
                IF UNAME_SYSNAME == "Windows":
                    PyErr_SetExcFromWindowsErr(SSLError, 0)
                ELSE:
                    PyErr_SetFromErrno(SSLError)
            elif err == SSL_ERROR_ZERO_RETURN:
                return 0
            elif err == SSL_ERROR_WANT_CONNECT:
                raise SSLError("SSL_ERROR_WANT_CONNECT")
            elif err == SSL_ERROR_WANT_ACCEPT:
                raise SSLError("SSL_ERROR_WANT_ACCEPT")
            else:
                raise SSLError("unknown")
 

class SSLError(socket.error):
    pass


class SSLWantRead(SSLError):
    pass


class SSLWantWrite(SSLError):
    pass

'''
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


cdef const EVP_CIPHER* get_aes_gcm_cipher(int keylen) except? NULL:
    if keylen == 128 / 8:
        return EVP_aes_128_gcm()
    elif keylen == 192 / 8:
        return EVP_aes_192_gcm()
    elif keylen == 256 / 8:
        return EVP_aes_256_gcm()
    raise ValueError("keylen must be 128, 192, or 256 bits")
'''

cdef _library_init():
    SSL_load_error_strings()
    SSL_library_init()


_library_init()
