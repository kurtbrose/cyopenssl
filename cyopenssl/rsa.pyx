cimport err


from  evp_h cimport *


cdef extern from "openssl/rsa.h" nogil:
    int RSA_public_encrypt(
        int flen, unsigned char *from_, unsigned char *to, RSA *rsa, int padding)
    int RSA_private_decrypt(
        int flen, unsigned char *from_, unsigned char *to, RSA *rsa, int padding)
    void RSA_free(RSA* rsa)
    int RSA_size(const RSA *rsa)

    int RSA_NO_PADDING, RSA_PKCS1_PADDING, RSA_PKCS1_OAEP_PADDING


cdef extern from "openssl/x509.h" nogil:
    ctypedef struct X509:
        pass

    EVP_PKEY *X509_get_pubkey(X509 *self)
    void X509_free(X509 *a)


cdef extern from "openssl/bio.h" nogil:
    ctypedef struct BIO:
        pass

    BIO *BIO_new_mem_buf(void *buf, int len)
    int BIO_free(BIO *a)


cdef extern from "openssl/pem.h" nogil:
    EVP_PKEY *PEM_read_bio_PrivateKey(
        BIO *bp, EVP_PKEY **x, void *cb, void *u)
    X509 *PEM_read_bio_X509(
        BIO *bp, X509 **x, void *cb, void *u)


cdef class KeyPair:
    '''
    Converts PEM formatted private key and public key into a keypair
    struct for doing RSA operations.

    e.g. KeyPair(open('key.pem').read(), open('cert.pem').read(), passphrase)
    '''
    cdef EVP_PKEY *private_key
    cdef EVP_PKEY *public_key
    cdef int size

    def __cinit__(self, bytes privkey, bytes pubkey, bytes passphrase):
        cdef:
            BIO *bio
            X509 *x509
            int size1, size2
            RSA *rsa

        self.private_key = NULL
        self.public_key = NULL
        bio = BIO_new_mem_buf(<char*>privkey, len(privkey))
        self.private_key = PEM_read_bio_PrivateKey(bio, NULL, NULL, <char*>passphrase)
        BIO_free(bio)
        if not self.private_key:
            raise ValueError('PEM_read_bio_PrivateKey() failed: ' + err.pop_and_format())
        bio = BIO_new_mem_buf(<char*>pubkey, len(pubkey))
        x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL)
        BIO_free(bio)
        if not x509:
            raise ValueError('PEM_read_bio_X509() failed: ' + err.pop_and_format())
        self.public_key = X509_get_pubkey(x509)
        X509_free(x509)
        rsa = EVP_PKEY_get1_RSA(self.private_key)
        size1 = RSA_size(rsa)
        RSA_free(rsa)
        rsa = EVP_PKEY_get1_RSA(self.public_key)
        size2 = RSA_size(rsa)
        RSA_free(rsa)
        if size1 <= 0 or size2 <= 0:
            raise ValueError(
                "RSA_size on EVP_PKEY structs returned {0}, {1}".format(size1, size2))
        if size1 != size2:
            raise ValueError(
                "public key size {0}, private key size {1}".format(size2 * 8, size1 * 8))
        self.size = size1


    def __dealloc__(self):
        if self.private_key:
            EVP_PKEY_free(self.private_key)
        if self.public_key:
            EVP_PKEY_free(self.public_key)

    def public_encrypt(self, bytes plaintext, Padding padding):
        return _rsa_helper(self.size, self.public_key, plaintext, padding, 1)

    def private_decrypt(self, bytes ciphertext, Padding padding):
        return _rsa_helper(self.size, self.private_key, ciphertext, padding, 0)

    def get_rsa_size(self):
        'return the curve size (size of ciphertext, maximum size of plaintext)'
        return self.size


cdef bytearray _rsa_helper(int size, EVP_PKEY *pkey, bytes input, Padding padding, int is_encrypt):
    cdef:
        RSA *rsa
        int rc

    rsa = EVP_PKEY_get1_RSA(pkey)
    try:
        outbuf = bytearray(size)
        if is_encrypt:
            rc = RSA_public_encrypt(len(input), input, outbuf, rsa, padding.padding)
        else:
            rc = RSA_private_decrypt(size, input, outbuf, rsa, padding.padding)
        if rc == -1:
            raise ValueError(
                ('RSA_public_encrypt()' if is_encrypt else 'RSA_private_decrypt()') +
                ' failed: ' + err.pop_and_format())
        return outbuf[:rc]
    finally:
        RSA_free(rsa)  # undo inc-ref caused by get1_RSA above


cdef class Padding:
    'enum-like class -- access global constants from module'
    cdef int padding

    def __cinit__(self, val):
        self.padding = val


NO_PADDING = Padding(RSA_NO_PADDING)
PKCS1_PADDING = Padding(RSA_PKCS1_PADDING)
PKCS1_OAEP_PADDING = Padding(RSA_PKCS1_OAEP_PADDING)

