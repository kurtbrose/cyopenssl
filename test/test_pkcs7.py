import base64
import re

import test
import _test
from cyopenssl import *


def test_pkcs7_roundtrip():
    pkey = PrivateKey(open('{0}/key1k.pem'.format(_test.RESOURCES)).read(), 'test')
    cert_pem_bytes = open('{0}/cert1k.pem'.format(_test.RESOURCES)).read()
    cert_bytes = base64.b64decode(_CERT_RE.match(cert_pem_bytes).group(1).replace("\n", ""))
    cert = Certificate(cert_bytes)
    certstack = CertStack([cert])
    digest = pkcs7_encrypt(certstack, 'hello world!')
    ciphertext = digest.pem_digest()
    digest2 = PKCS7_digest.parse_pem(str(ciphertext))
    plaintext = pkcs7_decrypt(digest2, pkey, cert)


_CERT_RE = re.compile(
    r'-----BEGIN CERTIFICATE-----\n(.*)\n-----END CERTIFICATE-----\n', flags=re.DOTALL)

if __name__ == "__main__":
    test_pkcs7_roundtrip()