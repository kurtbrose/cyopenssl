import test
import _test

from cyopenssl import rsa
from cyopenssl import Certificate


def test_rsa_roundtrip():
    private_bytes = open('{0}/key1k.pem'.format(_test.RESOURCES)).read()
    public_bytes = open('{0}/cert1k.pem'.format(_test.RESOURCES)).read()
    keypair = rsa.KeyPair(private_bytes, public_bytes, 'test')
    ct = keypair.public_encrypt('hello world!', rsa.PKCS1_PADDING)
    pt = keypair.private_decrypt(str(ct), rsa.PKCS1_PADDING)


if __name__ == "__main__":
    test_rsa_roundtrip()
