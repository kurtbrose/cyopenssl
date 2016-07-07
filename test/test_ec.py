import sys
import os.path
import random

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cyopenssl import ec


def rand_pair(curve=ec.CURVES['K-163']):
    keypair = ec.gen_keypair(curve)
    pub_bytes = keypair.encode_pubkey()
    pub_key = ec.PublicKey(str(pub_bytes), curve)
    return keypair, pub_key


def test():
    # create some keypairs to test crypto
    print "test keypair generate"
    kp, pk = rand_pair()
    kp2, pk2 = rand_pair()
    print "test keypair from integer"
    ec.int2keypair(random.randint(0, int(1e12)), ec.CURVES['K-163'])
    print "test ECDH"
    ecdh(pk, kp2)
    print "test sign"
    sig = kp.sign('hello')
    print "test signature serialize"
    r, s = sig.get_r_s_buf()
    print "test signature parse"
    sig2 = buf2ECDSA_Signature()
    print "test signature verify"
    assert pk.verify('hello', sig2)


if __name__ == "__main__":
    test()
