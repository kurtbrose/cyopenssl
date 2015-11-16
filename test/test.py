import sys
import os.path
sys.path.append(os.path.dirname(os.path.abspath(__file__)) + '/..')

import socket
import threading


from openssl import *


RESOURCES = os.path.dirname(os.path.abspath(__file__)) + '/resources'
PORT = 9898


def network_test(ctx):
    def run_one_server(ctx, port=PORT):
        s = socket.socket()
        s.bind( ('127.100.100.1', port) )
        s.listen(300)
        c, a = s.accept()
        c2 = Socket(s, ctx, server_side=True)


    def run_one_client(ctx, port=PORT):
        s = socket.create_connection( ('127.100.100.1', port) )
        s2 = Socket(s, ctx)


    server = threading.Thread(target=run_one_server, args=(ctx,))
    server.daemon = True
    server.start()

    run_one_client(ctx)



def test():
    import timeit
    '''
    dur = timeit.timeit(lambda: aes_gcm_encrypt('abc', 'a' * 16, 'a' * 12), number=1000)
    print dur * 1000, "us per aes gcm encrypt"

    plaintext = "hello world!"
    ciphertext, tag = aes_gcm_encrypt(plaintext, 'a' * 16, 'a' * 12)
    assert plaintext == aes_gcm_decrypt(ciphertext, 'a' * 16, 'a' * 12, tag)

    dur2 = timeit.timeit(lambda: aes_gcm_decrypt(ciphertext, 'a' * 16, 'a' * 12, tag), number=1000)
    print dur2 * 1000, "us per aes gcm decrypt"
    '''

    print "initializing context..."
    ctx = Context('TLSv1')
    ctx.set_password('test')
    ctx.use_cerificate_chain_file(RESOURCES + '/cert1k.pem')
    ctx.use_privatekey_file(RESOURCES + '/key1k.pem')
    print "performing handshake..."
    network_test(ctx)




if __name__ == "__main__":
    test()
