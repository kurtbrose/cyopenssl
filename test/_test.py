import socket
import select
import threading
import os.path
import time
import pprint

from openssl import *

RESOURCES = os.path.dirname(os.path.abspath(__file__)) + '/resources'
PORT = 9898


def run_one_server(ctx, port=PORT):
    if type(ctx) is int:
        ctx = init_contexts()[ctx]
    s = socket.socket()
    s.bind( ('127.100.100.1', port) )
    s.listen(300)
    c, a = s.accept()
    c2 = Socket(c, ctx, server_side=True)
    c2.send('hello world!')
    print c.getpeername()


def run_one_client(ctx, port=PORT):
    s = socket.create_connection( ('127.100.100.1', port) )
    s2 = Socket(s, ctx)
    print "client recieved", s2.recv(1024)
    print s.getpeername()


def thread_network_test(ctx):
    server = threading.Thread(target=run_one_server, args=(ctx,))
    server.daemon = True
    server.start()
    time.sleep(0.25)  # give the server time to start
    run_one_client(ctx)


def google_client_test(ctx):
    s = socket.create_connection(('google.com', 443))
    s2 = Socket(s, ctx)


def init_contexts():
    contexts = []
    for s in ['1k', '2k', '4k']:
        ctx = Context('TLSv1')
        ctx.set_password('test')
        ctx.use_certificate_chain_file('{0}/cert{1}.pem'.format(RESOURCES, s))
        ctx.load_client_CA_list('{0}/cert{1}.pem'.format(RESOURCES, s))
        ctx.load_verify_locations('{0}/cert{1}.pem'.format(RESOURCES, s))
        ctx.use_privatekey_file('{0}/key{1}.pem'.format(RESOURCES, s))
        ctx.check_privatekey()
        contexts.append(ctx)
    return contexts


def encryption():
    import timeit

    dur = timeit.timeit(lambda: aes_gcm_encrypt('abc', 'a' * 16, 'a' * 12), number=1000)
    print dur * 1000, "us per aes gcm encrypt"

    plaintext = "hello world!"
    ciphertext, tag = aes_gcm_encrypt(plaintext, 'a' * 16, 'a' * 12)
    assert plaintext == aes_gcm_decrypt(ciphertext, 'a' * 16, 'a' * 12, tag)

    dur2 = timeit.timeit(lambda: aes_gcm_decrypt(ciphertext, 'a' * 16, 'a' * 12, tag), number=1000)
    print dur2 * 1000, "us per aes gcm decrypt"
