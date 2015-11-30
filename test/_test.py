import socket
import select
import threading
import os.path
import time
import pprint

from cyopenssl import *

RESOURCES = os.path.dirname(os.path.abspath(__file__)) + '/resources'
PORT = 9898


def run_one_server(ctx, logf, port=PORT):
    if type(ctx) is int:
        ctx = init_contexts()[ctx]
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind( ('127.100.100.1', port) )
    s.listen(300)
    c, a = s.accept()
    c.settimeout(0.1)  # localhost should be very fast
    c2 = Socket(c, ctx, server_side=True)
    req = c2.recv(1024)
    bytes_recvd = 0
    while req:
        bytes_recvd += len(req)
        c2.send(req)
        req = c2.recv(1024)

    c2.shutdown(socket.SHUT_RDWR)
    s.close()


def run_one_client(ctx, logf, port=PORT):
    s = socket.create_connection( ('127.100.100.1', port) )
    s.settimeout(0.1)  # localhost should be very fast
    s2 = Socket(s, ctx)
    start = tfunc()
    for i in range(100):
        s2.send('hello world!')
        s2.recv(1024)
    logf("client echo latency " + str((tfunc() - start) * 1e6 / 100) + "us")
    logf('client sent: hello world!\n'
         'client recieved: ' + s2.recv(1024))
    s2.shutdown(socket.SHUT_RDWR)


def thread_network_test(ctx):
    log = []
    logf = lambda e: log.append((tfunc(), e))
    server = threading.Thread(target=run_one_server, args=(ctx, logf))
    server.daemon = True
    server.start()
    time.sleep(0.25)  # give the server time to start
    run_one_client(ctx, logf)
    log.sort()
    print "\n".join(["{}".format(e[1]) for e in log])


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


import sys
if sys.platform == 'win32':
    tfunc = time.clock
else:
    tfunc = time.time
