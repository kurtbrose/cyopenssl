import socket
import select
import base64
import threading
import os.path
import time
import timeit
import pprint
import traceback

from cyopenssl import *

RESOURCES = os.path.dirname(os.path.abspath(__file__)) + '/resources'
PORT = 9898


def run_one_server(ctx, logf, port=PORT, event=None):
    if type(ctx) is int:
        ctx = init_contexts()[ctx]
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind( ('127.100.100.1', port) )
    s.listen(300)
    if event:
        event.set()
    c, a = s.accept()
    c.settimeout(0.1)  # localhost should be very fast
    c2 = Socket(c, ctx, server_side=True)
    #c2.enable_debug_print()
    logf("SERVER: START LOOP")
    req = c2.recv(1024)
    bytes_recvd = 0
    while req:
        bytes_recvd += len(req)
        c2.send(req)
        try:
            req = c2.recv(1024)
            if not req:
                logf("SERVER: GOT EMPTY RECV() DATA")
        except socket.error:
            logf(
                "SERVER: SOCKET ERROR AFTER {0} bytes\n".format(bytes_recvd)
                + traceback.format_exc())
            break

    c2.shutdown(socket.SHUT_RDWR)
    s.close()

    logf("SERVER: LOOP COMPLETE")


def run_one_client(ctx, logf, port=PORT):
    s = socket.create_connection( ('127.100.100.1', port) )
    s.settimeout(0.1)  # localhost should be very fast
    s2 = Socket(s, ctx)
    #s2.enable_debug_print()
    ts = []
    for i in range(100):
        start = tfunc()
        s2.send('hello world!')
        resp = s2.recv(1024)
        ts.append(tfunc() - start)
    logf("client mean latency " + str(sum(ts) * 1e6 / len(ts)) + "us")
    logf("client median latency " + str(sorted(ts)[len(ts) / 2] * 1e6) + "us")
    logf('client sent: hello world!\n'
         'client recieved: ' + resp)
    s2.shutdown(socket.SHUT_RDWR)


def thread_network_test(ctx):
    log = []
    logf = lambda e: log.append((tfunc(), e))
    ready = threading.Event()
    server = threading.Thread(
        target=run_one_server, args=(ctx, logf), kwargs={'event': ready})
    server.daemon = True
    server.start()
    if not ready.wait(0.5):
        raise Exception("server not ready after 500ms")
    try:
        run_one_client(ctx, logf)
    finally:
        server.join()
        log.sort()
        print "\n".join(["{}".format(e[1]) for e in log])


def session_test(ctx, ping_pongs=1):
    class BufSock(object):
        fileno = lambda self: -1

        def __init__(self):
            self.inbuf = bytearray()
            self.sent_msgs = []

        def setpeer(self, peer):
            self.peer = peer

        def sendall(self, data):
            unparsed = data
            while unparsed:
                nxt = TLS_Msg(unparsed)
                #print "sending...", nxt
                unparsed = unparsed[len(nxt):]
                break
            self.peer.inbuf += data

        def recv_into(self, buf):
            if not self.inbuf:
                raise self.NeedPeerData()
            recvd = min(len(buf), len(self.inbuf))
            unparsed = self.inbuf[:recvd]
            while unparsed:
                nxt = TLS_Msg(unparsed)
                #print 'recving...', nxt
                unparsed = unparsed[len(nxt):]
                break
            buf[:recvd] = self.inbuf[:recvd]
            self.inbuf = self.inbuf[recvd:]
            return recvd

        @classmethod
        def pair(cls):
            a, b = cls(), cls()
            a.setpeer(b)
            b.setpeer(a)
            return a, b

        class NeedPeerData(ValueError):
            pass

    c, s = BufSock.pair()

    tls_c = Socket(c, ctx)
    tls_s = Socket(s, ctx, server_side=True)
    tls_c.enable_debug_print()
    tls_s.enable_debug_print()

    for i in range(10):
        try:
            tls_c.do_handshake()
            tls_s.do_handshake()
            break
        except BufSock.NeedPeerData:
            try:
                tls_s.do_handshake()
                tls_c.do_handshake()
            except BufSock.NeedPeerData:
                pass
    else:
        raise ValueError('could not complete TLS handshake')

    for i in range(ping_pongs):
        try:
            #print "sending application data",
            tls_c.send('h' * 1024)
        except BufSock.NeedPeerData:
            raise ValueError("client could not send without server data")
        try:
            #print 
            tls_s.recv(1024)
        except BufSock.NeedPeerData:
            raise ValueError("server did not recv client data")


class TLS_Msg(object):
    def __init__(self, data):
        self.content_type = data[0]
        self.version = data[1:3]
        self.length = data[3] * 256 + data[4]
        self.data = data[:self.length + 5]

    def __len__(self):
        return len(self.data)

    def __repr__(self):
        TYPES = {
            20: 'change_cipher_spec', 21: 'alert', 22: 'handshake',
            23: 'application_data'
        }
        return "<TLS_Msg type={0}, len={1}>".format(
            TYPES.get(self.content_type, self.content_type), self.length)


def google_client_test(ctx):
    s = socket.create_connection(('google.com', 443))
    s2 = Socket(s, ctx)
    s2.send('GET / HTTP/0.9\r\n\r\n')
    resp = s2.recv(32 * 1024)  # just check that we can establish SSL tunnel
    assert resp, "google handshake failed"


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


def pkcs7():
    def pem2asn(data):
        # hackety hack hack way of converting PEM 2 ASN1 binary string
        # ... good enough for this test but nothing else
        return base64.b64decode(
            'MII' + data.partition('MII')[2].partition('-----')[0].replace('\n', ''))

    print "PKCS7 performance..."
    for s in ['1k', '2k', '4k']:
        pub = open('{0}/cert{1}.pem'.format(RESOURCES, s)).read()
        cert = Certificate(pem2asn(pub))
        certstore = CertStore()
        certstore.add_cert(cert)
        certstack = CertStack([cert])
        key = open('{0}/key{1}.pem'.format(RESOURCES, s)).read()
        pkey = PrivateKey(key, 'test')
        for inp in ('a', 'a' * 256, 'a' * 1024, 'a' * 1024 * 1024):
            signed = pkcs7_sign(cert, pkey, inp)
            encrypted = pkcs7_encrypt(certstack, inp)
            assert pkcs7_verify(signed, certstore), "verify failed"
            assert pkcs7_decrypt(encrypted, pkey, cert) == inp, "decrypt failed"
            PKCS7_digest.parse_pem(str(signed.pem_digest()))
            PKCS7_digest.parse_pem(str(encrypted.pem_digest()))
            print "key:", s, "input {0:8d}".format(len(inp))
            dur = timeit.timeit(
                lambda: pkcs7_sign(cert, pkey, inp).pem_digest(), number=10)
            print "SIGN {0:6.02f}ms".format(dur * 100),
            dur = timeit.timeit(
                lambda: pkcs7_verify(signed, certstore), number=10)
            print "VERIFY {0:6.02f}ms".format(dur * 100),
            dur = timeit.timeit(
                lambda: pkcs7_encrypt(certstack, inp), number=10)
            print "ENCRYPT {0:6.02f}ms".format(dur * 100),
            dur = timeit.timeit(
                lambda: pkcs7_decrypt(encrypted, pkey, cert), number=10)
            print "DECRYPT {0:6.02f}ms".format(dur * 100)

import sys
if sys.platform == 'win32':
    tfunc = time.clock
else:
    tfunc = time.time
