import socket

import test
import _test
from cyopenssl import *


contexts = _test.init_contexts()
ctx = contexts[0]


s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind( ('127.100.100.1', 8888) )
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
