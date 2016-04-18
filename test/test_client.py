import socket

import test
import _test
from cyopenssl import *

contexts = _test.init_contexts()
ctx = contexts[0]
N_SEND = 1000

s = socket.create_connection( ('127.100.100.1', 8888) )
s2 = Socket(s, ctx)
s2.send('test')
s2.recv(4)
start = time.time()
for i in range(N_SEND):
	s2.send('test')
	s2.recv(4)
finish = time.time()
s2.shutdown(socket.SHUT_RDWR)

print "{0:0.2f}us per SSL echo".format(1e6 * (finish - start) / N_SEND)
