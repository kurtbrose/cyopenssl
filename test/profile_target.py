import time

import test
import _test

contexts = _test.init_contexts()

N_SEND = 100000

s = time.time()
_test.session_test(contexts[0], N_SEND)
f = time.time()

print "{0:0.2f}us per send+recv".format(1e6 * (f - s) / N_SEND)
