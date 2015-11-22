import sys
import os.path
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)) + '/..')

import multiprocessing
import time
import _test


def run():
    cs = _test.init_contexts()

    for ctx in cs:
        print "google test"
        _test.google_client_test(ctx)
        print "thread test"
        _test.thread_network_test(cs[0])

        p = multiprocessing.Process(target=_test.run_one_server, args=(0, logf))
        p.daemon = True
        p.start()
        time.sleep(0.3)
        _test.run_one_client(cs[0], logf)


def logf(msg):
    print msg


if __name__ == "__main__":
    run()
