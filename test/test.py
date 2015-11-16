import sys
import os.path
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)) + '/..')

import multiprocessing
import _test


def run():
    cs = _test.init_contexts()
    p = multiprocessing.Process(target=_test.run_one_server, args=(0,))
    p.daemon = True
    p.start()
    _test.run_one_client(cs[0])


if __name__ == "__main__":
    run()
