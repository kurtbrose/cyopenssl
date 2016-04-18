import time
import subprocess
import sys
import atexit


import test
import _test


def run():
	server = _start("test_server.py")
	time.sleep(0.1)
	client = _start("test_client.py")
	client.wait()


_PROCS = []


def _start(module):
	proc = subprocess.Popen([sys.executable, module])
	_PROCS.append(proc)
	return proc


def _cleanup():
	for proc in _PROCS:
		try:
			proc.kill()
		except OSError:
			pass


if __name__ == "__main__":
	run()
