import ctypes
import os.path

RESOURCE_DIR = os.path.dirname(os.path.abspath(__file__)) + '/resources'

ctypes.CDLL(RESOURCE_DIR + '/libeay32.dll')
ctypes.CDLL(RESOURCE_DIR + '/ssleay32.dll')

from openssl import *
