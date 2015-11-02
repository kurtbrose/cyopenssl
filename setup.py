from distutils.core import setup, Extension
from Cython.Build import cythonize
import platform
import os

if platform.system() == 'Windows':
    # because I can't figure out how to get distutils to
    # properly pass through the -IC parameter, just go
    # around it with environment variable
    os.environ['INCLUDE'] = 'C:\\OpenSSL-Win32\\include'
    libraries=['libeay32', 'ssleay32']
    os.environ['LIB'] = 'C:\\OpenSSL-Win32\\lib'
else:
    libraries = ['ssl', 'crypto']
    extra_compile_args = []


extension = Extension('openssl', sources=['openssl.pyx'],
    libraries=libraries)  # , extra_compile_args=extra_compile_args)


setup(
    name='cyopenssl',
    ext_modules=cythonize(extension)
    )