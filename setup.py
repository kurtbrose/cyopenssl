from distutils.core import setup, Extension
from Cython.Build import cythonize
import platform
import os


extra_compile_args = []
extra_objects = []
libraries = []
include_dirs = ['src/monotonic_timer/']
library_dirs = []

compiler = 'msvc'  # TODO: detect this properly
STATIC = False

if platform.system() == 'Windows':
    include_dirs = ['C:\\OpenSSL-Win32\\include']
    if compiler == 'msvc':
        if STATIC:
            extra_objects = [
                'C:\\OpenSSL-Win32\\lib\\libeay32.lib', 
                'C:\\OpenSSL-Win32\\lib\\ssleay32.lib']
        else:
            library_dirs = ['C:\\OpenSSL-Win32\\lib']
            libraries = ['libeay32', 'ssleay32', 'ws2_32', 'advapi32', 'crypt32',
                         'gdi32', 'user32']
    elif compiler == 'mingw32':
        # let's try doing an end-run around all that complexity via MinGW
        SSLPATH = 'C:\\OpenSSL-Win32\\lib\\MinGW'
        libraries = []
        extra_objects = [SSLPATH + '\\libeay32.a', SSLPATH + '\\ssleay32.a']
        # by doing the link step manually, I can get it to use .a files; but still fails
        # at import time...
        # ld -shared build\temp.win32-2.7\Release\openssl.o libeay32.a ssleay32.a -LC:\Python27\libs 
        #  -LC:\Python27\PCbuild -lpython27 -lmsvcr90 
        #  -o C:\Users\Kurt\workspace\cyopenssl\openssl.pyd
else:
    libraries = ['ssl', 'crypto']


extension = Extension('openssl', sources=['cyopenssl/openssl.pyx', 'src/monotonic_timer/monotonic_timer.c'],
    libraries=libraries, extra_compile_args=extra_compile_args,
    extra_objects=extra_objects, include_dirs=include_dirs,
    library_dirs=library_dirs)


setup(
    name='cyopenssl',
    ext_modules=cythonize(extension)
    )
