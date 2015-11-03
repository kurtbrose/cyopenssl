from distutils.core import setup, Extension
from Cython.Build import cythonize
import platform
import os

if platform.system() == 'Windows':
    # because I can't figure out how to get distutils to
    # properly pass through the -IC parameter, just go
    # around it with environment variable
    os.environ['INCLUDE'] = 'C:\\OpenSSL-Win32\\include'
    # MT -- we are going to use the static versions
    libraries=['libeay32MT', 'ssleay32MT']
    # add default libraries included by visual studios projects
    # and other assorted missing dependencies
    # ... someone could spend an excurciating few hours figuring
    # out exactly which of these libraries are needed and which are
    # not to minimize the list
    libraries += ["advapi32", "shell32", "ole32", "oleaut32", "uuid", 
        "odbc32", "odbccp32", "kernel32", "user32", "ws2_32", "Gdi32" ]
    os.environ['LIB'] = 'C:\\OpenSSL-Win32\\lib\\VC\\static'
else:
    libraries = ['ssl', 'crypto']
    extra_compile_args = []


extension = Extension('openssl', sources=['openssl.pyx'],
    libraries=libraries)  # , extra_compile_args=extra_compile_args)


setup(
    name='cyopenssl',
    ext_modules=cythonize(extension)
    )
