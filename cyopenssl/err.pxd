'''
Utility funciotn pop_and_format() for making human readable string
out of error return codes.
'''
cdef extern from "openssl/err.h":
    unsigned long ERR_get_error()
    unsigned long ERR_peek_error()
    char *ERR_error_string(unsigned long e, char *buf)
    const char *ERR_lib_error_string(unsigned long e)
    const char *ERR_func_error_string(unsigned long e)
    const char *ERR_reason_error_string(unsigned long e)

cdef inline bytes pop_and_format():
    cdef:
        int err
        list err_list

    err_list = []
    err = ERR_get_error()
    while err:
        err_list.append((
            <bytes>ERR_lib_error_string(err),
            <bytes>ERR_func_error_string(err),
            <bytes>ERR_reason_error_string(err)))
        err = ERR_get_error()
    return b"-".join([b":".join(e) for e in err_list])
