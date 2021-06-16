#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

static PyObject * tp_copy_fd(PyObject *self, PyObject *args) {
    unsigned char buf[4096];
    int fd0, fd1, ret;

    if (!PyArg_ParseTuple(args, "ii", &fd0, &fd1))
        return NULL;
    
    Py_BEGIN_ALLOW_THREADS;
    // printf("fd0=%d fd1=%d\n", fd0, fd1);
    socklen_t bufsize = sizeof(buf);
    ret = getsockopt(fd0, SOL_SOCKET, SO_RCVBUF, buf, &bufsize);
    //printf("fd0=%d getsockopt=%d buf[3]=%d bs=%d\n", fd0, ret, *((unsigned int *)buf), bufsize);
    while ((ret = read(fd0, buf, sizeof(buf))) > 0) {
        // printf("read successful: %d\n", ret);
        int idx;
        int rsize = ret;
        idx = write(fd1, buf, rsize);
        // printf("write successful: %d\n", idx);
        while (idx != rsize) {
            ret = write(fd1, buf + idx, rsize - idx);
            if (ret < 0) {
                //Py_END_ALLOW_THREADS;
                //return PyLong_FromLong(2);
                goto end;
            }
            idx += ret;
        }
    }
end:
    //printf("aight i'm done ret=%d\n", ret);
    
    Py_END_ALLOW_THREADS;
    return PyLong_FromLong(ret);
}

// Py init stuff

static PyMethodDef TransproxyMethods[] = {
    {"copy_fd",  tp_copy_fd, METH_VARARGS,
     "Copy data from first fd to second fd."},
    {NULL, NULL, 0, NULL}        /* Sentinel */
};

static struct PyModuleDef transproxy_module = {
    PyModuleDef_HEAD_INIT,
    "transproxy_native",   /* name of module */
    NULL, /* module documentation, may be NULL */
    -1,       /* size of per-interpreter state of the module,
                 or -1 if the module keeps state in global variables. */
    TransproxyMethods
};

PyMODINIT_FUNC
PyInit_transproxy_native(void)
{
    return PyModule_Create(&transproxy_module);
}
