#include "Python.h"

/* this is mostly from cpython/Modules/posixmodule.c */

PyDoc_STRVAR(pyreaddir_top__doc__,
"This module provides access to readdir, which is similar to posix readdir.");

PyDoc_STRVAR(pyreaddir__doc__,
"readdir(path) -> (name, type, ino)\n\n\
Return a list containing the (names, types, inodes) of the entries in the directory.\n\
\n\
    path: path of directory to list\n\
\n\
The list is in arbitrary order.  It does not include the special\n\
entries '.' and '..' even if they are present in the directory.");

#include <sys/types.h>
#include <dirent.h>

static PyObject *
ReadDirEntry_type(struct dirent *self)
{
    switch (self->d_type)
    {
# define PRNT_ENT(T) \
        case DT_ ## T : \
            return PyString_FromString( #T )
        PRNT_ENT(BLK);
        PRNT_ENT(CHR);
        PRNT_ENT(DIR);
        PRNT_ENT(FIFO);
        PRNT_ENT(LNK);
        PRNT_ENT(REG);
        PRNT_ENT(SOCK);
        PRNT_ENT(UNKNOWN);
    }

    return PyString_FromString("<Error>");
}

static PyObject *
posix_error_with_allocated_filename(char* name)
{
    PyObject *rc = PyErr_SetFromErrnoWithFilename(PyExc_OSError, name);
    PyMem_Free(name);
    return rc;
}

#if 1
#define NAMLEN(dirent) strlen((dirent)->d_name)
#else /* reclen ?? */
#define NAMLEN(dirent) (dirent)->d_namlen
#endif

static PyObject *
_pyreaddir(PyObject *self, PyObject *args)
{
    /* XXX Should redo this putting the (now four) versions of opendir
 *        in separate files instead of having them all here... */
    char *name = NULL;
    PyObject *d, *v;
    PyObject *vtype;
    PyObject *vino;
    PyObject *tv;
    DIR *dirp;
    struct dirent *ep;
    int arg_is_unicode = 1;

    errno = 0;
    if (!PyArg_ParseTuple(args, "U:readdir", &v)) {
        arg_is_unicode = 0;
        PyErr_Clear();
    }
    if (!PyArg_ParseTuple(args, "et:readdir", Py_FileSystemDefaultEncoding, &name))
        return NULL;
    Py_BEGIN_ALLOW_THREADS
    dirp = opendir(name);
    Py_END_ALLOW_THREADS
    if (dirp == NULL) {
        return posix_error_with_allocated_filename(name);
    }
    if ((d = PyList_New(0)) == NULL) {
        Py_BEGIN_ALLOW_THREADS
        closedir(dirp);
        Py_END_ALLOW_THREADS
        PyMem_Free(name);
        return NULL;
    }
    for (;;) {
        errno = 0;
        Py_BEGIN_ALLOW_THREADS
        ep = readdir(dirp);
        Py_END_ALLOW_THREADS
        if (ep == NULL) {
            if (errno == 0) {
                break;
            } else {
                Py_BEGIN_ALLOW_THREADS
                closedir(dirp);
                Py_END_ALLOW_THREADS
                Py_DECREF(d);
                return posix_error_with_allocated_filename(name);
            }
        }
        if (ep->d_name[0] == '.' &&
            (NAMLEN(ep) == 1 ||
             (ep->d_name[1] == '.' && NAMLEN(ep) == 2)))
            continue;

        v = PyString_FromStringAndSize(ep->d_name, NAMLEN(ep));
        if (v == NULL) {
            Py_DECREF(d);
            d = NULL;
            break;
        }

        vtype = ReadDirEntry_type(ep);
        if (!vtype) {
            Py_DECREF(v);
            Py_DECREF(d);
            d = NULL;
            break;
        }

        vino = PyLong_FromLong(ep->d_ino);
        if (!vino) {
            Py_DECREF(vtype);
            Py_DECREF(v);
            Py_DECREF(d);
            d = NULL;
            break;
        }

        tv = PyTuple_New(3);
        if (!tv) {
            Py_DECREF(vino);
            Py_DECREF(vtype);
            Py_DECREF(v);
            Py_DECREF(d);
            d = NULL;
            break;
        }

        PyTuple_SetItem(tv, 0, v);
        PyTuple_SetItem(tv, 1, vtype);
        PyTuple_SetItem(tv, 2, vino);

        if (PyList_Append(d, tv) != 0) {
            Py_DECREF(tv);
            Py_DECREF(d);
            d = NULL;
            break;
        }
        Py_DECREF(tv);
    }
    Py_BEGIN_ALLOW_THREADS
    closedir(dirp);
    Py_END_ALLOW_THREADS
    PyMem_Free(name);

    return d;
}  /* end of posix_listdir */

static PyMethodDef pyreaddir_methods[] = {
    {"readdir",         _pyreaddir, METH_VARARGS, pyreaddir__doc__},
    {NULL,              NULL}            /* Sentinel */
};



PyMODINIT_FUNC
initpyreaddir(void)
{
    PyObject *m, *v;

    m = Py_InitModule3("pyreaddir",
                       pyreaddir_methods,
                       pyreaddir_top__doc__);
    if (m == NULL)
        return;
}

