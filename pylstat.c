#include "Python.h"
#include "structseq.h"

/* this is mostly from cpython/Modules/posixmodule.c */

PyDoc_STRVAR(pylstat_top__doc__,
"This module provides access to lstat/stat with nsec data.");

#undef STAT
#undef FSTAT
#undef STRUCT_STAT

#       define STAT stat
#       define FSTAT fstat
#       define STRUCT_STAT struct stat

static int initialized;
static PyTypeObject StatResultType;
static newfunc structseq_new;

static PyObject *
statresult_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    PyStructSequence *result;
    int i;

    result = (PyStructSequence*)structseq_new(type, args, kwds);
    if (!result)
        return NULL;
    /* If we have been initialized from a tuple,
       st_?time might be set to None. Initialize it
       from the int slots.  */
    for (i = 7; i <= 9; i++) {
        if (result->ob_item[i+3] == Py_None) {
            Py_DECREF(Py_None);
            Py_INCREF(result->ob_item[i]);
            result->ob_item[i+3] = result->ob_item[i];
        }
    }
    return (PyObject*)result;
}

static int _stat_float_times = 1;

static PyObject *
posix_error_with_filename(char* name)
{
    return PyErr_SetFromErrnoWithFilename(PyExc_OSError, name);
}

static PyObject *
_PyInt_FromUid(uid_t uid)
{
    if (uid <= LONG_MAX)
        return PyInt_FromLong(uid);
    return PyLong_FromUnsignedLong(uid);
}

static PyObject *
_PyInt_FromGid(gid_t gid)
{
    if (gid <= LONG_MAX)
        return PyInt_FromLong(gid);
    return PyLong_FromUnsignedLong(gid);
}

#ifdef HAVE_LONG_LONG
static PyObject *
_PyInt_FromDev(PY_LONG_LONG v)
{
    if (LONG_MIN <= v && v <= LONG_MAX)
        return PyInt_FromLong((long)v);
    else
        return PyLong_FromLongLong(v);
}
#else
#  define _PyInt_FromDev PyInt_FromLong
#endif

PyDoc_STRVAR(stat_result__doc__,
"stat_result: Result from stat or lstat.\n\n\
This object may be accessed either as a tuple of\n\
  (mode, ino, dev, nlink, uid, gid, size, atime, mtime, ctime)\n\
or via the attributes st_mode, st_ino, st_dev, st_nlink, st_uid, and so on.\n\
\n\
Posix/windows: If your platform supports st_blksize, st_blocks, st_rdev,\n\
or st_flags, they are available as attributes only.\n\
\n\
See os.stat for more information.");

static PyStructSequence_Field stat_result_fields[] = {
    {"st_mode",    "protection bits"},
    {"st_ino",     "inode"},
    {"st_dev",     "device"},
    {"st_nlink",   "number of hard links"},
    {"st_uid",     "user ID of owner"},
    {"st_gid",     "group ID of owner"},
    {"st_size",    "total size, in bytes"},
    /* The NULL is replaced with PyStructSequence_UnnamedField later. */
    {NULL,   "integer time of last access"},
    {NULL,   "integer time of last modification"},
    {NULL,   "integer time of last change"},
    {"st_atime",   "time of last access"},
    {"st_mtime",   "time of last modification"},
    {"st_ctime",   "time of last change"},
    {"st_atime_ns",   "time of last access in nanoseconds"},
    {"st_mtime_ns",   "time of last modification in nanoseconds"},
    {"st_ctime_ns",   "time of last change in nanoseconds"},
#ifdef HAVE_STRUCT_STAT_ST_BLKSIZE
    {"st_blksize", "blocksize for filesystem I/O"},
#endif
#ifdef HAVE_STRUCT_STAT_ST_BLOCKS
    {"st_blocks",  "number of blocks allocated"},
#endif
#ifdef HAVE_STRUCT_STAT_ST_RDEV
    {"st_rdev",    "device type (if inode device)"},
#endif
#ifdef HAVE_STRUCT_STAT_ST_FLAGS
    {"st_flags",   "user defined flags for file"},
#endif
#ifdef HAVE_STRUCT_STAT_ST_GEN
    {"st_gen",    "generation number"},
#endif
#ifdef HAVE_STRUCT_STAT_ST_BIRTHTIME
    {"st_birthtime",   "time of creation"},
#endif
    {0}
};

#ifdef HAVE_STRUCT_STAT_ST_BLKSIZE
#define ST_BLKSIZE_IDX 16
#else
#define ST_BLKSIZE_IDX 15
#endif

#ifdef HAVE_STRUCT_STAT_ST_BLOCKS
#define ST_BLOCKS_IDX (ST_BLKSIZE_IDX+1)
#else
#define ST_BLOCKS_IDX ST_BLKSIZE_IDX
#endif

#ifdef HAVE_STRUCT_STAT_ST_RDEV
#define ST_RDEV_IDX (ST_BLOCKS_IDX+1)
#else
#define ST_RDEV_IDX ST_BLOCKS_IDX
#endif

#ifdef HAVE_STRUCT_STAT_ST_FLAGS
#define ST_FLAGS_IDX (ST_RDEV_IDX+1)
#else
#define ST_FLAGS_IDX ST_RDEV_IDX
#endif

#ifdef HAVE_STRUCT_STAT_ST_GEN
#define ST_GEN_IDX (ST_FLAGS_IDX+1)
#else
#define ST_GEN_IDX ST_FLAGS_IDX
#endif

#ifdef HAVE_STRUCT_STAT_ST_BIRTHTIME
#define ST_BIRTHTIME_IDX (ST_GEN_IDX+1)
#else
#define ST_BIRTHTIME_IDX ST_GEN_IDX
#endif

static PyStructSequence_Desc stat_result_desc = {
    "stat_result", /* name */
    stat_result__doc__, /* doc */
    stat_result_fields,
    10
};



PyDoc_STRVAR(stat_float_times__doc__,
"stat_float_times([newval]) -> oldval\n\n\
Determine whether os.[lf]stat represents time stamps as float objects.\n\
If newval is True, future calls to stat() return floats, if it is False,\n\
future calls return ints. \n\
If newval is omitted, return the current setting.\n");

static PyObject*
stat_float_times(PyObject* self, PyObject *args)
{
    int newval = -1;
    if (!PyArg_ParseTuple(args, "|i:stat_float_times", &newval))
        return NULL;
    if (newval == -1)
        /* Return old value */
        return PyBool_FromLong(_stat_float_times);
    _stat_float_times = newval;
    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject *billion = NULL;

static void
fill_time(PyObject *v, int index, time_t sec, unsigned long nsec)
{
    PyObject *fval,*ival;
#if SIZEOF_TIME_T > SIZEOF_LONG
    ival = PyLong_FromLongLong((PY_LONG_LONG)sec);
#else
    ival = PyInt_FromLong((long)sec);
#endif
    PyObject *ns_fractional = PyLong_FromUnsignedLong(nsec);
    PyObject *s_in_ns = NULL;
    PyObject *ns_total = NULL;

    if (!ival)
        goto exit;
    if (!ns_fractional)
        goto exit;

    s_in_ns = PyNumber_Multiply(ival, billion);
    if (!s_in_ns)
        goto exit;

    ns_total = PyNumber_Add(s_in_ns, ns_fractional);
    if (!ns_total)
        goto exit;

    if (_stat_float_times) {
        fval = PyFloat_FromDouble(sec + 1e-9*nsec);
    } else {
        fval = ival;
        Py_INCREF(fval);
    }
    PyStructSequence_SET_ITEM(v, index, ival);
    PyStructSequence_SET_ITEM(v, index+3, fval);
    PyStructSequence_SET_ITEM(v, index+6, ns_total);
    ival = NULL;
    fval = NULL;
    ns_total = NULL;
exit:
    Py_XDECREF(ival);
    Py_XDECREF(ns_fractional);
    Py_XDECREF(s_in_ns);
    Py_XDECREF(ns_total);
    Py_XDECREF(fval);
}

/* pack a system stat C structure into the Python stat tuple
 *    (used by posix_stat() and posix_fstat()) */
static PyObject*
_pystat_fromstructstat(STRUCT_STAT *st)
{
    unsigned long ansec, mnsec, cnsec;
    PyObject *v = PyStructSequence_New(&StatResultType);
    if (v == NULL)
        return NULL;

    PyStructSequence_SET_ITEM(v, 0, PyInt_FromLong((long)st->st_mode));
#ifdef HAVE_LARGEFILE_SUPPORT
    PyStructSequence_SET_ITEM(v, 1,
                              PyLong_FromLongLong((PY_LONG_LONG)st->st_ino));
#else
    PyStructSequence_SET_ITEM(v, 1, PyInt_FromLong((long)st->st_ino));
#endif
#ifdef MS_WINDOWS
    PyStructSequence_SET_ITEM(v, 2, PyLong_FromUnsignedLong(st->st_dev));
#else
    PyStructSequence_SET_ITEM(v, 2, _PyInt_FromDev(st->st_dev));
#endif
    PyStructSequence_SET_ITEM(v, 3, PyInt_FromLong((long)st->st_nlink));
#if defined(MS_WINDOWS)
    PyStructSequence_SET_ITEM(v, 4, PyInt_FromLong(0));
    PyStructSequence_SET_ITEM(v, 5, PyInt_FromLong(0));
#else
    PyStructSequence_SET_ITEM(v, 4, _PyInt_FromUid(st->st_uid));
    PyStructSequence_SET_ITEM(v, 5, _PyInt_FromGid(st->st_gid));
#endif
#ifdef HAVE_LARGEFILE_SUPPORT
    PyStructSequence_SET_ITEM(v, 6,
                              PyLong_FromLongLong((PY_LONG_LONG)st->st_size));
#else
    PyStructSequence_SET_ITEM(v, 6, PyInt_FromLong(st->st_size));
#endif

#if defined(HAVE_STAT_TV_NSEC)
    ansec = st->st_atim.tv_nsec;
    mnsec = st->st_mtim.tv_nsec;
    cnsec = st->st_ctim.tv_nsec;
#elif defined(HAVE_STAT_TV_NSEC2)
    ansec = st->st_atimespec.tv_nsec;
    mnsec = st->st_mtimespec.tv_nsec;
    cnsec = st->st_ctimespec.tv_nsec;
#elif defined(HAVE_STAT_NSEC)
    ansec = st->st_atime_nsec;
    mnsec = st->st_mtime_nsec;
    cnsec = st->st_ctime_nsec;
#else
    ansec = mnsec = cnsec = 0;
#endif
    fill_time(v, 7, st->st_atime, ansec);
    fill_time(v, 8, st->st_mtime, mnsec);
    fill_time(v, 9, st->st_ctime, cnsec);

#ifdef HAVE_STRUCT_STAT_ST_BLKSIZE
    PyStructSequence_SET_ITEM(v, ST_BLKSIZE_IDX,
                              PyInt_FromLong((long)st->st_blksize));
#endif
#ifdef HAVE_STRUCT_STAT_ST_BLOCKS
    PyStructSequence_SET_ITEM(v, ST_BLOCKS_IDX,
                              PyInt_FromLong((long)st->st_blocks));
#endif
#ifdef HAVE_STRUCT_STAT_ST_RDEV
    PyStructSequence_SET_ITEM(v, ST_RDEV_IDX,
                              PyInt_FromLong((long)st->st_rdev));
#endif
#ifdef HAVE_STRUCT_STAT_ST_GEN
    PyStructSequence_SET_ITEM(v, ST_GEN_IDX,
                              PyInt_FromLong((long)st->st_gen));
#endif
#ifdef HAVE_STRUCT_STAT_ST_BIRTHTIME
    {
      PyObject *val;
      unsigned long bsec,bnsec;
      bsec = (long)st->st_birthtime;
#ifdef HAVE_STAT_TV_NSEC2
      bnsec = st->st_birthtimespec.tv_nsec;
#else
      bnsec = 0;
#endif
      if (_stat_float_times) {
        val = PyFloat_FromDouble(bsec + 1e-9*bnsec);
      } else {
        val = PyInt_FromLong((long)bsec);
      }
      PyStructSequence_SET_ITEM(v, ST_BIRTHTIME_IDX,
                                val);
    }
#endif
#ifdef HAVE_STRUCT_STAT_ST_FLAGS
    PyStructSequence_SET_ITEM(v, ST_FLAGS_IDX,
                              PyInt_FromLong((long)st->st_flags));
#endif

    if (PyErr_Occurred()) {
        Py_DECREF(v);
        return NULL;
    }

    return v;
}

static PyObject *
posix_do_stat(PyObject *self, PyObject *args,
              char *format,
#ifdef __VMS
              int (*statfunc)(const char *, STRUCT_STAT *, ...),
#else
              int (*statfunc)(const char *, STRUCT_STAT *),
#endif
              char *wformat,
              int (*wstatfunc)(const Py_UNICODE *, STRUCT_STAT *))
{
    STRUCT_STAT st;
    char *path = NULL;          /* pass this to stat; do not free() it */
    char *pathfree = NULL;  /* this memory must be free'd */
    int res;
    PyObject *result;

    if (!PyArg_ParseTuple(args, format,
                          Py_FileSystemDefaultEncoding, &path))
        return NULL;
    pathfree = path;

    Py_BEGIN_ALLOW_THREADS
    res = (*statfunc)(path, &st);
    Py_END_ALLOW_THREADS

    if (res != 0) {
        result = posix_error_with_filename(pathfree);
    }
    else
        result = _pystat_fromstructstat(&st);

    PyMem_Free(pathfree);
    return result;
}

PyDoc_STRVAR(posix_lstat__doc__,
"lstat(path) -> stat result\n\n\
Like stat(path), but do not follow symbolic links.");

static PyObject *
posix_lstat(PyObject *self, PyObject *args)
{
#ifdef HAVE_LSTAT
    return posix_do_stat(self, args, "et:lstat", lstat, NULL, NULL);
#else /* !HAVE_LSTAT */
#ifdef MS_WINDOWS
    return posix_do_stat(self, args, "et:lstat", STAT, "U:lstat", win32_wstat);
#else
    return posix_do_stat(self, args, "et:lstat", STAT, NULL, NULL);
#endif
#endif /* !HAVE_LSTAT */
}

PyDoc_STRVAR(posix_stat__doc__,
"stat(path) -> stat result\n\n\
Perform a stat system call on the given path.");

static PyObject *
posix_stat(PyObject *self, PyObject *args)
{
#ifdef MS_WINDOWS
    return posix_do_stat(self, args, "et:stat", STAT, "U:stat", win32_wstat);
#else
    return posix_do_stat(self, args, "et:stat", STAT, NULL, NULL);
#endif
}

static PyMethodDef pylstat_methods[] = {
    {"lstat",           posix_lstat, METH_VARARGS, posix_lstat__doc__},
    {"stat",            posix_stat, METH_VARARGS, posix_stat__doc__},
    {"stat_float_times", stat_float_times, METH_VARARGS, stat_float_times__doc__},
    {NULL,              NULL}            /* Sentinel */
};

PyMODINIT_FUNC
initpylstat(void)
{
    PyObject *m, *v;

    m = Py_InitModule3("pylstat",
                       pylstat_methods,
                       pylstat_top__doc__);
    if (m == NULL)
        return;

    if (!initialized) {
        stat_result_desc.name = "inipylstat.stat_result";
        stat_result_desc.fields[7].name = PyStructSequence_UnnamedField;
        stat_result_desc.fields[8].name = PyStructSequence_UnnamedField;
        stat_result_desc.fields[9].name = PyStructSequence_UnnamedField;
        PyStructSequence_InitType(&StatResultType, &stat_result_desc);
        structseq_new = StatResultType.tp_new;
        StatResultType.tp_new = statresult_new;
    }

    Py_INCREF((PyObject*) &StatResultType);
    PyModule_AddObject(m, "stat_result", (PyObject*) &StatResultType);

    initialized = 1;

    billion = PyLong_FromLong(1000000000);
    if (!billion)
        return; /* lol */
}

