#! /usr/bin/python -tt

__version__ = '0.1.8'
__version_info__ = tuple([ int(num) for num in __version__.split('.')])

import ctypes
import sys

def fake_readdir(path=None):
    return [(x, 'UNKNOWN', -1L) for x in os.listdir(path)]
try:
    # akfa
    import pyreaddir
    readdir = pyreaddir.readdir
    # print "JDBG:", "Using C readdir"
except:
    # print "JDBG:", "Using fake readdir"
    pyreaddir = None
    readdir = fake_readdir

try:
    # akfa
    import pylstat
    _lstat_ns = pylstat.lstat
    _stat_ns  = pylstat.stat
    # print "JDBG:", "Using C lstat"
except:
    # print "JDBG:", "Using fake lstat"
    pylstat = None

if False: pass

elif sys.platform == "linux" or sys.platform == "linux2":
    libc_name = "libc.so.6" # "libc.so.6"
elif sys.platform == "darwin":
    libc_name = "/usr/lib/libc.dylib" # "libc.so.6"
libc = ctypes.CDLL(libc_name)
libc.memcmp.argtypes = (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t)

def _fcmp(a, b):
    """ ustr_cmp_fast """
    la = len(a)
    lb = len(b)
    if la == lb:
        return libc.memcmp(a, b, la)
    return la - lb
def _shorten_snap(x):
    if len(x) > 3 and x[-1] == 'z' and x[-2] == 'g' and x[-3] == '.':
        return x[:-3]
    return x
def _snap_cmp(a, b):
    return _fcmp(_shorten_snap(a), _shorten_snap(b))


import hashlib
_checksum_aliases = {'sha'    : 'sha1',
                     'sha2'   : 'sha256'}
_checksum_d_len   = {"md5"    : 32,
                     "sha1"   : 40,
                     "sha256" : 64,
                     "sha512" : 128}

try:
    import hashlib
    # Add sha384 ?? When we don't support it above?
    if hasattr(hashlib, 'algorithms'): # Should be 2.7+
        _available_checksums = set(hashlib.algorithms)
    else:
        _available_checksums = set(['md5', 'sha1', 'sha256', 'sha512'])
except ImportError:
    # Python-2.4.z ... gah!
    import sha
    import md5
    _available_checksums = set(['md5', 'sha1'])
    class hashlib:

        @staticmethod
        def new(algo):
            if algo == 'md5':
                return md5.new()
            if algo == 'sha1':
                return sha.new()
            raise ValueError, "Bad checksum type"

# some checksum types might be disabled
for ctype in list(_available_checksums):
    try:
        hashlib.new(ctype)
    except:
        print >> sys.stderr, 'Checksum type %s disabled' % repr(ctype)
        _available_checksums.remove(ctype)
for ctype in 'sha256', 'sha1':
    if ctype in _available_checksums:
        _default_checksums = [ctype]
        break
else:
    raise ImportError, 'broken hashlib'
del ctype

class Checksums:
    """ Generate checksum(s), on given pieces of data. Producing the
        Length and the result(s) when complete. """

    def __init__(self, checksums=None, ignore_missing=False, ignore_none=False):
        if checksums is None:
            checksums = _default_checksums
        self._sumalgos = []
        self._sumtypes = []
        self._len = 0

        done = set()
        for sumtype in checksums:
            if sumtype == 'sha':
                sumtype = 'sha1'
            if sumtype in done:
                continue

            if sumtype in _available_checksums:
                sumalgo = hashlib.new(sumtype)
            elif ignore_missing:
                continue
            else:
                raise TypeError, 'Error Checksumming, bad checksum type %s' % sumtype
            done.add(sumtype)
            self._sumtypes.append(sumtype)
            self._sumalgos.append(sumalgo)
        if not done and not ignore_none:
            raise TypeError, 'Error Checksumming, no valid checksum type'

    def __len__(self):
        return self._len

    # Note that len(x) is assert limited to INT_MAX, which is 2GB on i686.
    length = property(fget=lambda self: self._len)

    def update(self, data):
        self._len += len(data)
        for sumalgo in self._sumalgos:
            sumalgo.update(data)

    def update_dict(self, datadict):
        """ Update differently for each. len() is max. """
        size = 0
        for sumtype, sumalgo in zip(self._sumtypes, self._sumalgos):
            if sumtype not in datadict:
                continue
            size = max(size, len(datadict[sumtype]))
            sumalgo.update(datadict[sumtype])
        self._len += size

    def read(self, fo, size=2**16):
        data = fo.read(size)
        self.update(data)
        return data

    def hexdigests(self):
        ret = {}
        for sumtype, sumdata in zip(self._sumtypes, self._sumalgos):
            ret[sumtype] = sumdata.hexdigest()
        return ret

    def hexdigest(self, checksum=None):
        if checksum is None:
            if not self._sumtypes:
                return None
            checksum = self._sumtypes[0]
        if checksum == 'sha':
            checksum = 'sha1'
        return self.hexdigests()[checksum]

    def digests(self):
        ret = {}
        for sumtype, sumdata in zip(self._sumtypes, self._sumalgos):
            ret[sumtype] = sumdata.digest()
        return ret

    def digest(self, checksum=None):
        if checksum is None:
            if not self._sumtypes:
                return None
            checksum = self._sumtypes[0]
        if checksum == 'sha':
            checksum = 'sha1'
        return self.digests()[checksum]


class AutoFileChecksums:
    """ Generate checksum(s), on given file/fileobject. Pretending to be a file
        object (overrrides read). """

    def __init__(self, fo, checksums, ignore_missing=False, ignore_none=False):
        self._fo       = fo
        self.checksums = Checksums(checksums, ignore_missing, ignore_none)

    def __getattr__(self, attr):
        return getattr(self._fo, attr)

    def read(self, size=-1):
        return self.checksums.read(self._fo, size)

def _file2hexdigests(filename, checksum_types=None, datasize=None, utime=None):
    if checksum_types is None:
        checksum_types = _available_checksums
    data = Checksums(checksum_types)
    CHUNK = 1024 * 8
    try:
        fo = open(filename)
        while data.read(fo, CHUNK):
            if datasize is not None and data.length > datasize:
                break
        fo.close()
        if utime is not None:
            try:
                os.utime(filename, utime)
            except:
                pass
    except Exception, e:
        # print "JDBG:", "E", e
        return None
    return data.hexdigests()

def _data2hexdigests(data, checksum_types=None):
    if checksum_types is None:
        checksum_types = _available_checksums
    chk = Checksums(checksum_types)
    chk.update(data)
    return chk.hexdigests()

def _link2hexdigests(filename, checksum_types=None):
    return _data2hexdigests(os.readlink(filename))

def _valid_checksum_data(checksum_data):
    for i in checksum_data:
        if i in "0123456789abcdef":
            continue
        return False
    return True

import os
import glob
import stat
import weakref
import time # mtime UI
import errno

if pylstat is None:
    _lstat_ns = os.lstat
    _stat_ns  = os.stat

def _lstat_f(filename, ignore_EACCES=False):
    """ Call lstat(), but don't die if the file isn't there. Returns None. """
    try:
        return _lstat_ns(filename)
    except OSError, e:
        if e.errno in (errno.ENOENT, errno.ENOTDIR):
            return None
        if ignore_EACCES and e.errno == errno.EACCES:
            return None
        raise
def _readdir_f(dirname, ignore_EACCES=False):
    """ Call readdir(), don't die if the dir. isn't readable. Returns []. """
    try:
        return readdir(dirname)
    except OSError, e:
        if e.errno in (errno.ENOENT, errno.ENOTDIR, errno.EPERM):
            return []
        if ignore_EACCES and e.errno == errno.EACCES:
            return []
        raise
def _unlink_f(filename):
    """ Call os.unlink, but don't die if the file isn't there. This is the main
        difference between "rm -f" and plain "rm". """
    try:
        os.unlink(filename)
        return True
    except OSError, e:
        if e.errno not in (errno.ENOENT, errno.EPERM, errno.EACCES,errno.EROFS):
            raise
    return False

__show_checksum_work__ = False
__show_stat_work__ = False

def _vfs_parent(vfs):
    if vfs._parent is None:
        return None
    parent = vfs._parent()
    assert parent is None or isinstance(parent, VFS_d)
    return parent

def _vfs_path(vfs):
    parent = _vfs_parent(vfs)
    if parent is None:
        return vfs.name

    if parent.path == '/':
        return parent.path + vfs.name
    return parent.path + '/' + vfs.name

def _vfs_depth(vfs):
    parent = _vfs_parent(vfs)
    if parent is None:
        return 0 # 1 ?
    return _vfs_depth(parent) + 1

def _num_cpus_online(unknown=1):
    if not hasattr(os, "sysconf"):
        return unknown

    if not os.sysconf_names.has_key("SC_NPROCESSORS_ONLN"):
        return unknown

    ncpus = os.sysconf("SC_NPROCESSORS_ONLN")
    try:
        ncpus = int(ncpus)
        if ncpus > 0:
            return ncpus
    except:
        pass

    return unknown

mp_workers = None
mp_worker_num = 0
try:
    import multiprocessing
except:
    pass

_s2ns = 1000000000 # billion, for seconds * billion == nanoseconds
class VFS_f(object):
    __slots__ = ['_parent', 'name', 'readonly',
                 '_checksum', '_stat', '_path', '_depth',
                 '_stat_st_size',
                 '_stat_st_mtime',
                 '_stat_st_mtime_ns',
                 '_stat_st_mode',
                 '_stat_st_ctime',
                 '_stat_st_ctime_ns',
                 '_stat_st_atime',
                 '_stat_st_atime_ns',
                 '_stat_st_nlink',
                 '_stat_st_dev',
                 '_stat_st_ino',
                 '_stat_st_uid',
                 '_stat_st_gid',
                 ]

    def __init__(self, parent, name, _stat=None, readonly=False):
        assert parent is None or isinstance(parent, VFS_d)

        self._parent = None
        if parent is not None:
            self._parent = weakref.ref(parent)
        self.name = name

        self.readonly  = readonly

        self._checksum = None
        self._stat     = _stat
        self._path     = None
        self._depth    = None

        self._stat_st_size  = None
        self._stat_st_mtime    = None
        self._stat_st_mtime_ns = None

        self._stat_st_mode  = None
        self._stat_st_ctime    = None
        self._stat_st_ctime_ns = None
        self._stat_st_atime    = None
        self._stat_st_atime_ns = None
        self._stat_st_nlink = None

        self._stat_st_dev   = None
        self._stat_st_ino   = None
        self._stat_st_uid   = None
        self._stat_st_gid   = None

    def _parent_recalc(self, data_only=False):
        parent = _vfs_parent(self)
        if parent is None:
            return
        parent._recalc(data_only)

    @property
    def path(self):
        if self._path is None:
            if False: return _vfs_path(self)
            self._path = _vfs_path(self)
        return self._path

    def __str__(self):
        return self.path

    @property
    def depth(self):
        if self._depth is None:
            if False: return _vfs_depth(self)
            self._depth = _vfs_depth(self)
        return self._depth

    def checksums(self):
        if self._checksum is None:
            if self.readonly:
                return {}

            self._parent_recalc(data_only=True)

            if __show_checksum_work__:
                print >>sys.stderr, "JDBG: chksum for:", self.path

            if False: pass
            elif self.isreg:
                self._checksum = _file2hexdigests(self.path)
            elif self.islnk:
                self._checksum = _link2hexdigests(self.path)

            if self._checksum is None: # EPERM or not lnk/reg
                self.size = 0
                self._checksum = _data2hexdigests("")

        return self._checksum

    def async_checksum_beg(self):
        if self._checksum is None:
            if self.readonly:
                return {}

            if False: pass
            elif self.isreg:
                self._checksum = mp_workers.apply_async(_file2hexdigests, (self.path,))
            elif self.islnk:
                self._checksum = mp_workers.apply_async(_link2hexdigests, (self.path,))
            else:
                self.size = 0
                self._checksum = _data2hexdigests("")
                return False

            return True
        return False

    def async_checksum_ready(self):
        if isinstance(self._checksum, multiprocessing.pool.AsyncResult):
            return self._checksum.ready()
        return None

    def async_checksum_end(self):
        if isinstance(self._checksum, multiprocessing.pool.AsyncResult):
            self._parent_recalc(data_only=True)

            self._checksum = self._checksum.get()
            if self._checksum is None: # EPERM
                self.size = 0
                self._checksum = _data2hexdigests("")

    def _delStatVal(self, mem=None):
        self._stat = None
        if mem is not None and hasattr(self, "_stat_" + mem):
            delattr(self, "_stat_" + mem)
    def _getStatStat(self):
        if self._stat is None:
            if self.readonly:
                return None
            if __show_stat_work__:
                print >>sys.stderr, "JDBG: stat for *:", mem, self.path

            self._parent_recalc(data_only=True)

            self._stat = _lstat_f(self.path)
        return self._stat # Can still be None

    def async_stat_beg(self):
        if self._stat is None:
            if self.readonly:
                return None
            self._stat = mp_workers.apply_async(_lstat_f, (self.path,))
            return True
        return False

    def async_stat_ready(self):
        if isinstance(self._stat, multiprocessing.pool.AsyncResult):
            return self._stat.ready()
        return None

    def async_stat_end(self):
        if isinstance(self._stat, multiprocessing.pool.AsyncResult):
            self._stat = self._stat.get()
            self._parent_recalc(data_only=True)

    def _getStatVal(self, mem, zero=0):
        _res = getattr(self, "_stat_" + mem)
        if _res is not None:
            return _res

        _stat = self._getStatStat()
        if _stat is None:
            return zero
        return getattr(self._stat, mem)
    def _setStatVal(self, mem, val):
        setattr(self, "_stat_" + mem, val)
    def _getSize(self): # So we can override it
        if False:
            return self._getStatVal("st_size")
        if self._stat_st_size is not None:
            return self._stat_st_size

        _stat = self._getStatStat()
        if _stat is None:
            return 0
        return _stat.st_size
    size = property(fget=lambda self:     self._getSize(),
                    fset=lambda self,val: self._setStatVal("st_size", val),
                    fdel=lambda self:     self._delStatVal("st_size"),
                    doc="Size of the the file (cached)")
    st_atime = property(fget=lambda self: int(self._getStatVal("st_atime")),
                        fset=lambda self,val: self._setStatVal("st_atime", val),
                        fdel=lambda self:     self._delStatVal("st_atime"),
                        doc="Access time of the file (cached)")
    def _getStatAtimens(self):
        if self._stat_st_atime_ns is not None:
            return int(self._stat_st_atime_ns)

        if pylstat is None:
            return self.st_atime * _s2ns

        _stat = self._getStatStat()
        if _stat is None:
            return self.st_atime * _s2ns
        return _stat.st_atime_ns
    st_atime_ns = property(fget=lambda self: self._getStatAtimens(),
                     fset=lambda self,val: self._setStatVal("st_atime_ns", val),
                     fdel=lambda self:     self._delStatVal("st_atime_ns"),
                           doc="Access time of the file in nanoseconds(cached)")
    def _getStatCtime(self):
        if self._stat_st_ctime is not None:
            return int(self._stat_st_ctime)

        _stat = self._getStatStat()
        if _stat is None:
            return 0
        return int(_stat.st_ctime)
    st_ctime = property(fget=lambda self:     self._getStatCtime(),
                        fset=lambda self,val: self._setStatVal("st_ctime", val),
                        fdel=lambda self:     self._delStatVal("st_ctime"),
                        doc="Change time of the file (cached)")
    def _getStatCtimens(self):
        if self._stat_st_ctime_ns is not None:
            return int(self._stat_st_ctime_ns)

        if pylstat is None:
            return self.st_ctime * _s2ns

        _stat = self._getStatStat()
        if _stat is None:
            return self.st_ctime * _s2ns
        return _stat.st_ctime_ns
    st_ctime_ns = property(fget=lambda self: self._getStatCtimens(),
                     fset=lambda self,val: self._setStatVal("st_ctime_ns", val),
                     fdel=lambda self:     self._delStatVal("st_ctime_ns"),
                          doc="Change time of the file in nanoseconds (cached)")
    def _getStatMtime(self):
        if self._stat_st_mtime is not None:
            return int(self._stat_st_mtime)

        _stat = self._getStatStat()
        if _stat is None:
            return 0
        return int(_stat.st_mtime)
    mtime = property(fget=lambda self:     self._getStatMtime(),
                     fset=lambda self,val: self._setStatVal("st_mtime", val),
                     fdel=lambda self:     self._delStatVal("st_mtime"),
                     doc="Modified time of the file (cached)")
    def _getStatMtimens(self):
        if self._stat_st_mtime_ns is not None:
            return int(self._stat_st_mtime_ns)

        if pylstat is None:
            return self.mtime * _s2ns

        _stat = self._getStatStat()
        if _stat is None:
            return self.mtime * _s2ns
        return _stat.st_mtime_ns
    mtime_ns = property(fget=lambda self:     self._getStatMtimens(),
                     fset=lambda self,val: self._setStatVal("st_mtime_ns", val),
                     fdel=lambda self:     self._delStatVal("st_mtime_ns"),
                        doc="Modified time of the file in nanoseconds (cached)")
    st_ino = property(fget=lambda self:     self._getStatVal("st_ino"),
                      fset=lambda self,val: self._setStatVal("st_ino", val),
                      fdel=lambda self:     self._delStatVal("st_ino"),
                      doc="Inode of the file (cached)")
    st_dev = property(fget=lambda self:     self._getStatVal("st_dev"),
                      fset=lambda self,val: self._setStatVal("st_dev", val),
                      fdel=lambda self:     self._delStatVal("st_dev"),
                      doc="Device of the file (cached)")
    st_nlink = property(fget=lambda self:     self._getStatVal("st_nlink"),
                        fset=lambda self,val: self._setStatVal("st_nlink", val),
                        fdel=lambda self:     self._delStatVal("st_nlink"),
                        doc="Number of links to the file (cached)")
    st_mode = property(fget=lambda self:     self._getStatVal("st_mode"),
                       fset=lambda self,val: self._setStatVal("st_mode", val),
                       fdel=lambda self:     self._delStatVal("st_mode"),
                       doc="Mode of the file (cached)")
    st_uid = property(fget=lambda self:     self._getStatVal("st_uid"),
                      fset=lambda self,val: self._setStatVal("st_uid", val),
                      fdel=lambda self:     self._delStatVal("st_uid"),
                      doc="UID of the file (cached)")
    st_gid = property(fget=lambda self:     self._getStatVal("st_gid"),
                      fset=lambda self,val: self._setStatVal("st_gid", val),
                      fdel=lambda self:     self._delStatVal("st_gid"),
                      doc="GID of the file (cached)")
    @property
    def isdir(self):
        return stat.S_ISDIR(self.st_mode)
    @property
    def islnk(self):
        return stat.S_ISLNK(self.st_mode)
    @property
    def isreg(self):
        return stat.S_ISREG(self.st_mode)


def _vfsd_size(vfsd):
    size = 0
    for vfs in vfsd:
        size += vfs.size
    return size

def _vfsd_num(vfsd):
    num = 0
    for vfs in vfsd:
        if isinstance(vfs, VFS_d):
            num += vfs.num
        num += 1
    return num

def _vfsd_checksum(vfsd):
    ret = Checksums(_available_checksums)
    for vfs in vfsd:
        ret.update(vfs.name)
        ret.update(' ')
        ret.update_dict(vfs.checksums())
        ret.update('\n')
    return ret.hexdigests()

class VFS_d(VFS_f):
    __slots__ = ['nodes', '_num', '__weakref__']

    def __init__(self, parent, name, _stat=None, readonly=False):
        VFS_f.__init__(self, parent, name, _stat, readonly)

        self.nodes = {}

        self._num          = None
        # self._checksum     = None
        # self._stat_st_size = None

    def _recalc(self, data_only=False):
        self._checksum     = None
        if not data_only:
            self._num      = None
        self._stat_st_size = None

        self._parent_recalc(data_only)

    def add(self, vfs):
        # assert vfs.parent is self
        self.nodes[vfs.name] = vfs
        self._recalc()

    def xremove(self, vfs):
        # assert vfs.parent is self
        del self.nodes[vfs.name]
        self._recalc()

    def __iter__(self):
        return (self.nodes[x] for x in sorted(self.nodes.keys(), cmp=_fcmp))

    def checksums(self):
        if self._checksum is None:
            if __show_checksum_work__:
                print >>sys.stderr, "JDBG: chksum for D:", self.path
            self._parent_recalc(data_only=True)
            self._checksum = _vfsd_checksum(self)
            if __show_checksum_work__:
                print >>sys.stderr, "JDBG: chksum for D:", self._checksum
        return self._checksum

    def async_checksum_beg(self):
        return False
    def async_checksum_ready(self):
        return False
    def async_checksum_end(self):
        pass

    # @property
    # def size(self):
    def _getSize(self):
        if self._stat_st_size is None:
            self._parent_recalc(data_only=True)
            self._stat_st_size = _vfsd_size(self)
        return self._stat_st_size

    @property
    def num(self):
        if self._num is None:
            self._parent_recalc()
            self._num = _vfsd_num(self)
        return self._num


def _path2names(path):
    names = path.split('/')
    if names[0] == '':
        assert path[0] == '/'
        names[0] = '/'
    return names

def _names2parent(roots, names, readonly=False):
    parent = None
    for name in names[:-1]:
        if parent is None:
            if name not in roots:
                roots[name] = VFS_d(None, name, readonly=readonly)
            parent = roots[name]
        else:
            if name not in parent.nodes:
                parent.add(VFS_d(parent, name, readonly=readonly))
            parent = parent.nodes[name]
    return parent

def _name2vfs(roots, parent, T, name, readonly=False):
    vfs = None
    if parent is None:
        if name in roots:
            vfs = roots[name]
    else:
        if name in parent.nodes:
            vfs = parent.nodes[name]

    if vfs is not None: pass
    elif T == 'd':
        vfs = VFS_d(parent, name, readonly=readonly)
    elif T == 'f':
        vfs = VFS_f(parent, name, readonly=readonly)
    elif T == 'l':
        vfs = VFS_f(parent, name, readonly=readonly)
    else:
        assert False, "Bad type."

    if parent is None:
        roots[name] = vfs
    else:
        parent.nodes[name] = vfs
    return vfs

def _root2useful(root):
    """ Move fwd from a root to the first useful dir. """
    while len(root.nodes) == 1:
        nroot = root.nodes.values()[0]
        if not isinstance(nroot, VFS_d):
            break
        root = nroot
    return root

def find_node(root, path):
    """ Like the above, but doesn't build anything new just returns None. """
    if root is None:
        return None

    names = [p for p in path.split('/') if p != '']
    if path[0] == '/':
        names.insert(0, '/') # Removed due to magic above.

    if names[0] == root.name:
        names = names[1:]
        if not names:
            return root
    # elif root.name != '/': # Allow first / to be dropped.
    else: # Allow leading blanks to be dropped.
        while len(root.nodes) == 1 and isinstance(root.nodes.values()[0], VFS_d):
            if names[0] in root.nodes:
                break
            root = root.nodes.values()[0]

        if len(root.nodes) != 1 or names[0] not in root.nodes:
            print >>sys.stderr, "JDBG:", names[0], "!=", root.name
            return None

    vfs = root
    for name in names:
        if not isinstance(vfs, VFS_d):
            return None
        if name not in vfs.nodes:
            print >>sys.stderr, "JDBG:", name, "not in", vfs.name
            return None
        vfs = vfs.nodes[name]
    return vfs

# Unicode Block Elements
# http://www.fileformat.info/info/unicode/block/block_elements/utf8test.htm
_filblok_left2right = (
        '\xe2\x96\x8f',
        '\xe2\x96\x8e',
        '\xe2\x96\x8d',
        '\xe2\x96\x8c',
        '\xe2\x96\x8b',
        '\xe2\x96\x8a',
        '\xe2\x96\x89',
        '\xe2\x96\x88')
_filblok_shade = (
        '\xe2\x96\x91',
        '\xe2\x96\x92',
        '\xe2\x96\x93',
        '\xe2\x96\x88')
_filblok_down2up = (
        '\xe2\x96\x81',
        '\xe2\x96\x82',
        '\xe2\x96\x83',
        '\xe2\x96\x84',
        '\xe2\x96\x85',
        '\xe2\x96\x86',
        '\xe2\x96\x87',
        '\xe2\x96\x88')
_filblok_ascii = ('-', '=')

def _term_add_bar(bar_max_length, pc):
    if pc < 0: pc = 0
    if pc > 1: pc = 1

    blen = bar_max_length
    num = int(blen * pc)

    if sys.stdout.encoding == 'UTF-8':
        fil = _filblok_left2right
        # fil = _filblok_down2up
        # fil = _filblok_shade
    else:
        fil = _filblok_ascii

    bar  = fil[-1] * num
    rem = (blen * pc) - int(blen * pc)
    # rem is between 0 and 1, Eg. 0.1234
    # See how many elements of fil we can use, should be between 0 and len-1.
    rem = int(rem / (1.0 / len(fil)))
    if rem:
        bar += fil[rem-1]
        num += 1
    bar += ' ' * (blen - num)

    return '[%s]' % bar

def shorten_text(text, size):
    if len(text) <= size:
        return text
    half = size / 2
    size -= half

    el = "..."
    els = 3
    if sys.stdout.encoding == 'UTF-8':
        el = '\xe2\x80\xa6'
        els = 1
    if half > els:
        half -= els
        return text[:half] + el + text[-size:]
    return text[:half] + text[-size:]

class Prog:
    def __init__(self, prefix, total, output_func=None, every=1, elapse=0.25):
        self.prefix = prefix
        self.total  = total
        self.output_func = output_func
        self.every = every
        self.elapse = elapse

        self._tm_beg  = time.time()
        self._tm_last = self._tm_beg + 0.1

        self._last_num = 0
        self._last_tm  = 0

        if self.output_func is None:
            self.output_func = lambda x: x

    def _chk(self, num):
        if num == self.total:
            self._last_num = num
            self._last_tm  = time.time()
            return True

        if num - self._last_num < self.every:
            return False

        now = time.time()
        if now - self._last_tm < self.elapse:
          return False

        self._last_num = num
        self._last_tm  = now
        return True

    def progress_up(self, num, val):
        if not self._chk(num):
            return
        text = self.output_func(val)

        mnum = max(3, len(_ui_num(num)))
        left = 79 - (len(self.prefix) + mnum + 3 + mnum + 1)
        text = shorten_text(text, left)
        secs = self._last_tm - self._tm_beg
        print '%s%*s/s %*s %-*s\r' % (self.prefix, mnum, _ui_num_s(num, secs),
                                      mnum, _ui_num(num), left, text),
        sys.stdout.flush()

    def progress(self, num, val):
        if not self._chk(num):
            return
        text = self.output_func(val)

        ui_tot = _ui_num(num) # self.total)
        mnum = len(ui_tot)
        left = 79 - (len(self.prefix) + mnum + 3 + mnum + 1 + 3 + 2 + 18 + 1)
        text = shorten_text(text, left)
        perc = float(num) / float(self.total)
        textperc = _term_add_bar(16, perc)
        perc = int(100 * perc)
        secs = self._last_tm - self._tm_beg

        print '%s%*s/s %*s %3u%% %s %-*s\r' % (self.prefix,
                                               mnum, _ui_num_s(num, secs), mnum,
                                               ui_tot, perc,
                                               textperc, left, text),
        sys.stdout.flush()


    def end(self):
        print ' ' * 79, '\r',
        sys.stdout.flush()
        self._last_num = 0
        self._last_tm  = 0

def _ui_path(vfs):
    if False:
        return vfs.path.replace('\\', '\\\\').replace('\n', '\\n')

    nodes = [vfs]
    while _vfs_parent(nodes[-1]) is not None:
        nodes.append(_vfs_parent(nodes[-1]))
    while len(nodes) >= 2 and len(nodes[-1].nodes) == 1:
        nodes.pop()

    path = ''
    if len(nodes) != 1:
        if nodes[-1].name == '/':
            path = '/'
            nodes.pop()
        while len(nodes) >= 2:
            path += nodes.pop().name + '/'
    path += nodes[0].name
    return path.replace('\\', '\\\\').replace('\n', '\\n')

def _walk_(vfsd, ui, progress):
    " Internal Worker. "
    for (fn, T, ino) in _readdir_f(vfsd.path, ignore_EACCES=True):
        if T not in ('DIR', 'REG', 'LNK', 'UNKNOWN'):
            continue

        if False: pass
        elif T == 'DIR':
            isdir = True
            vfs = VFS_d(vfsd, fn)
        else:
            isdir = False
            vfs = VFS_f(vfsd, fn)
            if T == 'UNKNOWN':
                if vfs.isdir: # This requires a stat.
                    isdir = True
                    vfs = VFS_d(vfsd, vfs.name, vfs._stat) # hack so no stat 2x
                elif not (vfs.islnk or vfs.isreg):
                    continue

        vfsd.add(vfs)

        if isdir:
            _walk_(vfs, ui, progress)
        if progress is not None:
            progress[0] += 1
            progress[1].progress_up(progress[0], vfsd)

def _walk(vfsd, ui=False):
    """ Walk the FS, adding nodes for each. """
    progress = None
    if ui:
        progress = [0, Prog("Walk: ", 0, _ui_path)]
    _walk_(vfsd, ui, progress)
    if progress is not None:
        progress[1].end()

def _valid_cached_dirs(vfsd, verbose=False):
    ret = True

    size = _vfsd_size(vfsd)
    if size != vfsd.size:
        if verbose:
            print >>sys.stderr, "Err: Dir. %s failed size check: %u vs. %u" % (vfsd.name, size, vfsd.size)
        ret = False

    num = _vfsd_num(vfsd)
    if num != vfsd.num:
        if verbose:
            print >>sys.stderr, "Err: Dir. %s failed num check: %u vs. %u" % (vfsd.name, len(vfsd.nodes), vfsd.num)
        ret = False

    chks = _vfsd_checksum(vfsd)
    # Saved version can have different checksums.
    for sumkey in chks:
        if sumkey not in vfsd.checksums():
            continue
        if chks[sumkey] != vfsd.checksums()[sumkey]:
            if verbose:
                msg = "Err: Dir. %s failed checksum-%s check:\n => %s\n => %s"
                msg = msg % (vfsd.name, sumkey, chks[sumkey], vfsd.checksums()[sumkey])
                print >>sys.stderr, msg
            ret = False

    for vfs in vfsd:
        if isinstance(vfs, VFS_d):
            if not _valid_cached_dirs(vfs, verbose=verbose):
                ret = False
    return ret

def _load_p(fn, num, roots, ifo, line):
    sline = line.split(' ', 3)
    if len(sline) != 4:
        print >>sys.stderr, "Can't parse P line %d, in %s\n => %s\n" % (num, fn, line)
        return None
    p,T,size,path = sline

    while int(size) > len(path):
        nline = ifo.next()
        if nline[-1] != '\n':
            print >>sys.stderr, "Can't parse P nline %d, in %s\n => %s" % (num, fn, line)
            return None
        nline = nline[:-1]
        path = path + '\n' + nline
    if int(size) != len(path):
        print >>sys.stderr, "Invalid name line %d, in %s\n => %s\n" % (num, fn, line)
        return None

    if T not in ('d', 'f', 'l'):
        print >>sys.stderr, "Invalid type line %d, in %s\n => %s\n" % (num, fn, line)
        return None

    names = _path2names(path)
    parent = _names2parent(roots, names, readonly=True)
    name = names[-1]
    vfs = _name2vfs(roots, parent, T, name, readonly=True)

    return vfs

_cached_nodes_di = {}
_cached_nodes_ns = {}
_cached_nodes_ps = {}
def _load_cached(vfs): # Cache stuff, note that we only care about checksums
    if vfs is None:
        return

    if vfs._stat_st_size is None:
        return

    if vfs.name not in _cached_nodes_ns:
        _cached_nodes_ns[vfs.name] = {}
    if vfs.size not in _cached_nodes_ns[vfs.name]:
        _cached_nodes_ns[vfs.name][vfs.size] = [vfs]
    elif False:
        last = _cached_nodes_ns[vfs.name][vfs.size][-1]
        if last.checksums() != vfs.checksums():
            _cached_nodes_ns[vfs.name][vfs.size].append(vfs)
    else:
        _cached_nodes_ns[vfs.name][vfs.size].append(vfs)

    if vfs.path not in _cached_nodes_ps:
        _cached_nodes_ps[vfs.path] = {}
    if vfs.size not in _cached_nodes_ps[vfs.path]:
        _cached_nodes_ps[vfs.path][vfs.size] = [vfs]
    else:
        _cached_nodes_ps[vfs.path][vfs.size].append(vfs)

    if vfs._stat_st_dev is None or vfs._stat_st_ino is None:
        return

    if vfs.st_dev not in _cached_nodes_di:
        _cached_nodes_di[vfs.st_dev] = {}
    if vfs.st_ino not in _cached_nodes_di[vfs.st_dev]:
        _cached_nodes_di[vfs.st_dev][vfs.st_ino] = [vfs]
    else:
        _cached_nodes_di[vfs.st_dev][vfs.st_ino].append(vfs)

import gzip
def _load(fn, data_only=False, gunzip=True):
    num = 1
    try:
        if fn.endswith(".gz"):
            fo = gzip.open(fn)
        else:
            fo = open(fn)
    except IOError, e:
        print >>sys.stderr, "open(%s): %s" % (fn, e)
        return None

    line = fo.readline()
    if line not in ("mtree-file-0.1\n", "mtree-file-0.2\n"):
        print >>sys.stderr, "Invalid header line %d, in %s\n => %s" % (num, fn, line)
        return None

    def _read_int0(line, vfs, mem, base=10):
        sline = line.split(' ', 3)
        if len(sline) != 2:
            val = "z"
        else:
            name,val = sline

        try:
            setattr(vfs, mem, int(val, base))
            return True
        except ValueError:
            print >>sys.stderr, "Invalid %s line %d, in %s\n => %s" % (mem, num, fn, sline)
            return False

    def _read_int(line, vfs, mem, base=10):
        sline = line.split(' ', 3)
        if len(sline) != 2:
            val = "z"
        else:
            name,val = sline

        if val.isdigit():
            setattr(vfs, mem, int(val, base))
            return True
        else:
            print >>sys.stderr, "Invalid %s line %d, in %s\n => %s" % (mem, num, fn, sline)
            return False

    def _read_int2(line, vfs, mem, base=10):
        val = line[3:]
        if val.isdigit():
            setattr(vfs, mem, int(val, base))
            return True
        else:
            print >>sys.stderr, "Invalid %s line %d, in %s\n => %s" % (mem, num, fn, sline)
            return False

    roots = {}
    vfs = None
    ifo = iter(fo)
    for line in ifo:
        if line[-1] != '\n':
            print >>sys.stderr, "Can't parse P line %d, in %s\n => %s" % (num, fn, line)
            return None
        line = line[:-1]
        num += 1
        if False: pass
        elif line[0] == 'P' and line[1] == ':':

            _load_cached(vfs)
            vfs = _load_p(fn, num, roots, ifo, line)
            if vfs is None:
                return None

        elif vfs is None:
            print >>sys.stderr, "Excpecting P at line %d, in %s\n => %s\n" % (num, fn, line)
            return None

        elif line[0] == 'C' and line[1] == '-':
            sline = line.split(' ')
            if len(sline) != 2:
                print >>sys.stderr, "Invalid checksum at line %d, in %s\n => %s\n" % (num, fn, line)
                return None
            sum,val = sline

            sum = sum[2:-1]
            if vfs._checksum is None:
                vfs._checksum = {}
            vfs._checksum[sum] = val

        elif line[0] == 'S' and line[1] == ':':
            if False:
                setattr(vfs, "size", int(line[3:]))
            elif False:
                vfs._stat_st_size = int(line[3:])
            elif False:
                val = line[3:]
                if not val.isdigit():
                    print >>sys.stderr, "Invalid size line %d, in %s\n => %s" % (num, fn, sline)
                    return None
                vfs._stat_st_size = int(val)
            elif True:
                try:
                    vfs._stat_st_size = int(line[3:])
                except ValueError:
                    print >>sys.stderr, "Invalid size line %d, in %s\n => %s" % (num, fn, sline)
                    return None

            elif not _read_int2(line, vfs, "size"):
                return None

        elif line[0] == 'M' and line[1] == 'T' and line[2] == ':':
            try:
                sline = line[4:].split('.')
                if False: pass
                elif len(sline) == 1:
                    vfs._stat_st_mtime = int(sline[0])
                elif len(sline) == 2:
                    vfs._stat_st_mtime    = int(sline[0])
                    vfs._stat_st_mtime_ns = int(sline[1])
                    vfs._stat_st_mtime_ns += vfs._stat_st_mtime * _s2ns
            except ValueError:
                print >>sys.stderr, "Invalid mtime line %d, in %s\n => %s" % (num, fn, sline)
                return None
            if True: continue
            if not _read_int(line, vfs, "mtime"):
                return None

        elif data_only:
            continue

        elif line[0] == 'N' and line[1] == 'u' and line[2] == 'm' and line[3] == ':':
            pass

        elif line[0] == 'U' and line[1] == ':':
            try:
                vfs._stat_st_uid = int(line[3:])
            except ValueError:
                print >>sys.stderr, "Invalid uid line %d, in %s\n => %s" % (num, fn, sline)
                return None
            if True: continue
            if not _read_int(line, vfs, "st_uid"):
                return None

        elif line[0] == 'G' and line[1] == ':':
            try:
                vfs._stat_st_gid = int(line[3:])
            except ValueError:
                print >>sys.stderr, "Invalid gid line %d, in %s\n => %s" % (num, fn, sline)
                return None
            if True: continue
            if not _read_int(line, vfs, "st_gid"):
                return None

        elif line[0] == 'D' and line[1] == ':':
            try:
                vfs._stat_st_dev = int(line[3:])
            except ValueError:
                print >>sys.stderr, "Invalid dev line %d, in %s\n => %s" % (num, fn, sline)
                return None
            if True: continue
            if not _read_int(line, vfs, "st_dev"):
                return None

        elif line[0] == 'I' and line[1] == ':':
            try:
                vfs._stat_st_ino = int(line[3:])
            except ValueError:
                print >>sys.stderr, "Invalid ino line %d, in %s\n => %s" % (num, fn, sline)
                return None
            if True: continue
            if not _read_int(line, vfs, "st_ino"):
                return None

        elif line[0] == 'L' and line[1] == ':':
            try:
                vfs._stat_st_nlink = int(line[3:])
            except ValueError:
                print >>sys.stderr, "Invalid nlink line %d, in %s\n => %s" % (num, fn, sline)
                return None
            if True: continue
            if not _read_int(line, vfs, "st_nlink"):
                return None

        elif line[0] == 'M' and line[1] == 'O' and line[2] == ':':
            try:
                vfs._stat_st_mode = int(line[4:], 8)
            except ValueError:
                print >>sys.stderr, "Invalid mode line %d, in %s\n => %s" % (num, fn, sline)
                return None
            if True: continue
            if not _read_int(line, vfs, "st_mode", 8):
                return None

        elif line[0] == 'A' and line[1] == 'T' and line[2] == ':':
            try:
                sline = line[4:].split('.')
                if False: pass
                elif len(sline) == 1:
                    vfs._stat_st_atime = int(sline[0])
                elif len(sline) == 2:
                    vfs._stat_st_atime    = int(sline[0])
                    vfs._stat_st_atime_ns = int(sline[1])
                    vfs._stat_st_atime_ns += vfs._stat_st_atime * _s2ns
            except ValueError:
                print >>sys.stderr, "Invalid atime line %d, in %s\n => %s" % (num, fn, sline)
                return None
            if True: continue
            if not _read_int(line, vfs, "st_atime"):
                return None

        elif line[0] == 'C' and line[1] == 'T' and line[2] == ':':
            try:
                sline = line[4:].split('.')
                if False: pass
                elif len(sline) == 1:
                    vfs._stat_st_atime = int(sline[0])
                elif len(sline) == 2:
                    vfs._stat_st_ctime    = int(sline[0])
                    vfs._stat_st_ctime_ns = int(sline[1])
                    vfs._stat_st_ctime_ns += vfs._stat_st_ctime * _s2ns
            except ValueError:
                print >>sys.stderr, "Invalid ctime line %d, in %s\n => %s" % (num, fn, sline)
                return None
            if True: continue
            if not _read_int(line, vfs, "st_ctime"):
                return None

        else:
            print >>sys.stderr, "Unknown line %d, in %s\n => %s\n" % (num, fn, line)

    _load_cached(vfs)
    return roots

def _1root_load(path, data_only=False):
    if os.path.isdir(path):
        xpath = auto_load_fn(path)
        if xpath is not None: path = xpath
    roots = _load(path, data_only)
    if not roots:
        print >>sys.stderr, "No roots (%s)\n" % path
        return None
    if len(roots) > 1:
        print >>sys.stderr, "Multiple roots (%s): %s\n" % (path, ", ".join(roots.keys()))
        return None
    for root in roots:
        return roots[root]
    assert False
    return None

def u_load(path, data_only=False):
    off = path.find('//')
    if off == -1:
        root = _1root_load(path, data_only)
        if root is None:
            return None
        return root, root
    node_path = path[off+2:]
    path = path[:off]

    root = _1root_load(path, data_only)
    if root is None:
        return None

    node = find_node(root, node_path)
    if node is None:
        print >>sys.stderr, "Bad node path:", node_path
        return None
    return root, node

def auto_load_fns(snap_dir):
    try:
        old_snaps = os.listdir(snap_dir)
    except:
        return []
    snap_base = os.path.basename(snap_dir)
    old_snaps = [snap for snap in old_snaps
                 if snap.startswith(snap_base) and
                    (snap.endswith(".mtree") or snap.endswith(".mtree.gz"))]
    if not old_snaps:
        return []
    return sorted(old_snaps, cmp=_snap_cmp)
def auto_load_fn(snap_dir):
    last_snap = auto_load_fns(snap_dir)
    if not last_snap:
        return None
    last_snap = last_snap[-1]
    last_snap = snap_dir + "/" + last_snap
    return last_snap

def _cache_read_ns(vfs, verbose):
    if vfs.name not in _cached_nodes_ns:
        if verbose:
            print >>sys.stderr, "Cache: Name not found:", vfs.name
        return []

    if vfs.size not in _cached_nodes_ns[vfs.name]:
        if verbose:
            print >>sys.stderr, "Cache: Size not found:", vfs.name, vfs.size
        return []
    return _cached_nodes_ns[vfs.name][vfs.size]
def _cache_read_ps(vfs, verbose):
    if vfs.path not in _cached_nodes_ps:
        if verbose:
            print >>sys.stderr, "Cache: Path not found:", vfs.path
        return []

    if vfs.size not in _cached_nodes_ps[vfs.path]:
        if verbose:
            print >>sys.stderr, "Cache: Size not found:", vfs.path, vfs.size
        return []
    return _cached_nodes_ps[vfs.path][vfs.size]
def _cache_read_di(vfs, verbose):
    if vfs.st_dev not in _cached_nodes_di:
        if verbose:
            print >>sys.stderr, "Cache: Dev not found:", vfs.name
        return []
    if vfs.st_ino not in _cached_nodes_di[vfs.st_dev]:
        if verbose:
            print >>sys.stderr, "Cache: Inode not found:", vfs.name
        return []
    return _cached_nodes_di[vfs.st_dev][vfs.st_ino]

def _cache_read_(vfsd, verify_cached="nsm", verbose=False, progress=None):
    if not _cached_nodes_ns:
        return
    for vfs in vfsd:
        if progress is not None:
            progress[1] += 1
            tot = progress[0].num
            progress[2].progress(progress[1], vfs)
        if isinstance(vfs, VFS_d):
            _cache_read_(vfs, verify_cached, verbose, progress)
            # continue # More checks??

        if False: pass

        elif verify_cached in ("ism", "nism", "pism"):
            # Try to use dev/inode
            try_nodes = _cache_read_di(vfs, verbose)
            if _cache_read_chk(vfs, verify_cached, verbose, progress,try_nodes):
                continue
            try_nodes = _cache_read_ns(vfs, verbose)

        elif verify_cached in ("ps", "psm", "pism"):
            # Use path/size
            try_nodes = _cache_read_ps(vfs, verbose)

        else:
            # Don't try dev/inode as we don't have that data here.
            try_nodes = _cache_read_ps(vfs, verbose)
            if _cache_read_chk(vfs, verify_cached, verbose, progress,try_nodes):
                continue
            try_nodes = _cache_read_ns(vfs, verbose)

        _cache_read_chk(vfs, verify_cached, verbose, progress, try_nodes)

def _cache_read_chk(vfs, verify_cached, verbose, progress, try_nodes):
        assert vfs._stat is not None

        if False and len(try_nodes) >= 10:
            progress[2].end()
            print >>sys.stderr, "Cache: lots:", vfs.name, len(try_nodes)
            if len(try_nodes) > 1000: akfjaljfdlajlkdsajf

        found = None
        isd = isinstance(vfs, VFS_d)
        for cvfs in try_nodes:
            if isd != isinstance(cvfs, VFS_d):
                if verbose:
                    print >>sys.stderr, "Cache: dir. vs file:", vfs.path
                continue
            if verify_cached in ("ns", "ps", "nsm", "psm",
                                 "ism", "nism", "pism"):
                if isd: # Dirs.
                    if len(vfs.nodes) != len(cvfs.nodes) or vfs.num != cvfs.num:
                        if verbose:
                            print >>sys.stderr, "Cache: Dir. num:", vfs.path
                        continue
                elif vfs.size != cvfs.size: # Files
                    if verbose:
                        print >>sys.stderr, "Cache: no size:", vfs.path
                    continue
                else:
                    if verbose:
                        print >>sys.stderr, "Cache: size:", vfs.path, vfs.size, cvfs.size
            if verify_cached in ("nsm", "psm", "ism", "nism", "pism"):
                if vfs.mtime != cvfs.mtime:
                    if verbose:
                        print >>sys.stderr, "Cache: no mtime:", vfs.path
                    continue
                if (pylstat is not None and
                     vfs.mtime_ns       != cvfs.mtime_ns and # Valid
                    (vfs.mtime * _s2ns) != cvfs.mtime_ns):   # No NS in cache
                    if verbose:
                        print >>sys.stderr, "Cache: no mtime_ns:", vfs.path
                    continue
            if verify_cached in ("ism", "nism", "pism"):
                if vfs.st_dev != cvfs.st_dev:
                    if verbose:
                        print >>sys.stderr, "Cache: no dev:", vfs.path
                    continue
                if vfs.st_dev != cvfs.st_dev:
                    if verbose:
                        print >>sys.stderr, "Cache: no ino:", vfs.path
                    continue
            if verify_cached in ("ps", "psm", "pism"):
                if vfs.path != cvfs.path:
                    if verbose:
                        print >>sys.stderr, "Cache: no path:", vfs.path
                    continue

            for csum in _available_checksums:
                if csum not in cvfs.checksums():
                    if verbose:
                        print >>sys.stderr, "Cache: no csum:", vfs.path
                    break
            else:
                if verbose:
                    print >>sys.stderr, "Cache: found:", vfs.path, cvfs.path
                if found is not None:
                    if found.checksums() == cvfs.checksums():
                        continue
                    if verbose:
                        print >>sys.stderr, "Cache: multi matches:", found, cvfs
                    found = None
                    break
                found = cvfs
                if True: break # Don't multi search anymore, we have NS time.

        if found is not None:
            vfs._checksum = found.checksums()
            return True
        return False

def _cache_read(vfsd, verify_cached="nsm", verbose=False, ui=False):
    if verbose:
        print >>sys.stderr, "Cache: verify:", verify_cached
    progress = None
    if ui and not verbose:
        progress = [vfsd, 0, Prog("Cache: ", vfsd.num, _ui_path)]
    _cache_read_(vfsd, verify_cached, verbose, progress)
    if progress is not None:
        progress[2].end()

# http://serverfault.com/questions/292014/preferred-format-of-file-names-which-include-a-timestamp
def _sys_time(tm):
    # return time.strftime("%Y%m%dT%H%MZ", time.gmtime(tm))
    return time.strftime("%Y-%m-%d--%H%MZ", time.gmtime(tm))
def _ui_time(tm, nospc=False):
    if nospc:
        return _sys_time(tm)
    return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(tm))

import locale
_used_locale = False
def _ui_lnum(num):
    global _used_locale
    if not _used_locale:
        locale.setlocale(locale.LC_ALL, '')
        _used_locale = True
    return locale.format("%d", int(num), True)

def _ui_num_s(num, sec):
    val = num / sec
    if val <= 10:
        return ("%7.7f" % (float(num) / sec))[:7]
    return _ui_num(val)
def _ui_num(num):
    num = int(num)
    if num < 1000:
        return "%7s" % num

    end = ["K", "M", "G", "T", "P", "E", "Z", "Y"]
    suffix = 0

    while num > (1000*1000):
        num /= 1000
        suffix += 1

    if suffix >= len(end):
        return _ui_lnum(num)

    num = str(num)
    if len(num) ==  4:
        return "  %s.%s%s" % (num[0],   num[1:3], end[suffix])
    if len(num) ==  5:
        return  " %s.%s%s" % (num[0:2], num[2:4], end[suffix])
    if len(num) ==  6:
        return   "%s.%s%s" % (num[0:3], num[3:5], end[suffix])

    assert False
    return num

_ui_rwx = ["---", "--x", "-w-", "-wx",
           "r--", "r-x", "rw-", "rwx"]    
def _ui_mode(mode):
    " We ignore everything but symlinks/dirs/reg. """
    e = (mode & 0006)
    g = (mode & 0060) >> 3
    u = (mode & 0600) >> 6
    return _ui_rwx[u] + _ui_rwx[g] + _ui_rwx[e]

primary_checksum = None
primary_checksum_ui_len = 16
def _prnt_vfs(fo, vfs, info=False, ui=False, tree=False, size_prefix=''):

    def _maybe_ui(val, func):
        if not ui:
            return val
        return func(val)
    def _muin(val):
        return _maybe_ui(val, _ui_num)
    def _muil(val):
        return _maybe_ui(val, _ui_lnum)
    def _muit(val, valns):
        ret = _maybe_ui(val, _ui_time)
        if pylstat is not None:
            valns -= val * _s2ns
            if valns:
                ret = str(ret) + ".%09u" % valns
        return ret

    assert info is not None

    if not info:
        chksum = vfs.checksums()[primary_checksum]
        fn = vfs.path
        if ui:
            chksum = chksum[:primary_checksum_ui_len]
        if tree:
            if not vfs.depth:
                fn = vfs.name
            else:
                indent = ' |  ' * (vfs.depth - 1) + ' \\_ '
                fn = indent + vfs.name
        if ui and isinstance(vfs, VFS_d) and _vfs_parent(vfs) is not None:
            fn = fn + '/'
        fo.write("%s %s%s %s\n" % (chksum, size_prefix, _muin(vfs.size), fn))
        return

    if 'p' not in info: 
        pass
    elif vfs.isdir:
        fo.write("%s %s %d %s\n" % ('P:', 'd', len(vfs.path), vfs.path))
    elif vfs.islnk:
        fo.write("%s %s %d %s\n" % ('P:', 'l', len(vfs.path), vfs.path))
    elif vfs.isreg:
        fo.write("%s %s %d %s\n" % ('P:', 'f', len(vfs.path), vfs.path))
    elif not vfs.st_mode:
        print >>sys.stderr, "Skip:", vfs.path
        return
    else:
        print >>sys.stderr, "JDBG:", "BAD:", vfs.path, vfs.st_mode
        return

    if 'name' in info:
        fo.write("%s %s\n" % ('Name:', vfs.name))

    if 'c' in info:
        for csum in sorted(vfs.checksums()):
            fo.write('C-%s: %s\n' % (csum, vfs.checksums()[csum]))
    if 's' in info:
        fo.write("%s %s\n"  % ('S:',  _muin(vfs.size)))
    if 'num' in info:
        if isinstance(vfs, VFS_d):
            fo.write("%s %s %s\n"  % ('Num:',  _muil(len(vfs.nodes)), _muil(vfs.num)))
    if 'mt' in info:
        fo.write("%s %s\n"  % ('MT:', _muit(vfs.mtime, vfs.mtime_ns)))

    if 'u' in info:
        fo.write("%s %d\n"  % ('U:',  vfs.st_uid))
    if 'g' in info:
        fo.write("%s %d\n"  % ('G:',  vfs.st_gid))
    if 'd' in info:
        fo.write("%s %d\n"  % ('D:',  vfs.st_dev))
    if 'i' in info:
        fo.write("%s %d\n"  % ('I:',  vfs.st_uid))
    if 'l' in info:
        fo.write("%s %s\n"  % ('L:',  _muil(vfs.st_nlink)))
    if 'mo' in info:
        if ui:
            fo.write("%s %#o (%s)\n" % ('MO:', vfs.st_mode, _ui_mode(vfs.st_mode)))
        else:
            fo.write("%s %#o\n" % ('MO:', vfs.st_mode))
    if 'at' in info:
        fo.write("%s %s\n"  % ('AT:', _muit(vfs.st_atime, vfs.st_atime_ns)))
    if 'ct' in info:
        fo.write("%s %s\n"  % ('CT:', _muit(vfs.st_ctime, vfs.st_ctime_ns)))

def _prnt_vfsd(fo, vfsd, info=False, ui=False, tree=False):
    _prnt_vfs(fo, vfsd, info, ui, tree)
    if not isinstance(vfsd, VFS_d):
        return

    for vfs in vfsd:
        _prnt_vfsd(fo, vfs, info, ui, tree)

def _walk_checksum_vfsd_prop(vfsd):
    " Internal Worker. "
    ret = False
    if vfsd._checksum is None:
        ret = True

    if isinstance(vfsd, VFS_d):
        for vfs in vfsd:
            if _walk_checksum_vfsd_prop(vfs):
                ret = True
    if ret:
        vfsd._parent_recalc(data_only=True)
    return ret

def _walk_checksum_vfsd_calc(vfsd, progress):
    " Internal Worker. "
    if vfsd._checksum is not None:
        return

    progress[0] += 1
    if isinstance(vfsd, VFS_d):
        for vfs in vfsd:
            _walk_checksum_vfsd_calc(vfs, progress)
    else:
        progress[0] += vfsd.size

def _walk_checksum_vfsd_(vfsd, ui, progress):
    " Internal Worker. "
    if vfsd._checksum is not None:
        return

    if isinstance(vfsd, VFS_d):
        for vfs in vfsd:
            _walk_checksum_vfsd_(vfs, ui, progress)

    if progress is not None:
        progress[1] += 1
        if not isinstance(vfsd, VFS_d):
            half = int(vfsd.size / 2)
            progress[1] += half
        progress[2].progress(progress[1], vfsd)
        if not isinstance(vfsd, VFS_d):
            progress[1] += vfsd.size - half
    vfsd.checksums()

def _walk_checksum_vfsd(vfsd, ui=False):
    """ Walk the tree and ask for checksums. """
    _walk_checksum_vfsd_prop(vfsd)
    progress = None
    if ui:
        progress = [0]
        _walk_checksum_vfsd_calc(vfsd, progress)
        progress = [progress[0], 0, Prog("Sum: ", progress[0], _ui_path)]
    _walk_checksum_vfsd_(vfsd, ui, progress)
    if progress is not None:
        progress[2].end()

def _walk_checksum_vfsd_mpb_(vfsd, ui, progress, working):
    " Internal Worker. "
    if vfsd._checksum is not None:
        return

    if isinstance(vfsd, VFS_d):
        for vfs in vfsd:
            _walk_checksum_vfsd_mpb_(vfs, ui, progress, working)

    if progress is not None:
        progress[1] += 1
        if not isinstance(vfsd, VFS_d):
            half = int(vfsd.size / 2)
            progress[1] += half
        tot = progress[0]
        progress[2].progress(progress[1], vfsd)

    if not vfsd.async_checksum_beg():
        if progress is not None:
            if not isinstance(vfsd, VFS_d):
                half = int(vfsd.size / 2)
                progress[1] += vfsd.size - half
        return

    working.append(vfsd)
    if len(working) > max(mp_worker_num, 256):
        while working and working[0].async_checksum_ready():
            ovfsd = working.pop(0)
            if progress is not None:
                if not isinstance(ovfsd, VFS_d):
                    half = int(ovfsd.size / 2)
                    progress[1] += ovfsd.size - half
            ovfsd.async_checksum_end()

def _walk_checksum_vfsd_mpe_(vfsd, ui, progress, working):
    for ovfsd in working:
        ovfsd.async_checksum_end()
        if progress is not None:
            if not isinstance(ovfsd, VFS_d):
                half = int(ovfsd.size / 2)
                progress[1] += ovfsd.size - half
            tot = progress[0]
            progress[2].progress(progress[1], ovfsd)

def _walk_checksum_vfsd_mp(vfsd, ui=False):
    """ Walk the tree and ask for checksums. """
    _walk_checksum_vfsd_prop(vfsd)
    progress = None
    if ui:
        progress = [0]
        _walk_checksum_vfsd_calc(vfsd, progress)
        progress = [progress[0], 0, Prog("SumMP: ", progress[0], _ui_path)]
    working = []
    _walk_checksum_vfsd_mpb_(vfsd, ui, progress, working)
    _walk_checksum_vfsd_mpe_(vfsd, ui, progress, working)

    if progress is not None:
        progress[2].end()

def _walk_stat_vfsd_(vfsd, ui, progress):
    " Internal Worker. "
    if isinstance(vfsd, VFS_d):
        for vfs in vfsd:
            _walk_stat_vfsd_(vfs, ui, progress)

    if progress is not None:
        progress[0] += 1
        progress[1].progress(progress[0], vfsd)
    vfsd.mtime

def _walk_stat_vfsd(vfsd, ui=False):
    """ Walk the tree and ask for stat data. """
    progress = None
    if ui:
        progress = [0, Prog("Stat: ", vfsd.num, _ui_path)]
    _walk_stat_vfsd_(vfsd, ui, progress)
    if progress is not None:
        progress[1].end()

def _walk_stat_vfsd_mpb_(vfsd, ui, progress, working):
    " Internal Worker. "
    if isinstance(vfsd, VFS_d):
        for vfs in vfsd:
            _walk_stat_vfsd_mpb_(vfs, ui, progress, working)

    if progress is not None:
        progress[1] += 1
        progress[2].progress(progress[1], vfsd)
    vfsd.async_stat_beg()

def _walk_stat_vfsd_mpe_(vfsd, ui, progress, working):
    " Internal Worker. "
    assert not working
    if isinstance(vfsd, VFS_d):
        for vfs in vfsd:
            _walk_stat_vfsd_mpe_(vfs, ui, progress, working)
 
    if progress is not None:
        progress[1] += 1
        progress[2].progress(progress[1], vfsd)
    vfsd.async_stat_end()

def _walk_stat_vfsd_mpex_(vfsd, ui, progress, working, lim=0, ready=True):
    " Internal Worker. "
    if len(working) > lim:
        while working and (ready or working[0].async_stat_ready()):
            ovfsd = working.pop(0)
            ovfsd.async_stat_end()
            if progress is not None:
                progress[1] += 1
                progress[2].progress(progress[1], vfsd)

def _walk_stat_vfsd_mpbx_(vfsd, ui, progress, working):
    " Internal Worker. "
    if isinstance(vfsd, VFS_d):
        for vfs in vfsd:
            _walk_stat_vfsd_mpbx_(vfs, ui, progress, working)

    if progress is not None:
        progress[1] += 1
        progress[2].progress(progress[1], vfsd)

    if not vfsd.async_stat_beg():
        if progress is not None:
            progress[1] += 1
        return

    working.append(vfsd)
    _walk_stat_vfsd_mpex_(vfsd, ui, progress, working,
                          lim=max(mp_worker_num, 256), ready=False)

def _walk_stat_vfsd_mp(vfsd, ui=False):
    """ Walk the tree and ask for stat data. """
    progress = None
    if ui:
        progress = [vfsd, 0, Prog("StatMP: ", vfsd.num * 2, _ui_path)]
    working = []
    _walk_stat_vfsd_mpbx_(vfsd, ui, progress, working)
    _walk_stat_vfsd_mpex_(vfsd, ui, progress, working)
    if progress is not None:
        progress[2].end()

def _cmp_chksum_eq(vfs1, vfs2):
    vfs1chk = vfs1.checksums()[primary_checksum]
    vfs2chk = vfs2.checksums()[primary_checksum]
    return vfs1chk == vfs2chk

last_matched_chop_num = 8
last_matched_chop_ctx = 2
assert last_matched_chop_ctx*2 < last_matched_chop_num
last_matched = []
last_matched_chop  = True
_prnt_diff_dir_mod = True
_prnt_diff_reg_mod = True

def _diff_tst_prnt_eq(fo, vfs, ui, tree):
    _prnt_vfs(fo, vfs, info=False, ui=ui, tree=tree, size_prefix=' ')

def _diff_tst_last_matched_eq(fo, vfs, ui, tree):
    if not last_matched_chop:
        _diff_tst_prnt_eq(fo, vfs, ui, tree)
        return

    if len(last_matched) > last_matched_chop_num:
        last_matched.pop(-last_matched_chop_ctx-1)
    last_matched.append(vfs)

def _diff_tst_last_matched_prnt(fo, ui, tree):
    global last_matched

    if not last_matched:
        return

    if len(last_matched) >= last_matched_chop_num:
        for vfs in last_matched[:last_matched_chop_ctx]:
            _diff_tst_prnt_eq(fo, vfs, ui, tree)
        fo.write("[...]\n")
        for vfs in last_matched[-last_matched_chop_ctx:]:
            _diff_tst_prnt_eq(fo, vfs, ui, tree)
        # last_matched[:] = []
        last_matched = []

    for vfs in last_matched:
        _diff_tst_prnt_eq(fo, vfs, ui, tree)
    # last_matched[:] = []
    last_matched = []

def _diff_tst_prnt_mod(fo, tst, vfs1, vfs2, ui, tree):
    _diff_tst_last_matched_prnt(fo, ui, tree)
    if tst:
        _prnt_vfs(fo, vfs2, info=False, ui=ui, tree=tree, size_prefix='!')
    else:
        _prnt_vfs(fo, vfs1, info=False, ui=ui, tree=tree, size_prefix='-')
        _prnt_vfs(fo, vfs2, info=False, ui=ui, tree=tree, size_prefix='+')

def _prnt_diff_vfsds_(fo, vfsd1, vfsd2, ui=True, tree=False):
    info = False

    if _cmp_chksum_eq(vfsd1, vfsd2):
        _diff_tst_last_matched_eq(fo, vfsd2, tree)
        return

    _diff_tst_prnt_mod(fo, _prnt_diff_dir_mod, vfsd1, vfsd2, ui, tree)

    vfss1 = list(reversed(list(iter(vfsd1))))
    vfss2 = list(reversed(list(iter(vfsd2))))

    last_matched = []

    while vfss1 and vfss2:
        vfs1 = vfss1[-1]
        vfs2 = vfss2[-1]
        if vfs1.name != vfs2.name:
            _diff_tst_last_matched_prnt(fo, ui, tree)
            # print "JDBG:", vfs1.name, vfs2.name, _fcmp(vfs1.name, vfs2.name)
            if _fcmp(vfs1.name, vfs2.name) < 0:
                _prnt_vfs(fo, vfs1, info, ui, tree=tree, size_prefix='-')
                vfss1.pop()
            else:
                _prnt_vfs(fo, vfs2, info, ui, tree=tree, size_prefix='+')
                vfss2.pop()
            continue

        # At this point we have two nodes with the same name.
        vfss1.pop()
        vfss2.pop()

        if _cmp_chksum_eq(vfs1, vfs2):
            _diff_tst_last_matched_eq(fo, vfs2, ui, tree)
            continue

        # At this point both exist in the tree and are different.
        if not isinstance(vfs1, VFS_d) or not isinstance(vfs2, VFS_d):
            _diff_tst_prnt_mod(fo, _prnt_diff_reg_mod, vfs1, vfs2, ui, tree)
            continue

        _prnt_diff_vfsds_(fo, vfs1, vfs2, ui, tree)

    if vfss1 or vfss2:
        _diff_tst_last_matched_prnt(fo, ui, tree)
    for vfs1 in reversed(vfss1):
        _prnt_vfs(fo, vfs1, info, ui, tree=tree, size_prefix='-')
    for vfs2 in reversed(vfss2):
        _prnt_vfs(fo, vfs2, info, ui, tree=tree, size_prefix='+')

def _prnt_diff_vfsds(fo, vfsd1, vfsd2, ui=True, tree=False):
    _prnt_diff_vfsds_(fo, vfsd1, vfsd2, ui, tree)
    _diff_tst_last_matched_prnt(fo, ui, tree)

def _ui_prnt_root(root, ui=True, prefix="Root:"):
    assert isinstance(root, VFS_d)

    nnodes = len(root.nodes)
    if ui:
        nnodes = _ui_lnum(nnodes)
    nnum = root.num
    if ui:
        nnum = _ui_lnum(nnum)

    print prefix, root.name, nnodes, nnum
    _prnt_vfs(sys.stdout, root, ui=ui)

def _real_snapfn(snap_fn, auto_load, verify_cached):
    if not os.path.isdir(snap_fn):
        if auto_load and not snap_fn.endswith(".mtree"):
            snap_fn += "-" + _ui_time(time.time(), nospc=True) + ".mtree"
    else:
        _jdbg("auto snap")
        snap_base = os.path.basename(snap_fn)
        auto_cached_root = None
        last_snap = None
        if auto_load:
            _jdbgb("auto loaded")
            last_snap = auto_load_fn(snap_fn)
        if last_snap is not None:
            print "Loading snapshot:", last_snap
            data_only = verify_cached in ("ns", "ps", "nsm", "psm")
            auto_cached_root = u_load(last_snap, data_only)
            _jdbge("auto loaded")
        snap_fn += "/"
        snap_fn += snap_base
        snap_fn += "-" + _ui_time(time.time(), nospc=True) + ".mtree"
    return snap_fn

def _setup_argp(all_cmds):
    import optparse

    epilog = "\n    ".join(["\n\nCOMMANDS:"]+sorted(all_cmds)) + "\n"
    argp = optparse.OptionParser(
            description='Manipulate metadata trees, from the command line',
        version="%prog-" + __version__)
    argp.format_epilog = lambda y: epilog

    argp.add_option('-v',
            '--verbose', default=False, action='store_true',
            help='verbose output from commands')
    argp.add_option('--no-ui',
            dest="ui", action='store_false',
            help='print in mtree format')
    argp.add_option('--ui',
            '--human', dest='ui', default=True, action='store_true',
            help='print in human readable format')
    argp.add_option('--mp',
            dest='mp', default=None, type='int',
            help='use multiprocessing for N CPUs')
    argp.add_option('--no-chop-difference',
            dest="chop_diff", action='store_false',
            help='print full difference')
    argp.add_option('--chop-difference',
            dest="chop_diff", action='store_true', default=True,
            help='print chopped difference')
    argp.add_option('--ui-checksum-length',
            default=None, type='int',
            help='print in human readable format')
    argp.add_option('--no-auto-loading', '--no-automatic-loading',
            dest="auto_load", action='store_false',
            help='No automatic loading when snapshotting to dirs.')
    argp.add_option('--auto-loading', '--automatic-loading',
            dest="auto_load", action='store_true', default=True,
            help='automatic loading when snapshotting to dirs.')
    argp.add_option('-c',
            '--checksums', default="default",
            help='what checksums to use')
    argp.add_option('-V',
            '--verify-cached', default="nsm",
            help='what data do we verify for using cached checksums')
    argp.add_option('-l',
            '--load-mtree', default=[], action="append",
            help='file to load old metadata tree from')
    argp.add_option('--info-fields',
            '--information-fields', dest="info_fields", default="default",
            help='fields to show in info command')
    argp.add_option('--data-only',
            action='store_true', default=False,
            help='use only the data fields for everything, including snaps')
    argp.add_option('--info', dest="info_fields",
            help=optparse.SUPPRESS_HELP)

    return argp, argp.parse_args()

def _setup_arg_mp(opts):
    global mp_worker_num
    global mp_workers

    if opts.mp is None:
        mp_worker_num = _num_cpus_online()
        print "Workers:", mp_worker_num
    elif opts.mp > 0:
        mp_worker_num = opts.mp
    if mp_worker_num:
        mp_workers = multiprocessing.Pool(mp_worker_num)

def _setup_arg_checksum(opts):
    global _available_checksums
    global primary_checksum
    global primary_checksum_ui_len

    if opts.ui_checksum_length > 0:
        primary_checksum_ui_len = opts.ui_checksum_length

    if not opts.checksums:
        if 'md5' in _available_checksums:
            primary_checksum = 'md5'
        else:
            primary_checksum = 'sha1'
    else:
        chks = opts.checksums.split(',')
        if 'all' in chks:
            chks.update(list(_available_checksums))
        nchks = []
        for chk in chks:
            if chk in ('sm', 'small'):
                if 'md5' in _available_checksums:
                    chk = 'md5'
                else:
                    chk = 'sha1'

            if chk in ('def', 'default'):
                if 'md5' in _available_checksums:
                    primary_checksum = chk = 'md5'
                    nchks.extend(['md5', 'sha256', 'sha512'])
                else:
                    primary_checksum = chk = 'sha1'
                    nchks.extend(['sha1', 'sha256', 'sha512'])

            if chk not in _available_checksums:
                print >>sys.stderr, 'Invalid checksum:', chk, 'Supported:', \
                                    ", ".join(_available_checksums)
                sys.exit(1)
            nchks.append(chk)
        _available_checksums = set(nchks)
        primary_checksum = nchks[0]

def _setup_arg_vc(opts):
    _vc_valid = ("all", "data", "default", "ns", "ps", "nsm", "psm",
                 "ism", "nism", "pism")
    if opts.verify_cached not in _vc_valid:
        print >>sys.stderr, 'Invalid Verify:', 'Supported:',", ".join(_vc_valid)
        sys.exit(1)
    if opts.verify_cached == "all":
        opts.verify_cached = "pism"
    if opts.verify_cached == "data":
        opts.verify_cached = "ns"
    if opts.verify_cached == "default":
        opts.verify_cached = "nsm"

def _setup_arg_info(opts):
    _i_valid = set(['p', 'name', 'c', 's', 'num', 'mt',
                    'u', 'g', 'd', 'i', 'l', 'mo', 'at', 'ct'])
    ifields = set()
    # Allish -- no name, still has at. This is the save "format".
    ifields_all = set(['p', 'c', 's', 'num', 'mt',
                       'u', 'g', 'd', 'i', 'l', 'mo', 'at', 'ct'])
    if opts.data_only:
        ifields.update(set(['p', 'c', 's', 'mt'])) # Includes mt, =data doesn't
    for ifield in opts.info_fields.split(","):
        if ifield == 'all':
            ifields.update(ifields_all)
            continue
        if ifield in ('def', 'default'):
            ifields.update(set(['p', 'c', 's', 'num', 'mt', 'mo', 'ct']))
            continue
        if ifield in ('sm', 'small'):
            ifields.update(set(['p', 'c', 's', 'num', 'mt']))
            continue
        if ifield == 'data':
            ifields.update(set(['p', 'c', 's']))
            continue

        if ifield not in _vc_valid:
            print >>sys.stderr, 'Invalid Info. Field:', 'Supported:', ", ".join(_i_valid)
            sys.exit(1)
        ifields.add(ifield)

    return ifields

def _setup_arg_cache_load(opts):
    _cached_roots = {}
    if opts.load_mtree:
        data_only = opts.verify_cached in ("ns", "ps", "nsm", "psm")

        for fn in opts.load_mtree:
            root = u_load(fn, data_only)
            if root is None:
                continue
            rroot,root = root
            _cached_roots[fn] = rroot
        if opts.verbose:
            print >>sys.stderr, "Loaded:", root.num, len(_cached_roots), len(_cached)

    return _cached_roots

__jdbg_print__ = True
_top_beg = time.time()
def _jdbg(arg):
    if not __jdbg_print__:
        return
    print >>sys.stderr, "JDBG: %.4f %s" % (time.time()-_top_beg, arg)
_last_beg = None
def _jdbgb(arg):
    global _last_beg
    if not __jdbg_print__:
        return
    _last_beg = time.time()
    print >>sys.stderr, "JDBG: %6.2f BEG: %s" % (_last_beg-_top_beg, arg)
def _jdbge(arg):
    if not __jdbg_print__:
        return
    print >>sys.stderr, "JDBG: %6.2f      %s" % (time.time()-_last_beg, arg)

def main():
    """ Command line UI to run commands. """
    global prog
    global last_matched_chop
    global mp_worker_num
    global mp_workers

    remap_cmds = {'info' : 'information',
                  'ls' : 'list',
                  'diff' : 'difference',
                  'treediff' : 'tree-difference',
                  'tree-diff' : 'tree-difference',
                  'treedifference' : 'tree-difference',
                  'snap' : 'snapshot',
                  }
    all_cmds = ("summary", "list", "information", "difference",
                "snapshot", "check", "tree", "tree-difference", "resave", "help")

    (argp, (opts, cmds)) = _setup_argp(all_cmds)
    _jdbg("args")

    if argp.prog is not None:
        prog = argp.prog
    elif sys.argv:
        prog = os.path.basename(sys.argv[0])
    else:
        prog = "mtree"

    if opts.verbose:
        global __show_checksum_work__
        __show_checksum_work__ = True
        global __show_stat_work__
        __show_stat_work__ = True
        global _prnt_diff_dir_mod
        global _prnt_diff_reg_mod
        _prnt_diff_dir_mod = False
        _prnt_diff_reg_mod = False

    last_matched_chop = opts.chop_diff

    _setup_arg_checksum(opts)

    _setup_arg_vc(opts)

    ifields = _setup_arg_info(opts)

    _cached_roots = _setup_arg_cache_load(opts)

    cmd = 'unknown'
    if len(cmds) >= 1:
        cmd = remap_cmds.get(cmds[0], cmds[0])
    if cmd not in all_cmds and not cmd.startswith("debug-test-"):
        argp.print_help()
        sys.exit(1)

    _jdbg("cmds")

    errcode = 0
    done = False
    if False: pass

    elif cmd == 'snapshot':
        if len(cmds) < 3:
            print >>sys.stderr, "Format: %s %s <filename> <tree> [...]" % (prog, cmds[0])
            sys.exit(1)

        info = set(['p', 'c', 's', 'num', 'mt',
                    'u', 'g', 'd', 'i', 'l', 'mo', 'at', 'ct'])
        if opts.data_only:
            info = set(['p', 'c', 's', 'mt'])

        snap_fn = _real_snapfn(cmds[1], opts.auto_load, opts.verify_cached)
        print "Creating snapshot:", snap_fn

        try:
         try:
            out = open(snap_fn, "wb")
         except IOError, e:
            print >>sys.stderr, "open(%s): %s" % (snap_fn, e)
            sys.exit(1)

         if pylstat is None:
             out.write("mtree-file-0.1\n")
         else: # Can have NS data in atime/ctime/mtime
             out.write("mtree-file-0.2\n")
         roots = {}
         for path in cmds[2:]:
            if not os.path.isdir(path):
                print >>sys.stderr, "Path is not a directory: %s" % path
                continue

            names = _path2names(path)
            parent = _names2parent(roots, names)
            name = names[-1]

            vfs = _name2vfs(roots, parent, 'd', name)

            _jdbgb("walk")
            _walk(vfs, ui=opts.ui)
            _jdbge("walk")

            # _setup_arg_mp(opts) -- slower :(

            _jdbgb("walk stat")
            if mp_workers is None:
                _walk_stat_vfsd(vfs, ui=opts.ui)
            else:
                _walk_stat_vfsd_mp(vfs, ui=opts.ui)
            _jdbge("walk stat")

            _jdbgb("cached read")
            _cache_read(vfs, opts.verify_cached, opts.verbose, ui=opts.ui)
            _jdbge("cached read")

            _setup_arg_mp(opts)

            _jdbgb("walk checksums")
            if mp_workers is None:
                _walk_checksum_vfsd(vfs, ui=opts.ui)
            else:
                _walk_checksum_vfsd_mp(vfs, ui=opts.ui)
            _jdbge("walk checksums")

            _jdbgb("prnt vfs")
            _prnt_vfs(sys.stdout, vfs, ui=opts.ui)
            _jdbge("prnt vfs")
         if len(roots) == 1:
             _jdbgb("prnt vfsd")
             _prnt_vfsd(out, _root2useful(roots[roots.keys()[0]]), info=info)
             _jdbge("prnt vfsd")
         else:
             print len(roots), roots
        except KeyboardInterrupt, e:
            print >>sys.stderr, "\nRemoving: ", snap_fn
            _unlink_f(snap_fn)
            raise

    elif cmd == 'summary':
        if len(cmds) < 2:
            print >>sys.stderr, "Format: %s %s <filename> [...]" % (prog, cmds[0])
            sys.exit(1)

        for fn in cmds[1:]:
            root = u_load(fn, data_only=True)
            if root is None:
                errcode = 1
                done = True
                if done: print ''
                continue
            # Need to keep real root around due to GC.
            rroot,root = root
            _jdbg("post load")

            if done: print ''
            print "Filename:", fn
            _ui_prnt_root(_root2useful(root), ui=opts.ui)
            done = True

    elif cmd in ('information', 'list', 'tree'):
        if len(cmds) < 2:
            print >>sys.stderr, "Format: %s %s <filename> [...]" % (prog, cmds[0])
            sys.exit(1)

        data_only = False
        if cmd in ('list', 'tree'):
            data_only = True
            ifields = False

        _jdbg("beg")
        for fn in cmds[1:]:
            _jdbgb("load")
            root = u_load(fn, data_only)
            _jdbge("loaded")
            if root is None:
                errcode = 1
                done = True
                if done: print ''
                continue
            # Need to keep real root around due to GC.
            rroot,root = root

            if done: print ''
            done = True
            _jdbg("pre prnt")
            _prnt_vfsd(sys.stdout, _root2useful(root),
                       ifields, ui=opts.ui, tree=cmd=='tree')
        _jdbg("end")

    elif cmd in ('difference', 'tree-difference'):
        if len(cmds) == 2 and os.path.isdir(cmds[1]):
            last_snaps = auto_load_fns(cmds[1])
            if len(last_snaps) >= 2:
                cmds[1:] = [cmds[1] + '/' + last_snaps[-2],
                            cmds[1] + '/' + last_snaps[-1]]
                print "Loading snapshot:", cmds[1]
                print "Loading snapshot:", cmds[2]
        if len(cmds) != 3:
            print >>sys.stderr, "Format: %s %s [<dir>|<filename>] <filename>" % (prog, 
                                                                                 cmds[0])
            sys.exit(1)

        if False:
            roots1 = _load(cmds[1])
            if roots1 is None:
                sys.exit(1)
            roots2 = _load(cmds[2])
            if roots2 is None:
                sys.exit(1)
        else:
            roots1 = {}
            roots2 = {}
            data_only = True
            _jdbgb("load 1")
            roots1[1] = u_load(cmds[1], data_only)
            _jdbge("load 1")
            if roots1[1] is None:
                sys.exit(1)
            _jdbgb("load 2")
            roots2[2] = u_load(cmds[2], data_only)
            _jdbge("load 2")
            if roots2[2] is None:
                sys.exit(1)
            # Need to keep real root around due to GC.
            rroot1,roots1[1] = roots1[1]
            rroot2,roots2[2] = roots2[2]

        _jdbg("diff")

        treecmd = cmd=='tree-difference'
        if len(roots1) == 1 and len(roots2) == 1:
            root1 = roots1.values()[0]
            root2 = roots2.values()[0]

            if _cmp_chksum_eq(root1, root2):
                _ui_prnt_root(_root2useful(root1), ui=opts.ui, prefix="Equal:")
            else:
                _prnt_diff_vfsds(sys.stdout, root1, root2, ui=opts.ui, tree=treecmd)
        else:
            for root1 in sorted(roots1, cmp=_fcmp):
                if done: print ''
                done = True

                if root1 not in roots2:
                    _ui_prnt_root(roots1[root1], ui=opts.ui, prefix="Deleted root:")
                    continue
                root2 = roots2[root1]
                root1 = roots1[root1]
                if _cmp_chksum_eq(root1, root2):
                    _ui_prnt_root(root1, ui=opts.ui, prefix="Equal roots:")
                else:
                    _prnt_diff_vfsds(sys.stdout, root1, root2, tree=treecmd)
            for root2 in sorted(roots2, cmp=_fcmp):
                if root2 in roots1:
                    continue
                if done: print ''
                done = True
                root2 = roots2[root2]
                _ui_prnt_root(root2, ui=opts.ui, prefix="Added root:")
        _jdbg("end")

    elif cmd == 'check':
        if len(cmds) < 2:
            print >>sys.stderr, "Format: %s %s <filename> [...]" % (prog, cmds[0])
            sys.exit(1)

        for fn in cmds[1:]:
            roots = _load(fn)
            if opts.verbose:
                print >>sys.stderr, "JDBG:", roots
            if roots is None:
                errcode = 1
                done = True
                if done: print ''
                continue

            for root in sorted(roots, cmp=_fcmp):
                root = roots[root]
                print "Filename:", fn
                if _valid_cached_dirs(root, verbose=True): # opts.verbose):
                    continue
                if done: print ''
                # FIXME: Print diff?
                _ui_prnt_root(_root2useful(root), ui=opts.ui, prefix="Failed root:")
                done = True

    elif cmd == 'resave':

        if len(cmds) < 3:
            print >>sys.stderr, "Format: %s %s <new-filename> <old-filename>" % (prog, cmds[0])
            sys.exit(1)

        old_root = u_load(cmds[2], opts.data_only)
        if old_root is None:
            sys.exit(1)
            # Need to keep real root around due to GC.
        rroot,old_root = old_root

        info = set(['p', 'c', 's', 'num', 'mt',
                    'u', 'g', 'd', 'i', 'l', 'mo', 'at', 'ct'])
        if opts.data_only:
            info = set(['p', 'c', 's', 'mt'])

        snap_fn = _real_snapfn(cmds[1], opts.auto_load, opts.verify_cached)
        print "Creating snapshot:", snap_fn

        try:
         try:
            out = open(snap_fn, "wb")
         except IOError, e:
            print >>sys.stderr, "open(%s): %s" % (snap_fn, e)
            sys.exit(1)

         if False and pylstat is None: # Should work it out?
             out.write("mtree-file-0.1\n")
         else: # Can have NS data in atime/ctime/mtime
             out.write("mtree-file-0.2\n")
         vfs = old_root

         _jdbgb("prnt vfsd")
         _prnt_vfsd(out, vfs, info=info)
         _jdbge("prnt vfsd")
         _jdbgb("prnt vfs")
         _prnt_vfs(sys.stdout, vfs, ui=opts.ui)
         _jdbge("prnt vfs")
        except KeyboardInterrupt, e:
            print >>sys.stderr, "\nRemoving: ", snap_fn
            _unlink_f(snap_fn)
            raise

    elif cmd == 'debug-test-progress':
        if len(cmds) < 5:
            wait = 1.0
        else:
            wait = int(cmds[4])
        if len(cmds) < 4:
            interval = 1.0
        else:
            interval = int(cmds[3])
        if len(cmds) < 3:
            num = 0.0
        else:
            num = int(cmds[2])
        if len(cmds) < 2:
            total = 100.0
        else:
            total = int(cmds[1])

        p = Prog("PRE", total)
        while num < total:
            p.progress(num, "TEXT")
            time.sleep(wait)
            num += interval

    elif cmd == 'debug-test-walk':
        if len(cmds) < 3:
            T = "pyreaddir"
        else:
            T = cmds[2]
        if len(cmds) < 2:
            path = "."
        else:
            path = cmds[1]

        if T in ("os", "os-nostat"):
            global readdir
            readdir = fake_readdir

        if readdir is fake_readdir:
            print "Using OS walk"
        else:
            assert readdir is pyreaddir.readdir

        if True:
            roots = {}
            names = _path2names(path)
            parent = _names2parent(roots, names)
            name = names[-1]

            vfs = _name2vfs(roots, parent, 'd', name)
            _jdbgb("walk")
            _walk(vfs, ui=opts.ui)
            _jdbge("walk")

        if T not in ("os-nostat", 'nostat'):
            _setup_arg_mp(opts)

            _jdbgb("walk stat")
            if mp_workers is None:
                _walk_stat_vfsd(vfs, ui=opts.ui)
            else:
                _walk_stat_vfsd_mp(vfs, ui=opts.ui)
            _jdbge("walk stat")

            print vfs, vfs.num

    elif cmd == 'help':
        argp.print_help()
        return

    else:
        assert False, "Should be checked above, in all_cmds"       
    sys.exit(errcode)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt, e:
        print >>sys.stderr, "Exiting on C-c."
        sys.exit(1)
