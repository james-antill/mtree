#! /usr/bin/python -tt

__version__ = '0.1.4'
__version_info__ = tuple([ int(num) for num in __version__.split('.')])

import ctypes
import sys

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

def _lstat_f(filename, ignore_EACCES=False):
    """ Call os.lstat(), but don't die if the file isn't there. Returns None. """
    try:
        return os.lstat(filename)
    except OSError, e:
        if e.errno in (errno.ENOENT, errno.ENOTDIR):
            return None
        if ignore_EACCES and e.errno == errno.EACCES:
            return None
        raise
def _listdir_f(dirname, ignore_EACCES=False):
    """ Call os.listdir(), don't die if the dir. isn't readable. Returns []. """
    try:
        return os.listdir(dirname)
    except OSError, e:
        if e.errno in (errno.ENOENT, errno.ENOTDIR, errno.EPERM):
            return []
        if ignore_EACCES and e.errno == errno.EACCES:
            return []
        raise

__show_checksum_work__ = False
__show_stat_work__ = False

def _vfs_parent(vfs):
    if vfs._parent is None:
        return None
    parent = vfs._parent()
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

class VFS_f(object):
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
        self._stat_st_mtime = None

        self._stat_st_mode  = None
        self._stat_st_ctime = None
        self._stat_st_atime = None
        self._stat_st_nlink = None

        self._stat_st_dev   = None
        self._stat_st_ino   = None
        self._stat_st_uid   = None
        self._stat_st_gid   = None

    def _parent_recalc(self):
        parent = _vfs_parent(self)
        if parent is None:
            return
        parent._recalc()

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

            self._parent_recalc()

            if False: pass
            elif self.isreg:
                if __show_checksum_work__:
                    print >>sys.stderr, "JDBG: chksum for F:", self.path
                self._checksum = _file2hexdigests(self.path)
                if self._checksum is None: # EPERM
                    self.size = 0
                    self._checksum = _data2hexdigests("")
            elif self.islnk:
                if __show_checksum_work__:
                    print >>sys.stderr, "JDBG: chksum for L:", self.path
                self._checksum = _link2hexdigests(self.path)
                if self._checksum is None: # EPERM
                    self.size = 0
                    self._checksum = _data2hexdigests("")
            else:
                if __show_checksum_work__:
                    print >>sys.stderr, "JDBG: chksum for *:", self.path
                self._checksum = _data2hexdigests("")
        return self._checksum

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

            self._parent_recalc()

            self._stat = _lstat_f(self.path)
        return self._stat # Can still be None
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
    st_ctime = property(fget=lambda self: int(self._getStatVal("st_ctime")),
                        fset=lambda self,val: self._setStatVal("st_ctime", val),
                        fdel=lambda self:     self._delStatVal("st_ctime"),
                        doc="Change time of the file (cached)")
    def _getStatMtime(self): # For speed?
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
    def __init__(self, parent, name, _stat=None, readonly=False):
        VFS_f.__init__(self, parent, name, _stat, readonly)
        self.nodes = {}

        self._checksum     = None
        self._num          = None
        self._stat_st_size = None

    def _recalc(self):
        self._checksum     = None
        self._num          = None
        self._stat_st_size = None

        self._parent_recalc()

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
            self._parent_recalc()
            self._checksum = _vfsd_checksum(self)
            if __show_checksum_work__:
                print >>sys.stderr, "JDBG: chksum for D:", self._checksum
        return self._checksum

    # @property
    # def size(self):
    def _getSize(self):
        if self._stat_st_size is None:
            self._parent_recalc()
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
                parent.nodes[name] = VFS_d(parent, name, readonly=readonly)
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

def _term_add_bar(bar_max_length, pc):
    if pc < 0: pc = 0
    if pc > 1: pc = 1

    blen = bar_max_length
    bar  = '='*int(blen * pc)
    if (blen * pc) - int(blen * pc) >= 0.5:
        bar += '-'
    return '[%-*.*s]' % (blen, blen, bar)

def _stupid_progress(total, num, text):
      ui_tot = _ui_num(total)
      mnum = len(ui_tot)
      left = 79 - (mnum + 1 + mnum + 1 + 3 + 2 + 18 + 1)
      text = text[:left]
      perc = float(num) / float(total)
      textperc = _term_add_bar(16, perc)
      perc = int(100 * perc)
      print '%*s/%*s %3u%% %s %-*s\r' % (mnum, ui_tot, mnum, _ui_num(num), perc,
                                         textperc, left, text),
      sys.stdout.flush()
def _stupid_progress_end():
     print ' ' * 79, '\r',
     sys.stdout.flush()

def _walk_(vfsd, ui, progress):
    " Internal Worker. "
    for fn in _listdir_f(vfsd.path):
        vfs = VFS_f(vfsd, fn)
        if vfs.isdir: # This requires a stat.
                      # Use real Unix API for "free" file/dir. hint
            vfs = VFS_d(vfsd, vfs.name, vfs._stat) # FIXME: hack so no stat 2x
            vfsd.add(vfs)
            _walk_(vfs, ui, progress)
        elif not (vfs.islnk or vfs.isreg):
            continue
        else:
            vfsd.add(vfs)
        if False and progress is not None:
            progress[1] += 1
            _stupid_progress(progress[0].num + 1, progress[1],
                             vfsd.path.replace('\n', '\\n'))
def _walk(vfsd, ui=False):
    """ Walk the FS, adding nodes for each. """
    progress = None
    if ui:
        progress = [vfsd, 0]
    _walk_(vfsd, ui, progress)
    if False and progress is not None:
        _stupid_progress_end()

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

_cached = {}
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

    if vfs.name not in _cached:
        _cached[vfs.name] = []
    _cached[vfs.name].append(vfs)
    return vfs

def _load(fn, data_only=False):
    num = 1
    try:
        fo = open(fn)
    except IOError, e:
            print >>sys.stderr, "open(%s): %s" % (fn, e)
            return None

    line = fo.readline()
    if line != "mtree-file-0.1\n":
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
                vfs._stat_st_mtime = int(line[4:])
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
                vfs._stat_st_atime = int(line[4:])
            except ValueError:
                print >>sys.stderr, "Invalid atime line %d, in %s\n => %s" % (num, fn, sline)
                return None
            if True: continue
            if not _read_int(line, vfs, "st_atime"):
                return None

        elif line[0] == 'C' and line[1] == 'T' and line[2] == ':':
            try:
                vfs._stat_st_ctime = int(line[4:])
            except ValueError:
                print >>sys.stderr, "Invalid ctime line %d, in %s\n => %s" % (num, fn, sline)
                return None
            if True: continue
            if not _read_int(line, vfs, "st_ctime"):
                return None

        else:
            print >>sys.stderr, "Unknown line %d, in %s\n => %s\n" % (num, fn, line)

    return roots

def _1root_load(path, data_only=False):
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

def _cache_read(vfsd, verify_cached="nsm", verbose=False):
    if verbose:
        print >>sys.stderr, "Cache: verify:", verify_cached

    for vfs in vfsd:
        if isinstance(vfs, VFS_d):
            _cache_read(vfs, verify_cached, verbose)
            # continue # More checks??

        # FIXME: i needs ino/dev lookup
        if vfs.name not in _cached:
            if verbose:
                print >>sys.stderr, "Cache: Not found:", len(vfs.name), vfs.name, vfs.name
            continue

        found = None
        isd = isinstance(vfs, VFS_d)
        for cvfs in _cached[vfs.name]:
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

        if found is not None:
            vfs._checksum = found.checksums()

def _ui_time(tm, nospc=False):
    if nospc:
        return time.strftime("%Y-%m-%d--%H%MZ", time.gmtime(tm))
    return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(tm))

import locale
_used_locale = False
def _ui_lnum(num):
    global _used_locale
    if not _used_locale:
        locale.setlocale(locale.LC_ALL, '')
        _used_locale = True
    return locale.format("%d", int(num), True)

def _ui_num(num):
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
    def _muit(val):
        return _maybe_ui(val, _ui_time)

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
    else:
        print "JDBG:", "BAD:", vfs.path, vfs.st_mode
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
        fo.write("%s %s\n"  % ('MT:', _muit(vfs.mtime)))

    if 'u' in info:
        fo.write("%s %d\n"  % ('U:',  vfs.st_uid))
    if 'g' in info:
        fo.write("%s %d\n"  % ('G:',  vfs.st_gid))
    if 'd' in info:
        fo.write("%s %d\n"  % ('D:',  vfs.st_dev))
    if 'i' in info:
        fo.write("%s %d\n"  % ('I:',  vfs.st_uid))
    if 'l' in info:
        fo.write("%s %d\n"  % ('L:',  _muil(vfs.st_nlink)))
    if 'mo' in info:
        if ui:
            fo.write("%s %#o (%s)\n" % ('MO:', vfs.st_mode, _ui_mode(vfs.st_mode)))
        else:
            fo.write("%s %#o\n" % ('MO:', vfs.st_mode))
    if 'at' in info:
        fo.write("%s %s\n"  % ('AT:', _muit(vfs.st_atime)))
    if 'ct' in info:
        fo.write("%s %s\n"  % ('CT:', _muit(vfs.st_ctime)))

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
        vfsd._parent_recalc()
    return ret

def _walk_checksum_vfsd_calc(vfsd, progress):
    " Internal Worker. "
    if vfsd._checksum is not None:
        return

    progress[0].num += 1
    if isinstance(vfsd, VFS_d):
        for vfs in vfsd:
            _walk_checksum_vfsd_calc(vfs, progress)
    else:
        progress[0].size += vfsd.size

def _walk_checksum_vfsd_(vfsd, ui, progress):
    " Internal Worker. "
    if vfsd._checksum is not None:
        return

    if isinstance(vfsd, VFS_d):
        for vfs in vfsd:
            _walk_checksum_vfsd_(vfs, ui, progress)

    if progress is not None:
        if isinstance(vfsd, VFS_d):
            progress[1] += 1
        else:
            progress[1] += 1 + vfsd.size
        tot = progress[0].num + progress[0].size
        _stupid_progress(tot, progress[1],
                         vfsd.path.replace('\n', '\\n'))
    vfsd.checksums()
def _walk_checksum_vfsd(vfsd, ui=False):
    """ Walk the tree and ask for checksums. """
    _walk_checksum_vfsd_prop(vfsd)
    progress = None
    if ui:
        if False:
            progress = [vfsd, 0]
        else:
            fake_vfsd = lambda x: x
            fake_vfsd.num  = 0
            fake_vfsd.size = 0
            progress = [fake_vfsd, 0]
        _walk_checksum_vfsd_calc(vfsd, progress)
    _walk_checksum_vfsd_(vfsd, ui, progress)
    if progress is not None:
        _stupid_progress_end()

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
            help='fields to show in info command') # FIXME: allow stripping from snaps
    argp.add_option('--info', dest="info_fields",
            help=optparse.SUPPRESS_HELP)

    return argp, argp.parse_args()

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
_beg = time.time()
def _jdbg(arg):
    if not __jdbg_print__:
        return
    print >>sys.stderr, "JDBG: %f %s" % (time.time()-_beg, arg)

def main():
    """ Command line UI to run commands. """
    global prog
    global last_matched_chop

    remap_cmds = {'info' : 'information',
                  'ls' : 'list',
                  'diff' : 'difference',
                  'treediff' : 'tree-difference',
                  'tree-diff' : 'tree-difference',
                  'treedifference' : 'tree-difference',
                  'snap' : 'snapshot',
                  }
    all_cmds = ("summary", "list", "information", "difference",
                "snapshot", "check", "tree", "tree-difference", "help")

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
    if cmd not in all_cmds:
        argp.print_help()
        sys.exit(1)

    _jdbg("cmds")

    done = False
    if False: pass

    elif cmd == 'snapshot':
        if len(cmds) < 3:
            print >>sys.stderr, "Format: %s %s <filename> <tree> [...]" % (prog, cmds[0])
            sys.exit(1)

        info = set(['p', 'c', 's', 'num', 'mt',
                    'u', 'g', 'd', 'i', 'l', 'mo', 'at', 'ct'])

        snap_fn = cmds[1]
        if not os.path.isdir(snap_fn):
            if opts.auto_load and not snap_fn.endswith(".mtree"):
                snap_fn += "-" + _ui_time(time.time(), nospc=True) + ".mtree"
        else:
            _jdbg("auto snap")
            snap_base = os.path.basename(snap_fn)
            old_snaps = []
            if opts.auto_load:
                old_snaps = os.listdir(snap_fn)
            old_snaps = [snap for snap in old_snaps
                         if snap.startswith(snap_base) and
                            snap.endswith(".mtree")]
            if old_snaps:
                last_snap = sorted(old_snaps, cmp=_fcmp)[-1]
                print "Loading snapshot:", last_snap
                auto_cached_root = u_load(snap_fn + "/" + last_snap)
                _jdbg("auto loaded")
            snap_fn += "/"
            snap_fn += snap_base
            snap_fn += "-" + _ui_time(time.time(), nospc=True) + ".mtree"

        print "Creating snapshot:", snap_fn

        try:
            out = open(snap_fn, "wb")
        except IOError, e:
            print >>sys.stderr, "open(%s): %s" % (snap_fn, e)
            sys.exit(1)

        out.write("mtree-file-0.1\n")
        roots = {}
        for path in cmds[2:]:
            if not os.path.isdir(path):
                print >>sys.stderr, "Path is not a directory: %s" % path
                continue

            names = _path2names(path)
            parent = _names2parent(roots, names)
            name = names[-1]

            vfs = _name2vfs(roots, parent, 'd', name)

            _jdbg("pre walk")
            _walk(vfs, ui=opts.ui)
            _jdbg("pre cache read")
            _cache_read(vfs, opts.verify_cached, opts.verbose)

            _jdbg("pre walk checksums")
            _walk_checksum_vfsd(vfs, ui=opts.ui)
            _jdbg("walked checksums")
            _jdbg("pre prnt vfsd")
            _prnt_vfsd(out, vfs, info=info)
            _jdbg("pre prnt vfs")
            _prnt_vfs(sys.stdout, vfs, ui=opts.ui)

    elif cmd == 'summary':
        if len(cmds) < 2:
            print >>sys.stderr, "Format: %s %s <filename> [...]" % (prog, cmds[0])
            sys.exit(1)

        for fn in cmds[1:]:
            root = u_load(fn, data_only=True)
            if root is None:
                sys.exit(1)
            # Need to keep real root around due to GC.
            rroot,root = root
            _jdbg("post load")

            if done: print ''
            _ui_prnt_root(_root2useful(root), ui=opts.ui)
            done = True

    elif cmd in ('information', 'list', 'tree'):
        if len(cmds) < 2:
            print >>sys.stderr, "Format: %s %s <filename> [...]" % (prog, cmds[0])
            sys.exit(1)

        data_only = False
        if cmd in ('list', 'tree'):
            if opts.verify_cached in ("ns", "ps", "nsm", "psm"):
                data_only = True
            ifields = False

        _jdbg("beg")
        for fn in cmds[1:]:
            root = u_load(fn, data_only)
            _jdbg("loaded")
            if root is None:
                sys.exit(1)
            # Need to keep real root around due to GC.
            rroot,root = root

            if done: print ''
            done = True
            _jdbg("pre prnt")
            _prnt_vfsd(sys.stdout, root, ifields, ui=opts.ui, tree=cmd=='tree')
        _jdbg("end")

    elif cmd in ('difference', 'tree-difference'):
        if len(cmds) != 3:
            print >>sys.stderr, "Format: %s %s <filename> <filename>" % (prog, cmds[0])
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
            data_only = False
            if opts.verify_cached in ("ns", "ps", "nsm", "psm"):
                data_only = True
            roots1[1] = u_load(cmds[1], data_only)
            _jdbg("load 1")
            if roots1[1] is None:
                sys.exit(1)
            roots2[2] = u_load(cmds[2], data_only)
            _jdbg("load 2")
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
            print "JDBG:", roots
            if roots is None:
                sys.exit(1)

            for root in sorted(roots, cmp=_fcmp):
                root = roots[root]
                if _valid_cached_dirs(root, True): # opts.verbose):
                    continue
                if done: print ''
                # FIXME: Print diff?
                _ui_prnt_root(_root2useful(root), ui=opts.ui)
                done = True

    elif cmd == 'help':
        argp.print_help()
        return

    else:
        assert False, "Should be checked above, in all_cmds"       

if __name__ == "__main__":
    main()
