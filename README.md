Mtree
=====

Metadata trees for looking at a tree of objects as a single unit. Only
compares with the name and content, although it can store uid/gid/mtime/ctime/etc.


Big bugs
========

No real module API atm. -- will happen soon.
Will move also move to the toplevel.

misc bugs/etc.
==============

Not enough tests. never?

1.2M files
    don't have children slices for files
    size/mtime for dirs?
    err?
    parent? - .Path() becomes annoying.


snap creates .gz/.xz files?
    https://github.com/klauspost/compress/tree/master/zstd#zstd
    save just files more for HEAD?

http dls
    symlinking dls
scp/sftp dls

harlinking ... on discovery and creating them

split file + package
better progress
