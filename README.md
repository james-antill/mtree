Mtree
=====

Metadata trees for looking at a tree of objects as a single unit. Only
compares with the name and content, although it can store uid/gid/mtime/ctime/etc.


Big bugs
========

No real module API atm. -- will happen soon.

misc bugs/etc.
==============

Not enough tests. never?

1.2M files
    don't have children slices for files
    rm size/mtime for dirs?
    rm err?
    rm parent? - .Path() becomes annoying.

metadata dir?

snap creates .gz/.xz files?
    https://github.com/klauspost/compress/tree/master/zstd#zstd
    save just files more for HEAD?

hardlinking ... on discovery and creating them
    reflinks

split file + package
better progress
