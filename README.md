Mtree
=====

Metadata trees for looking at a tree of objects as a single unit. Only
compares with the name and content, although it can store uid/gid/mtime/etc.

  * To install: go get github.com/james-antill/mtree

Big bugs
========

No real module API atm. -- will happen soon.

.mtree/cache problems when empty and using offsets?

weird Couldn't generate .mtree for issue

misc bugs/etc.
==============

Not enough tests. never?

1.2M files
    don't have children slices for files
    rm size/mtime for dirs?
    rm err?
    rm parent? - .Path() becomes annoying.

metadata dir?

cache by file?
    cache in ~/.cache/ for "large" files?

snap creates .gz/.xz files?
    https://github.com/klauspost/compress/tree/master/zstd#zstd
    save just files more for HEAD?

hardlinking ... on discovery and creating them
    reflinks

admin/debug sub command
    show path/.mtree offsets etc.
    load file

Create/validate SHA256SUM / etc. files?

history sub command
    local
    remote
    diffs between versions

split cmd + package
better progress
