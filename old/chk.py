#! /usr/bin/python

import sys
import mtree

def main():
    chksum = sys.argv.pop(1)
    for fn in sys.argv[1:]:
        ret = mtree._file2hexdigests(fn, checksum_types=[chksum])
        if ret is None:
            continue
        print ret[chksum], fn

if __name__ == "__main__":
    main()
