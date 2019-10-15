#! /usr/bin/python

import mtree

if __name__ == "__main__":
    try:
        mtree.main()
    except KeyboardInterrupt, e:
        import sys
        print >>sys.stderr, "Exiting on C-c."
        sys.exit(1)
