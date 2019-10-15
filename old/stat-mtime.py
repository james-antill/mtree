#! /usr/bin/python -tt

import os
import sys

print "mtime =",
print os.stat(sys.argv[1]).st_mtime
