#! /usr/bin/python

import sys

fo = open(sys.argv[1])
ifo = iter(fo)

size = 0
num  = 0
for line in ifo:
    num += 1
    size += len(line)

print size, num
