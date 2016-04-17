#! /usr/bin/python -tt

import os

print os.stat(".")
os.stat_float_times(False)
print os.stat(".")
