#! /bin/sh -e

echo -n 'mtime = '
stat -c '%.Y' $@
