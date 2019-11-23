#! /bin/sh -e

d="$1"

if [ "x$d" = "x" ]; then
  d="."
fi

chk=sha256sum
# chk=md5sum
tfnp=`basename $0`
function tfname {
    mktemp -q /tmp/${tfnp}.$1.XXXXXX
}

function chksumFile {
  $chk < "$1" | cut -d ' ' -f 1 
}

function chksumData {
  printf "$1" | $chk | cut -d ' ' -f 1
}

function serialDir {
  # Doesn't work for \n filenames ... welcome to sh
  fnames=$(ls -A "$1" | egrep -v "~$")

  # Sort them
  sfnames=$(for i in $fnames; do
    printf "%08d,%s\n" "$(printf $i | wc -c)" "$i"
  done | LC_ALL=C sort | cut -d , -f 2)

  for i in $sfnames; do
    p="$1/$i"
    printf "$i "

    if [ -L "$p" ]; then
      sd=$(readlink -n "$p")
      chksumData "$sd"
      continue
    fi
    if [ -f "$p" ]; then
      chksumFile "$p"
      continue
    fi
    if [ -d "$p" ]; then
      tfn=`tfname dir`
      touch "$tfn"
      serialDir "$p" > "$tfn"
      chksumFile "$tfn"
      rm -f "$tfn"
      continue
    fi
  done
}

i=$(basename "$d")
printf "$i "
tfnm=`tfname main`
touch "$tfnm"
serialDir "$d" > $tfnm
chksumFile "$tfnm"
cat "$tfnm"
rm -f "$tfnm"
