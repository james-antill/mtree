#!/bin/bash

GOversion=1.14

go tool dist list >/dev/null || {
    echo 1>&2 "go tool dist list not supported - can't check compile"
    exit 0
}

failures=0
function compile {
    osarch=$1
    parts=(${osarch//\// })
    export GOOS=${parts[0]}
    export GOARCH=${parts[1]}
    if go tool compile -V >/dev/null 2>&1 ; then
        echo Try GOOS=${GOOS} GOARCH=${GOARCH}
        if ! sudo docker run --rm \
  -v "$PWD":/usr/src/myapp \
  -w /usr/src/myapp \
  -e GOOS=$GOOS \
  -e GOARCH=$GOARCH golang:$GOversion /usr/src/myapp/b/compile1.sh; then
            echo "*** Failed compiling GOOS=${GOOS} GOARCH=${GOARCH}"
            failures=$((failures+1))
        fi
    else
        echo Skipping GOOS=${GOOS} GOARCH=${GOARCH} as not supported
    fi
}

go fmt
if [ "$1x" != "qx" ]; then

while read -r line; do
    compile $line
done < <(go tool dist list)

else
    compile linux/amd64
    compile darwin/amd64
    compile windows/amd64
fi


if [ $failures -ne 0 ]; then
    echo "*** $failures compile failures"
    exit 1
fi
