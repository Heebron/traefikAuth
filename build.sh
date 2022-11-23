#!/bin/bash

VERSION=$(sed -n 2p version.txt)
DATE=$(date)

if [[ $(git status --porcelain --untracked-files=no | wc -l) -eq 0 ]] ; then
  HASH=$(git rev-parse HEAD)
else
  HASH=DEV
fi

echo VERSION = ${VERSION}
echo DATE = ${DATE}
echo HASH = ${HASH}

go vet .
go build -o dist/traefikAuth \
  -ldflags "-X \"main.buildStamp=${DATE}\" -X main.version=${VERSION} -X main.gitHash=${HASH} -s -w" .
