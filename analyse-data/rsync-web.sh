#!/bin/bash -e

dirs=$(
  for dir in *; do
    if ! [ -d "$dir" ]; then
      continue
    fi
    if ! [ -e "$dir/info.txt" ]; then
      continue
    fi

    echo "$dir"
  done \
  | xargs echo
)

rsync -az --delete --progress $dirs jukivili@paju.oulu.fi:public_html/crypto/

tar -cvf results.tar $dirs
xz -9eeevvv results.tar
rsync -az --delete --progress results.tar.xz jukivili@paju.oulu.fi:public_html/crypto/

rm results.tar.xz
