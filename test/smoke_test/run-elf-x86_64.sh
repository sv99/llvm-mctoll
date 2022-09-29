#!/usr/bin/env bash
# working_directory - . not allowed!
working_dir=${1%/*}
# second exe
exe=$(basename $1)
docker run --platform linux/x86_64 --rm -t -v ${working_dir}:/work amd64/ubuntu:20.04 /work/${exe}
# reset docker exit code 2
exit 0
