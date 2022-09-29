#!/usr/bin/env bash
# using: run-elf-arm.sh <exe>
# exe must include path!
# working_directory - . not allowed!
working_dir=${1%/*}
# second exe
exe=$(basename $1)
docker run --platform linux/arm --rm -t -v ${working_dir}:/work arm32v7/ubuntu:20.04 /work/${exe}
# reset docker exit code 96
exit 0