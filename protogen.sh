#!/bin/bash
# Generates protobuf Go datastructures from the proto directory.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
PROTOBUF_DIR=${PROTOBUF_DIR-${SCRIPT_DIR}/proto}
PROTOGEN_DIR=_protogen
GENERATION_DIR=${GENERATION_DIR-${SCRIPT_DIR}/${PROTOGEN_DIR}}
IMPORT_PREFIX="github.com/mwitkow/kfe/${PROTOGEN_DIR}"

# Builds all .proto files in a given package dirctory.
# NOTE: All .proto files in a given package must be processed *together*, otherwise the self-referencing
# between files in the same proto package will not work.
function proto_build_dir {
  DIR_FULL=${1}
  DIR_REL=${1##${PROTOBUF_DIR}}
  DIR_REL=${DIR_REL#/}
  echo "proto_build: $DIR_REL"
  mkdir -p ${GENERATION_DIR}/${DIR_REL} 2> /dev/null
  PATH=${GOPATH}/bin:$PATH protoc \
    -I${PROTOBUF_DIR} \
    --go_out=plugins=grpc:${GENERATION_DIR} \
    ${DIR_FULL}/*.proto || exit $?
  fix_imports ${GENERATION_DIR}/${DIR_REL}
  echo "DONE"
}

function fix_imports {
  DIR_FULL=${1}
  for file in $(ls ${DIR_FULL}/*.go 2>/dev/null); do
    # This is a massive hack (prefix of "kfe")
    # See https://github.com/golang/protobuf/issues/63
    sed --in-place='' -r "s~^import(.*) \"kfe(.*)\"$~import \1 \"${IMPORT_PREFIX}/kfe\2\"~" ${file};
    echo $file;
  done
}

# Generate files for each proto package directory.
for dir in `find -L ${PROTOBUF_DIR} -type d`; do
  if [[ "$dir" == ${PROTOGEN_DIR} ]]; then
      continue
  fi
  if [ -n "$(ls $dir/*.proto 2>/dev/null)" ]; then
    proto_build_dir ${dir} || exit 1
  fi
done