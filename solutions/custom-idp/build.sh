#!/bin/sh
set -xe

#cd "${0%/*}"
ARTIFACTS_DIR="${0%/*}/src/handler_layer"
python3 -m pip install pipenv
mkdir -p "$ARTIFACTS_DIR"
pipenv requirements > "$ARTIFACTS_DIR/requirements.txt"
rm -rf  "$ARTIFACTS_DIR/python"
mkdir -p "$ARTIFACTS_DIR/python"
python3 -m pip install -r "$ARTIFACTS_DIR/requirements.txt" -t "$ARTIFACTS_DIR/python"
sam build