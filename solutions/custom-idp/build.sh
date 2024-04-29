#!/bin/sh
set -xe

ARTIFACTS_DIR="${0%/*}/src/handler_layer"
python3.11 -m pip install pipenv
pipenv lock 
mkdir -p "$ARTIFACTS_DIR"
rm -rf  "$ARTIFACTS_DIR/python"
mkdir -p "$ARTIFACTS_DIR/python"
pipenv requirements > "$ARTIFACTS_DIR/requirements.txt"
python3.11 -m pip install -r "$ARTIFACTS_DIR/requirements.txt" -t "$ARTIFACTS_DIR/python"
sam build --template "${0%/*}/custom-idp.yaml"