#!/bin/bash
set -o errexit
set -o nounset
set -o verbose
mkdir -p ~/.local/lib/wireshark/plugins
ln -snf $PWD/*.lua ~/.local/lib/wireshark/plugins/
