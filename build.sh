#!/usr/bin/env bash

set -euo pipefail

if [ ! -f .config ]; then
    ./configure
fi

intercept-build-19 --append make -j$(nproc)
