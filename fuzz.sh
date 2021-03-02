#!/bin/bash
AFL_AUTORESUME=1 AFL_PATH="$(realpath ~/code/AFLplusplus/)" PATH="$AFL_PATH:$PATH" afl-fuzz -m 300 -i afl_inputs -o afl_outputs -U -L 0 -Z -- python ./ql.py @@
