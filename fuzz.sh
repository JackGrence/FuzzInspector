#!/bin/bash
AFL_AUTORESUME=1 AFL_PATH="$(realpath ~/code/AFLplusplus/)" PATH="$AFL_PATH:$PATH" afl-fuzz -i afl_inputs -o afl_outputs -U -- python ./ql.py @@
