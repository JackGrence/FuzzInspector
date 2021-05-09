#!/bin/bash
AFL_VISPORT=`cat visport` AFL_AUTORESUME=1 AFL_PATH="$(realpath ~/code/AFLplusplus/)" PATH="$AFL_PATH:$PATH" afl-fuzz -m 1000 -i afl_inputs -o afl_outputs -U  -t 40000+ -Z -- python ./ql.py @@
