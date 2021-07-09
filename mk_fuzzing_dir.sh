#!/bin/bash
PORT=$1

if [ "$PORT" == "" ]; then
  PORT=5000
fi

if [ $# -le 1 ]; then
  echo "Fuzzer name not found"
  echo "Please mkdir fuzzer_name && cp visport fuzzer_name/"
  FUZZER_NAMES=fuzzer_name
else
  shift
  FUZZER_NAMES=$@
fi

FUZZDIR=fuzzinspector_$PORT

if [ -d "$FUZZDIR" ]; then
  echo $FUZZDIR already exist!
else
  mkdir $FUZZDIR
  pushd $FUZZDIR
  git ls-tree --name-only HEAD ../ | xargs -I{} -n1 ln -s {} .
  echo $PORT > visport
  mkdir $FUZZER_NAMES
  for i in $FUZZER_NAMES
  do
    pushd $i
    ln -s ../visport .
    cp ../fuzz.sh ../ql-example.py .
    popd
  done
  popd
fi

echo "Please cd $FUZZDIR"
echo "# modify the fuzz.sh and ql.py to make your target happy"
echo "# start visualizer at `pwd`"
echo "./visrun.sh"
echo "# start fuzzing at $FUZZER_NAMES"
echo "./fuzz.sh"
