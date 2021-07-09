#!/bin/bash
if [ "$1" = "" ]
then
	echo "Usage: "$0" [port]"
	exit 1
fi
sudo apt-get install libpopt-dev
WORKDIR=fuzzinspector_$1
./mk_fuzzing_dir.sh $1
pushd $WORKDIR
wget https://github.com/libexif/exif/releases/download/exif-0_6_22-release/exif-0.6.22.tar.gz
wget https://github.com/libexif/libexif/releases/download/libexif-0_6_22-release/libexif-0.6.22.tar.gz
tar -xzf ./exif-0.6.22.tar.gz
tar -xzf ./libexif-0.6.22.tar.gz
export CC=../../../AFLplusplus/afl-gcc
export CFLAGS="-ggdb -Og"
mkdir libexif-0.6.22/out
mkdir exif-0.6.22/out
# build libexif
pushd libexif-0.6.22/out
LIBEXIF_PATH=`realpath .`
../configure --prefix=$LIBEXIF_PATH
make
make install
popd
# build exif
pushd exif-0.6.22/out
export LIBEXIF_LIBS=$LIBEXIF_PATH/lib/libexif.so
export LIBEXIF_CFLAGS=$CFLAGS
export CFLAGS="$CFLAGS -I$LIBEXIF_PATH/include/"
EXIF_PATH=`realpath .`
../configure --prefix=$EXIF_PATH
make
make install
popd
# prepare rootfs for qiling
mkdir rootfs
pushd rootfs
cp /lib64 . -rL
mkdir -p lib/x86_64-linux-gnu/
cp /lib/x86_64-linux-gnu lib/ -r
rm lib/x86_64-linux-gnu/libexif.so*
cp $LIBEXIF_PATH/lib/libexif.so* lib/x86_64-linux-gnu/
mkdir bin
cp $EXIF_PATH/bin/exif bin/
popd
# prepare fuzzing enviroment
pushd fuzzer_name
cp $EXIF_PATH/bin/exif .
mkdir afl_inputs
wget https://raw.githubusercontent.com/ianare/exif-samples/master/jpg/Canon_40D.jpg -P afl_inputs/
echo "#!/bin/bash" > fuzz.sh
echo "export LD_LIBRARY_PATH=$LIBEXIF_PATH/lib" >> fuzz.sh
echo 'AFL_VISPORT=`cat visport` AFL_AUTORESUME=1 AFL_PATH="$(realpath ../../AFLplusplus/)" PATH="$AFL_PATH:$PATH" afl-fuzz -i afl_inputs -o afl_outputs -Z -- ./exif @@' >> fuzz.sh
popd
# prepare the qiling enviroment for visualizer
cp ql-example.py ql.py

# please open two terminal to run visualizer and fuzzer
echo "NOTICE: You are not in the working directory, please \`cd\` to the correct path."
echo "Please \`workon fuzzinspector\` (or your virtualenv) and run the ./visrun.sh at `realpath .`"
echo "Then open another terminal to run the ./fuzz.sh at `realpath ./fuzzer_name`"
