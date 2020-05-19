#!/bin/sh
mkdir -p ./nvdcve_json
for i in `seq 2002 2020`
do
wget 'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-'$i'.json.zip'
unzip 'nvdcve_json/nvdcve-1.1-'$i'.json.zip'
done
