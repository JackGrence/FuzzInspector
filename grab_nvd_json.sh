#!/bin/sh
mkdir -p ./nvdcve_json
rm -rf ./nvdcve_json/*
for i in `seq 2002 2020`
do
	cd nvdcve_json
	wget 'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-'$i'.json.zip'
	unzip 'nvdcve-1.1-'$i'.json.zip'
	cd ../
done
