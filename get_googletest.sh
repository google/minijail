#/bin/bash

PV="1.11.0"

wget -q -nc --secure-protocol=TLSv1 "https://github.com/google/googletest/archive/release-${PV}.tar.gz" -O "googletest-release-${PV}.tar.gz"
tar zxvf "googletest-release-${PV}.tar.gz"
