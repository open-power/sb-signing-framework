#!/bin/sh
# Copyright 2017 IBM Corp.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# 	http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

#set -x

i=0

#while [ $i -le 10000 ];
while [ $i -le 10 ];

do

  i=`expr ${i} + 1` 

  rm obody.txt

  echo "Starting loop $i"
  
  openssl rand 64 -out regression-hash.bin

  ../keygeneccp521 -k regression-key.bin -p regression-pubkey.bin

  if [ $? -ne 0 ]; then
      echo " ERROR: Could not create key"
      exit 1
  fi

  ./signecc -obody obody.txt -usr test -pwd qazTGB -sender "test@email.com" -log regression.log -key regression-key.bin -auxcfg signecc-hwaux.cfg -di regression-hash.bin -do regression.sig -project RegressionTest

  if [ $? -ne 0 ]; then
      echo " ERROR: Could not sign"
      exit 1
  fi

done

rm obody.txt
rm regression.log
rm regression-key.bin
rm regression-pubkey.bin
rm regression.sig
rm regression-hash.bin
