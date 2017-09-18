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

#
# signer framework regression test - project configuration file
#
# Run this script from the framework server
#	Do not start the framework
#

#set -x

removeFiles()
{
    rm -f oatt.bin
    rm -f iatt.bin
    rm -f /home/dropbox/stop
    rm -f run.out
}

# searches $1 for "Return codeErrornnnn" and returns the value */

getErrorCode()
{
    sleep 1
    errorcode=`grep -m 1 "ERROR" $1 | gawk '{print $1}' | sed s/ERROR// | sed s/:// `
#    echo "getErrorCode: $errorcode"
    return $errorcode
}

# searches $1 for "Return codeErrornnnn" and returns the value */

getReasonCode()
{
    reasoncode=`grep -m 1 "reason_code" $1 | gawk '{print $6}' `
    return $reasoncode
}


export FRAMEWORK_CONFIG_FILE=test.cfg

sed s/athena\.cfg/athenatest\.cfg/ framework.cfg > test.cfg


echo ""
echo "Errors in project configuration file"
echo ""

# program

echo "Missing program"
removeFiles
sed s/program/programa/ athena.cfg > athenatest.cfg
(./framework -v > run.out) &
touch /home/dropbox/stop
getErrorCode run.out
if [ "$errorcode" -eq "23" ]; then
    echo " INFO: Error case OK"
else
    echo " ERROR: Error case failed"
    exit $errorcode
fi

echo "Bad program"
removeFiles
sed s/program=framework_test/program=framework_testa/ athena.cfg > athenatest.cfg
./framework  -v > run.out
touch /home/dropbox/stop
getErrorCode run.out
echo $errorcode
if [ "$errorcode" -eq "39" ]; then
    echo " INFO: Error case OK"
else
    echo " ERROR: Error case failed"
    exit $errorcode
fi

echo "Unaccessible program"
removeFiles
chmod u-x framework_test
(./framework > run.out)&
touch /home/dropbox/stop
getErrorCode run.out
chmod u+x framework_test
if [ "$errorcode" -eq "39" ]; then
    echo " INFO: Error case OK"
else
    echo " ERROR: Error case failed"
    exit $errorcode
fi

# log

echo "Missing log"
removeFiles
sed s/log/loga/ athena.cfg > athenatest.cfg
(./framework > run.out)&
touch /home/dropbox/stop
getErrorCode run.out
if [ "$errorcode" -eq "23" ]; then
    echo " INFO: Error case OK"
else
    echo " ERROR: Error case failed"
    exit $errorcode
fi

echo "Unaccessible log"
removeFiles
cp athena.cfg athenatest.cfg
chmod u-w logs/athena.log
(./framework > run.out)&
touch /home/dropbox/stop
getErrorCode run.out
chmod u+w logs/athena.log
if [ "$errorcode" -eq "23" ]; then
    echo " INFO: Error case OK"
else
    echo " ERROR: Error case failed"
    exit $errorcode
fi

# key

echo "Missing needkey"
removeFiles
sed s/needkey/needkeya/ athena.cfg > athenatest.cfg
(./framework > run.out)&
touch /home/dropbox/stop
getErrorCode run.out
if [ "$errorcode" -eq "23" ]; then
    echo " INFO: Error case OK"
else
    echo " ERROR: Error case failed"
    exit $errorcode
fi

echo "Bad value needkey"
removeFiles
sed s/needkey=true/needkey=truea/ athena.cfg > athenatest.cfg
(./framework > run.out)&
touch /home/dropbox/stop
getErrorCode run.out
if [ "$errorcode" -eq "23" ]; then
    echo " INFO: Error case OK"
else
    echo " ERROR: Error case failed"
    exit $errorcode
fi

echo "Missing key"
removeFiles
sed s/key/keya/ athena.cfg > athenatest.cfg
(./framework > run.out)&
touch /home/dropbox/stop
getErrorCode run.out
if [ "$errorcode" -eq "23" ]; then
    echo " INFO: Error case OK"
else
    echo " ERROR: Error case failed"
    exit $errorcode
fi

echo "Missing key file"
removeFiles
sed s/key=athenakey.tok/key=athenakey.toka/ athena.cfg > athenatest.cfg
(./framework -v > run.out) &
touch /home/dropbox/stop
getErrorCode run.out
if [ "$errorcode" -eq "23" ]; then
    echo " INFO: Error case OK"
else
    echo " ERROR: Error case failed"
    exit $errorcode
fi

echo "Unaccessible athena key file"
removeFiles
cp athena.cfg athenatest.cfg
chmod a-r athenakey.tok
(./framework > run.out)&
touch /home/dropbox/stop
getErrorCode run.out
chmod a+r athenakey.tok
if [ "$errorcode" -eq "23" ]; then
    echo " INFO: Error case OK"
else
    echo " ERROR: Error case failed"
    exit $errorcode
fi

echo "Bad athena key file"
removeFiles
sed s/key=athenakey.tok/key=athena.cfg/ athena.cfg > athenatest.cfg
(./framework > run.out)&
touch /home/dropbox/stop
getErrorCode run.out
if [ "$errorcode" -eq "15" ]; then
    echo " INFO: Error case OK"
else
    echo " ERROR: Error case failed"
    exit $errorcode
fi

# auxiliary project configuration file

echo "Missing needauxcfg"
removeFiles
sed s/needauxcfg/needauxcfga/ athena.cfg > athenatest.cfg
(./framework > run.out)&
touch /home/dropbox/stop
getErrorCode run.out
if [ "$errorcode" -eq "23" ]; then
    echo " INFO: Error case OK"
else
    echo " ERROR: Error case failed"
    exit $errorcode
fi

echo "Bad value needauxcfg"
removeFiles
sed s/needauxcfg=true/needauxcfg=truea/ athena.cfg > athenatest.cfg
(./framework > run.out)&
touch /home/dropbox/stop
getErrorCode run.out
if [ "$errorcode" -eq "23" ]; then
    echo " INFO: Error case OK"
else
    echo " ERROR: Error case failed"
    exit $errorcode
fi

echo "Missing auxcfg"
removeFiles
sed s/auxcfg/auxcfga/ athena.cfg > athenatest.cfg
(./framework > run.out)&
touch /home/dropbox/stop
getErrorCode run.out
if [ "$errorcode" -eq "23" ]; then
    echo " INFO: Error case OK"
else
    echo " ERROR: Error case failed"
    exit $errorcode
fi

echo "Missing auxcfg file"
removeFiles
sed s/auxcfg=athenaaux.cfg/auxcfg=athenaaux.bina/ athena.cfg > athenatest.cfg
(./framework > run.out)&
touch /home/dropbox/stop
getErrorCode run.out
if [ "$errorcode" -eq "23" ]; then
    echo " INFO: Error case OK"
else
    echo " ERROR: Error case failed"
    exit $errorcode
fi

echo "Unaccessible athena auxcfg file"
removeFiles
cp athena.cfg athenatest.cfg
chmod a-r athenaaux.cfg
(./framework > run.out)&
touch /home/dropbox/stop
getErrorCode run.out
chmod a+r athenaaux.cfg
if [ "$errorcode" -eq "23" ]; then
    echo " INFO: Error case OK"
else
    echo " ERROR: Error case failed"
    exit $errorcode
fi

# input attachment

echo "Missing neediatt"
removeFiles
sed s/neediatt/neediatta/ athena.cfg > athenatest.cfg
(./framework > run.out)&
touch /home/dropbox/stop
getErrorCode run.out
if [ "$errorcode" -eq "23" ]; then
    echo " INFO: Error case OK"
else
    echo " ERROR: Error case failed"
    exit $errorcode
fi

echo "Bad value neediatt"
removeFiles
sed s/neediatt=true/neediatt=truea/ athena.cfg > athenatest.cfg
(./framework > run.out)&
touch /home/dropbox/stop
getErrorCode run.out
if [ "$errorcode" -eq "23" ]; then
    echo " INFO: Error case OK"
else
    echo " ERROR: Error case failed"
    exit $errorcode
fi

# output attachment

echo "Missing needoatt"
removeFiles
sed s/needoatt/needoatta/ athena.cfg > athenatest.cfg
(./framework > run.out)&
touch /home/dropbox/stop
getErrorCode run.out
if [ "$errorcode" -eq "23" ]; then
    echo " INFO: Error case OK"
else
    echo " ERROR: Error case failed"
    exit $errorcode
fi

echo "Bad value needoatt"
removeFiles
sed s/needoatt=true/needoatt=truea/ athena.cfg > athenatest.cfg
(./framework > run.out)&
touch /home/dropbox/stop
getErrorCode run.out
if [ "$errorcode" -eq "23" ]; then
    echo " INFO: Error case OK"
else
    echo " ERROR: Error case failed"
    exit $errorcode
fi

# need pwd

echo "Missing needpwd"
removeFiles
sed s/needpwd/needpwda/ athena.cfg > athenatest.cfg
(./framework > run.out)&
touch /home/dropbox/stop
getErrorCode run.out
if [ "$errorcode" -eq "23" ]; then
    echo " INFO: Error case OK"
else
    echo " ERROR: Error case failed"
    exit $errorcode
fi

echo "Bad value needpwd"
removeFiles
sed s/needpwd=true/needpwd=truea/ athena.cfg > athenatest.cfg
(./framework > run.out)&
touch /home/dropbox/stop
getErrorCode run.out
if [ "$errorcode" -eq "23" ]; then
    echo " INFO: Error case OK"
else
    echo " ERROR: Error case failed"
    exit $errorcode
fi

# email

echo "Missing email"
removeFiles
sed s/email/emaila/ athena.cfg > athenatest.cfg
(./framework > run.out)&
touch /home/dropbox/stop
getErrorCode run.out
if [ "$errorcode" -eq "23" ]; then
    echo " INFO: Error case OK"
else
    echo " ERROR: Error case failed"
    exit $errorcode
fi

# senders

echo "Missing needsenders"
removeFiles
sed s/needsenders/needsendersa/ athena.cfg > athenatest.cfg
(./framework > run.out)&
touch /home/dropbox/stop
getErrorCode run.out
if [ "$errorcode" -eq "23" ]; then
    echo " INFO: Error case OK"
else
    echo " ERROR: Error case failed"
    exit $errorcode
fi

echo "Missing needsenders"
removeFiles
sed s/needsenders/needsendersa/ athena.cfg > athenatest.cfg
(./framework > run.out)&
touch /home/dropbox/stop
getErrorCode run.out
if [ "$errorcode" -eq "23" ]; then
    echo " INFO: Error case OK"
else
    echo " ERROR: Error case failed"
    exit $errorcode
fi

echo "Bad value needsenders"
removeFiles
sed s/needsenders=true/needsenders=truea/ athena.cfg > athenatest.cfg
(./framework > run.out)&
touch /home/dropbox/stop
getErrorCode run.out
if [ "$errorcode" -eq "23" ]; then
    echo " INFO: Error case OK"
else
    echo " ERROR: Error case failed"
    exit $errorcode
fi

#echo "needsenders but zero senders"
#removeFiles
#sed s/senders=3/senders=0/ athena.cfg > athenatest.cfg
#(./framework > run.out)&
#touch /home/dropbox/stop
#getErrorCode run.out
#if [ "$errorcode" -eq "24" ]; then
#    echo " INFO: Error case OK"
#else
#    echo " ERROR: Error case failed"
#    exit $errorcode
#fi

echo "senders but no needsenders"
removeFiles
sed s/needsenders=true/needsenders=false/ athena.cfg > athenatest.cfg
(./framework > run.out)&
touch /home/dropbox/stop
getErrorCode run.out
if [ "$errorcode" -eq "24" ]; then
    echo " INFO: Error case OK"
else
    echo " ERROR: Error case failed"
    exit $errorcode
fi

#echo "Illegal character in senders"
#removeFiles
#sed s/senders=3/senders=3a/ athena.cfg > athenatest.cfg
#(./framework > run.out)&
#touch /home/dropbox/stop
#getErrorCode run.out
#if [ "$errorcode" -eq "23" ]; then
#    echo " INFO: Error case OK"
#else
#    echo " ERROR: Error case failed"
#    exit $errorcode
#fi

#echo "Insufficient senders"
#removeFiles
#sed s/senders=3/senders=300/ athena.cfg > athenatest.cfg
#(./framework > run.out)&
#touch /home/dropbox/stop
#getErrorCode run.out
#if [ "$errorcode" -eq "23" ]; then
#    echo " INFO: Error case OK"
#else
#    echo " ERROR: Error case failed"
#    exit $errorcode
#fi

# notification

echo "Missing notifs"
removeFiles
sed s/notifs/notifsa/ athena.cfg > athenatest.cfg
(./framework > run.out)&
touch /home/dropbox/stop
getErrorCode run.out
if [ "$errorcode" -eq "23" ]; then
    echo " INFO: Error case OK"
else
    echo " ERROR: Error case failed"
    exit $errorcode
fi

echo "Illegal character in notifs"
removeFiles
sed s/notifs=/notifs=a/ athena.cfg > athenatest.cfg
(./framework > run.out)&
touch /home/dropbox/stop
getErrorCode run.out
if [ "$errorcode" -eq "23" ]; then
    echo " INFO: Error case OK"
else
    echo " ERROR: Error case failed"
    exit $errorcode
fi

echo "Insufficient notifs"
removeFiles
sed s/notifs=/notifs=400/ athena.cfg > athenatest.cfg
(./framework > run.out)&
touch /home/dropbox/stop
getErrorCode run.out
if [ "$errorcode" -eq "23" ]; then
    echo " INFO: Error case OK"
else
    echo " ERROR: Error case failed"
    exit $errorcode
fi

echo ""
echo "Tests Passed"
echo ""

removeFiles
rm -f test.cfg
rm -f athenatest.cfg

exit 0
