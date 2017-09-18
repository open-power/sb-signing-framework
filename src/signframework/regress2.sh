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
# signer framework regression test
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
    rm -f test.cfg
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

echo ""
echo "Errors in framework configuration file"
echo ""

echo "Missing line_max"
removeFiles
sed s/line_max/line_maxa/ framework.cfg > test.cfg
(./framework > run.out)&
touch /home/dropbox/stop
getErrorCode run.out
if [ "$errorcode" -eq "5" ]; then
    echo " INFO: Error case OK"
else
    echo " ERROR: Error case failed"
    exit $errorcode
fi

echo "Illegal value in line_max"
removeFiles
sed s/line_max=4000/line_max=0/ framework.cfg > test.cfg
(./framework > run.out)&
touch /home/dropbox/stop
getErrorCode run.out
if [ "$errorcode" -eq "8" ]; then
    echo " INFO: Error case OK"
else
    echo " ERROR: Error case failed"
    exit $errorcode
fi

echo "Illegal character in line_max"
removeFiles
sed s/line_max=4000/line_max=4000a/ framework.cfg > test.cfg
(./framework > run.out)&
touch /home/dropbox/stop
getErrorCode run.out
if [ "$errorcode" -eq "5" ]; then
    echo " INFO: Error case OK"
else
    echo " ERROR: Error case failed"
    exit $errorcode
fi

echo "Missing file_max"
removeFiles
sed s/file_max/file_maxa/ framework.cfg > test.cfg
(./framework > run.out)&
touch /home/dropbox/stop
getErrorCode run.out
if [ "$errorcode" -eq "5" ]; then
    echo " INFO: Error case OK"
else
    echo " ERROR: Error case failed"
    exit $errorcode
fi

echo "Illegal value in file_max"
removeFiles
sed s/file_max=10000/file_max=0/ framework.cfg > test.cfg
(./framework > run.out)&
touch /home/dropbox/stop
getErrorCode run.out
if [ "$errorcode" -eq "8" ]; then
    echo " INFO: Error case OK"
else
    echo " ERROR: Error case failed"
    exit $errorcode
fi

echo "Illegal character in file_max"
removeFiles
sed s/file_max=10000/file_max=10000a/ framework.cfg > test.cfg
(./framework > run.out)&
touch /home/dropbox/stop
getErrorCode run.out
if [ "$errorcode" -eq "5" ]; then
    echo " INFO: Error case OK"
else
    echo " ERROR: Error case failed"
    exit $errorcode
fi

echo "Missing framework_name"
removeFiles
sed s/framework_name/framework_namea/ framework.cfg > test.cfg
(./framework > run.out)&
touch /home/dropbox/stop
getErrorCode run.out
if [ "$errorcode" -eq "5" ]; then
    echo " INFO: Error case OK"
else
    echo " ERROR: Error case failed"
    exit $errorcode
fi





echo "Missing admins"
removeFiles
sed s/admins/adminsa/ framework.cfg > test.cfg
(./framework > run.out)&
touch /home/dropbox/stop
getErrorCode run.out
if [ "$errorcode" -eq "5" ]; then
    echo " INFO: Error case OK"
else
    echo " ERROR: Error case failed"
    exit $errorcode
fi

echo "Illegal character in admins"
removeFiles
sed s/admins=1/admins=1a/ framework.cfg > test.cfg
(./framework > run.out)&
touch /home/dropbox/stop
getErrorCode run.out
if [ "$errorcode" -eq "5" ]; then
    echo " INFO: Error case OK"
else
    echo " ERROR: Error case failed"
    exit $errorcode
fi

echo "Insufficient senders"
removeFiles
sed s/admins=1/admins=300/ framework.cfg > test.cfg
(./framework > run.out)&
touch /home/dropbox/stop
getErrorCode run.out
if [ "$errorcode" -eq "5" ]; then
    echo " INFO: Error case OK"
else
    echo " ERROR: Error case failed"
    exit $errorcode
fi


###

echo "Missing dropbox"
removeFiles
sed s/dropbox/dropboxa/ framework.cfg > test.cfg
(./framework > run.out)&
touch /home/dropbox/stop
getErrorCode run.out
if [ "$errorcode" -eq "5" ]; then
    echo " INFO: Error case OK"
else
    echo " ERROR: Error case failed"
    exit $errorcode
fi

###

echo "Missing password_expire"
removeFiles
sed s/password_expire/password_expirea/ framework.cfg > test.cfg
(./framework > run.out)&
touch /home/dropbox/stop
getErrorCode run.out
if [ "$errorcode" -eq "5" ]; then
    echo " INFO: Error case OK"
else
    echo " ERROR: Error case failed"
    exit $errorcode
fi

echo "Illegal value in password_expire"
removeFiles
sed s/password_expire=12/password_expire=0/ framework.cfg > test.cfg
(./framework > run.out)&
touch /home/dropbox/stop
getErrorCode run.out
if [ "$errorcode" -eq "11" ]; then
    echo " INFO: Error case OK"
else
    echo " ERROR: Error case failed"
    exit $errorcode
fi

echo "Illegal character in password_expire"
removeFiles
sed s/password_expire=12/password_expire=2a/ framework.cfg > test.cfg
(./framework > run.out)&
touch /home/dropbox/stop
getErrorCode run.out
if [ "$errorcode" -eq "5" ]; then
    echo " INFO: Error case OK"
else
    echo " ERROR: Error case failed"
    exit $errorcode
fi

###

echo "Missing log"
removeFiles
sed s/log/loga/ framework.cfg > test.cfg
(./framework > run.out)&
touch /home/dropbox/stop
getErrorCode run.out
if [ "$errorcode" -eq "5" ]; then
    echo " INFO: Error case OK"
else
    echo " ERROR: Error case failed"
    exit $errorcode
fi

echo "Unaccessible log"
removeFiles
cp framework.cfg test.cfg
chmod u-w logs/framework.log
(./framework > run.out)&
touch /home/dropbox/stop
getErrorCode run.out
chmod u+w logs/framework.log
if [ "$errorcode" -eq "3" ]; then
    echo " INFO: Error case OK"
else
    echo " ERROR: Error case failed"
    exit $errorcode
fi

echo "Missing stop_file"
removeFiles
sed s/stop_file/stop_filea/ framework.cfg > test.cfg
(./framework > run.out)&
touch /home/dropbox/stop
getErrorCode run.out
if [ "$errorcode" -eq "5" ]; then
    echo " INFO: Error case OK"
else
    echo " ERROR: Error case failed"
    exit $errorcode
fi

echo "Missing restart_file"
removeFiles
sed s/restart_file/restart_filea/ framework.cfg > test.cfg
(./framework > run.out)&
touch /home/dropbox/stop
getErrorCode run.out
if [ "$errorcode" -eq "5" ]; then
    echo " INFO: Error case OK"
else
    echo " ERROR: Error case failed"
    exit $errorcode
fi

echo "Missing out_body"
removeFiles
sed s/out_body/out_bodya/ framework.cfg > test.cfg
(./framework > run.out)&
touch /home/dropbox/stop
getErrorCode run.out
if [ "$errorcode" -eq "5" ]; then
    echo " INFO: Error case OK"
else
    echo " ERROR: Error case failed"
    exit $errorcode
fi

echo "Unaccessible out_body"
removeFiles
cp framework.cfg test.cfg
chmod u-w obody.txt
(./framework > run.out)&
touch /home/dropbox/stop
getErrorCode run.out
chmod u+w obody.txt
if [ "$errorcode" -eq "5" ]; then
    echo " INFO: Error case OK"
else
    echo " ERROR: Error case failed"
    exit $errorcode
fi

echo "Missing notif_log"
removeFiles
sed s/notif_log/notif_loga/ framework.cfg > test.cfg
(./framework > run.out)&
touch /home/dropbox/stop
getErrorCode run.out
if [ "$errorcode" -eq "5" ]; then
    echo " INFO: Error case OK"
else
    echo " ERROR: Error case failed"
    exit $errorcode
fi

echo "Unaccessible notif_log"
removeFiles
cp framework.cfg test.cfg
chmod u-w nlog.txt
(./framework > run.out)&
touch /home/dropbox/stop
getErrorCode run.out
chmod u+w nlog.txt
if [ "$errorcode" -eq "5" ]; then
    echo " INFO: Error case OK"
else
    echo " ERROR: Error case failed"
    exit $errorcode
fi

echo "Missing full_email"
removeFiles
sed s/full_email/full_emaila/ framework.cfg > test.cfg
(./framework > run.out)&
touch /home/dropbox/stop
getErrorCode run.out
if [ "$errorcode" -eq "5" ]; then
    echo " INFO: Error case OK"
else
    echo " ERROR: Error case failed"
    exit $errorcode
fi

echo "Unaccessible full_email"
removeFiles
cp framework.cfg test.cfg
touch email.txt
chmod u-w email.txt
(./framework > run.out)&
touch /home/dropbox/stop
getErrorCode run.out
chmod u+w email.txt
if [ "$errorcode" -eq "5" ]; then
    echo " INFO: Error case OK"
else
    echo " ERROR: Error case failed"
    cat run.out
    exit $errorcode
fi

echo "Missing in_attachment"
removeFiles
sed s/in_attachment/in_attachmenta/ framework.cfg > test.cfg
(./framework > run.out)&
touch /home/dropbox/stop
getErrorCode run.out
if [ "$errorcode" -eq "5" ]; then
    echo " INFO: Error case OK"
else
    echo " ERROR: Error case failed"
    exit $errorcode
fi

echo "Missing out_attachment"
removeFiles
sed s/out_attachment/out_attachmenta/ framework.cfg > test.cfg
(./framework > run.out)&
touch /home/dropbox/stop
getErrorCode run.out
if [ "$errorcode" -eq "5" ]; then
    echo " INFO: Error case OK"
else
    echo " ERROR: Error case failed"
    exit $errorcode
fi


echo "Missing key"
removeFiles
sed s/key/keya/ framework.cfg > test.cfg
(./framework > run.out)&
touch /home/dropbox/stop
getErrorCode run.out
if [ "$errorcode" -eq "5" ]; then
    echo " INFO: Error case OK"
else
    echo " ERROR: Error case failed"
    exit $errorcode
fi

echo "Missing master key file"
removeFiles
sed s/key=masterkey.bin/key=masterkey.bina/ framework.cfg > test.cfg
(./framework > run.out)&
touch /home/dropbox/stop
getErrorCode run.out
if [ "$errorcode" -eq "5" ]; then
    echo " INFO: Error case OK"
else
    echo " ERROR: Error case failed"
    exit $errorcode
fi

echo "Unaccessible master key file"
removeFiles
cp framework.cfg test.cfg
chmod a-r masterkey.bin
(./framework > run.out)&
touch /home/dropbox/stop
getErrorCode run.out
chmod a+r masterkey.bin
if [ "$errorcode" -eq "5" ]; then
    echo " INFO: Error case OK"
else
    echo " ERROR: Error case failed"
    exit $errorcode
fi

echo "Too large master key file"
removeFiles
sed s/key=masterkey.bin/key=athenakey.tok/ framework.cfg > test.cfg
(./framework > run.out)&
touch /home/dropbox/stop
getErrorCode run.out
if [ "$errorcode" -eq "5" ]; then
    echo " INFO: Error case OK"
else
    echo " ERROR: Error case failed"
    exit $errorcode
fi

echo "Too small master key file"
removeFiles
sed s/key=masterkey.bin/key=email.txt/ framework.cfg > test.cfg
(./framework > run.out)&
touch /home/dropbox/stop
getErrorCode run.out
if [ "$errorcode" -eq "4" ]; then
    echo " INFO: Error case OK"
else
    echo " ERROR: Error case failed"
    cat run.out
    exit $errorcode
fi

#echo "Invalid master key file"
#removeFiles
#sed s/key=masterkey.bin/key=badmasterkey.bin/ framework.cfg > test.cfg
#(./framework > run.out)&
#touch /home/dropbox/stop
#getReasonCode run.out
#if [ "$reasoncode" -eq "20" ]; then
#    echo " INFO: Error case OK"
#else
#    echo " ERROR: Error case failed"
#    cat run.out
#    exit $errorcode
#fi



echo "Bad project format"
removeFiles
sed s/athena=/athena/ framework.cfg > test.cfg
(./framework > run.out)&
touch /home/dropbox/stop
getErrorCode run.out
if [ "$errorcode" -eq "5" ]; then
    echo " INFO: Error case OK"
else
    echo " ERROR: Error case failed"
    exit $errorcode
fi

echo "Missing project config file"
removeFiles
sed s/athena=athena.cfg/athenaathena.cfga/ framework.cfg > test.cfg
(./framework > run.out)&
touch /home/dropbox/stop
getErrorCode run.out
if [ "$errorcode" -eq "5" ]; then
    echo " INFO: Error case OK"
else
    echo " ERROR: Error case failed"
    exit $errorcode
fi

echo "Unaccessible project config file"
removeFiles
cp framework.cfg test.cfg
chmod a-r athena.cfg
(./framework > run.out)&
touch /home/dropbox/stop
getErrorCode run.out
chmod a+r athena.cfg
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

exit 0

