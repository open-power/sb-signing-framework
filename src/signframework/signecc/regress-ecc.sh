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
# signer framework regression test - cosigner tests
#
# Run this script locally
#
# Prerequisites:
#	The coprocessor should have a profile (user) $USER with password $PWD.  See below.
#

#set -x

ECCKEY_A_TOK=tmpkeya.tok
ECCKEY_B_TOK=tmpkeyb.tok
ECCKEY_C_TOK=tmpkeyc.tok
ECCKEY_P_TOK=tmpkeyp.tok
ECCKEY_Q_TOK=tmpkeyq.tok
ECCKEY_R_TOK=tmpkeyr.tok

ECCKEY_A_BIN=tmpkeya.bin
ECCKEY_B_BIN=tmpkeyb.bin
ECCKEY_C_BIN=tmpkeyc.bin
ECCKEY_P_BIN=tmpkeyp.bin
ECCKEY_Q_BIN=tmpkeyq.bin
ECCKEY_R_BIN=tmpkeyr.bin

# CCA test user and password
USER=test
PWD=qazTGB

# output email body, for error messages
OBODY=tmpobody.txt

# aux config file
AUXCONFIG=tmpaux.cfg
AUXCONFIGA=tmpauxa.cfg

# audit log
AUDITLOG=tmp.log

# signature
SIGFILE=tmpsig.bin

removeFiles()
{
    rm -f $AUXCONFIG
    rm -f $AUXCONFIGA
    rm -f $OBODY
}

# searches $1 for "Return code:" and returns the value */

getReturnCode()
{
    returncode=`grep -m 1 "Return code:" $1 | gawk '{print $3 }'`
    return $returncode
}

# searches $1 for "ERRORnnnn" and returns the value */

getErrorCode()
{
    errorcode=`grep -m 1 "ERROR" $1 | gawk '{print $1}' | sed s/ERROR// | sed s/:// `
    return $errorcode
}

# searches $1 for "ERRORnnnn" at the end of the file and returns the value */

getLastErrorCode()
{
    errorcode=`tail -1 $1 | grep -m 1 "ERROR" | gawk '{print $1}' | sed s/ERROR// | sed s/:// `
    return $errorcode
}

# searches $1 for "reason_code" and returns the value */

getReasonCode()
{
    reasoncode=`grep -m 1 "reason_code" $1 | gawk '{print $6}' `
    return $reasoncode
}

sendFile()
{
./signecc -obody $OBODY -usr $USER -pwd $PWD -sender "test@email.com" -log $AUDITLOG -key $ECCKEY_A_TOK -auxcfg "$1" -di b64.bin -do $SIGFILE -project RegressionTest "$2"

}

#
# Regression Tests Start Here ...
#

echo "Create six test keys"
../keygeneccp521 -k $ECCKEY_A_TOK -p $ECCKEY_A_BIN -u $USER $PWD
../keygeneccp521 -k $ECCKEY_B_TOK -p $ECCKEY_B_BIN -u $USER $PWD
../keygeneccp521 -k $ECCKEY_C_TOK -p $ECCKEY_C_BIN -u $USER $PWD
../keygeneccp521 -k $ECCKEY_P_TOK -p $ECCKEY_P_BIN -u $USER $PWD
../keygeneccp521 -k $ECCKEY_Q_TOK -p $ECCKEY_Q_BIN -u $USER $PWD
../keygeneccp521 -k $ECCKEY_R_TOK -p $ECCKEY_R_BIN -u $USER $PWD


# check_unique false

echo "Testing Basic ECC hwa success case"
removeFiles
sendFile signeccsample-hwaux.cfg
getReturnCode $OBODY
if [ "$returncode" -eq "0" ]; then
    echo " INFO: Basic ECC hwa success case OK"
else
    echo " ERROR: Basic ECC hwa success case failed"
    exit $returncode
fi

# auxiliary cfg tests

echo "Testing Missing aux config file - ERROR2001"
removeFiles
sendFile signeccsample-hwaux.cfgxxx
getReturnCode $OBODY
getErrorCode $OBODY
if [ "$returncode" -eq "1" ] && [ "$errorcode" -eq "2001" ]; then
    echo " INFO: Missing aux config file OK"
else
    echo " ERROR: Missing aux config file failed"
    exit $returncode
fi

echo "Testing Missing Sign Algorithm - ERROR2002"
removeFiles
sed /sign_algorithm/d signeccsample-hwaux.cfg > $AUXCONFIG
sendFile $AUXCONFIG
getReturnCode $OBODY
getErrorCode $OBODY
if [ "$returncode" -eq "1" ] && [ "$errorcode" -eq "2002" ]; then
    echo " INFO: Missing Sign Algorithm OK"
else
    echo " ERROR: Missing Sign Algorithm failed"
    exit $returncode
fi

echo "Testing Bad Sign Algorithm - ERROR1027"
removeFiles
sed s/eccp521/rsa/ signeccsample-hwaux.cfg > $AUXCONFIG
sendFile $AUXCONFIG
getReturnCode $OBODY
getErrorCode $OBODY
if [ "$returncode" -eq "1" ] && [ "$errorcode" -eq "1027" ]; then
    echo " INFO: Bad Sign Algorithm - OK"
else
    echo " ERROR: Bad Sign Algorithm - failed"
    exit $returncode
fi

echo "Testing Missing digest algorithm - ERROR2004"
removeFiles
sed /digest_algorithm/d signeccsample-hwaux.cfg > $AUXCONFIG
sendFile $AUXCONFIG
getReturnCode $OBODY
getErrorCode $OBODY
if [ "$returncode" -eq "1" ] && [ "$errorcode" -eq "2004" ]; then
    echo " INFO: Missing digest algorithm OK"
else
    echo " ERROR: Missing digest algorithm failed"
    exit $returncode
fi

echo "Testing Bad digest algorithm - ERROR1028"
removeFiles
sed s/SHA-512/SHA-256/ signeccsample-hwaux.cfg > $AUXCONFIG
sendFile $AUXCONFIG
getReturnCode $OBODY
getErrorCode $OBODY
if [ "$returncode" -eq "1" ] && [ "$errorcode" -eq "1028" ]; then
    echo " INFO: Bad digest algorithm OK"
else
    echo " ERROR: Bad digest algorithm failed"
    exit $returncode
fi

echo "Testing Bad check unique value - ERROR2005"
removeFiles
sed s/check_unique=false/check_unique=falsexxx/ signeccsample-hwaux.cfg > $AUXCONFIG
sendFile $AUXCONFIG
getReturnCode $OBODY
getErrorCode $OBODY
if [ "$returncode" -eq "1" ] && [ "$errorcode" -eq "2005" ]; then
    echo " INFO: Bad check unique value OK"
else
    echo " ERROR: Bad check unique value failed"
    exit $returncode
fi

echo "Testing cfg file count illegal - ERROR2006"
removeFiles
sed s/cfg_files=3/cfg_files=3a/ signeccsample-hwaux.cfg > $AUXCONFIG
sendFile $AUXCONFIG -v
getReturnCode $OBODY
getErrorCode $OBODY
if [ "$returncode" -eq "1" ] && [ "$errorcode" -eq "2006" ]; then
    echo " INFO: cfg file count illegal OK"
else
    echo " ERROR: cfg file count illegal failed"
    exit $returncode
fi

echo "Testing cfg file count too large >100 - ERROR2007"
removeFiles
sed s/cfg_files=3/cfg_files=101/ signeccsample-hwaux.cfg > $AUXCONFIG
sendFile $AUXCONFIG -v
getReturnCode $OBODY
getErrorCode $OBODY
if [ "$returncode" -eq "1" ] && [ "$errorcode" -eq "2007" ]; then
    echo " INFO: cfg file count too largeOK"
else
    echo " ERROR: cfg file count too largefailed"
    exit $returncode
fi

echo "Testing cfg file count 0 - ERROR2008 "
removeFiles
sed s/cfg_files=3/cfg_files=0/ signeccsample-hwaux.cfg > $AUXCONFIG
sendFile $AUXCONFIG
getReturnCode $OBODY
getErrorCode $OBODY
if [ "$returncode" -eq "1" ] && [ "$errorcode" -eq "2008" ]; then
    echo " INFO: cfg file count 0 OK"
else
    echo " ERROR: cfg file count 0 failed"
    exit $returncode
fi

echo "Testing cfg files too small - ERROR2009"
removeFiles
sed s/cfg_files=3/cfg_files=4/ signeccsample-hwaux.cfg > $AUXCONFIG
sendFile $AUXCONFIG
getReturnCode $OBODY
getErrorCode $OBODY
if [ "$returncode" -eq "1" ] && [ "$errorcode" -eq "2009" ]; then
    echo " INFO: cfg files too small OK"
else
    echo " ERROR: cfg files too small failed"
    exit $returncode
fi

echo "Testing cfg file missing - ERROR2010"
removeFiles
sed s/signeccsample-hwa.cfg/signeccsample-hwaxxx.cfg/ signeccsample-hwaux.cfg > $AUXCONFIGA
sed s/check_unique=false/check_unique=true/ $AUXCONFIGA > $AUXCONFIG
sendFile $AUXCONFIG
getReturnCode $OBODY
getErrorCode $OBODY
if [ "$returncode" -eq "1" ] && [ "$errorcode" -eq "2010" ]; then
    echo " INFO: cfg file missing OK"
else
    echo " ERROR: cfg file missing failed"
    exit $returncode
fi


# input files

echo "Testing read only audit log - ERROR1018"
removeFiles
touch $AUDITLOG
chmod a-w $AUDITLOG
sendFile signeccsample-hwaux.cfg
chmod u+w $AUDITLOG
getReturnCode $OBODY
getErrorCode $OBODY
if [ "$returncode" -eq "1" ] && [ "$errorcode" -eq "1018" ]; then
    echo " INFO: read only audit log OK"
else
    echo " ERROR: read only audit log failed"
    exit $returncode
fi

echo "Testing missing key file - ERROR1019"
removeFiles
mv $ECCKEY_A_TOK ${ECCKEY_A_TOK}.save
sendFile signeccsample-hwaux.cfg
cp ${ECCKEY_A_TOK}.save ${ECCKEY_A_TOK}
getReturnCode $OBODY
getErrorCode $OBODY
if [ "$returncode" -eq "1" ] && [ "$errorcode" -eq "1019" ]; then
    echo " INFO: missing key file OK"
else
    echo " ERROR: missing key file failed"
    exit $returncode
fi

echo "Testing not readable key file - ERROR1019"
removeFiles
chmod a-r ${ECCKEY_A_TOK}
sendFile signeccsample-hwaux.cfg
chmod a+r ${ECCKEY_A_TOK}
getReturnCode $OBODY
getErrorCode $OBODY
if [ "$returncode" -eq "1" ] && [ "$errorcode" -eq "1019" ]; then
    echo " INFO: not readable key file OK"
else
    echo " ERROR: not readable key file failed"
    exit $returncode
fi

echo "Testing read only attachment - ERROR1020"
removeFiles
chmod a-r b64.bin
sendFile signeccsample-hwaux.cfg
chmod a+r b64.bin
getReturnCode $OBODY
getErrorCode $OBODY
if [ "$returncode" -eq "1" ] && [ "$errorcode" -eq "1020" ]; then
    echo " INFO: read only attachment OK"
else
    echo " ERROR: read only attachment failed"
    exit $returncode
fi

echo "Testing read only output file - ERROR1023"
removeFiles
chmod a-w $SIGFILE
sendFile signeccsample-hwaux.cfg
chmod u+w $SIGFILE
getReturnCode $OBODY
getErrorCode $OBODY
if [ "$returncode" -eq "1" ] && [ "$errorcode" -eq "1023" ]; then
    echo " INFO: read only attachment OK"
else
    echo " ERROR: read only attachment failed"
    exit $returncode
fi

#
# command line arguments
#

echo "Testing missing value for -usr - ERROR1002"
removeFiles
./signecc -obody $OBODY -pwd $PWD -sender "test@email.com" -log $AUDITLOG -key $ECCKEY_A_TOK -auxcfg signeccsample-hwaux.cfg -di b64.bin -do $SIGFILE -project RegressionTest -usr  
sendFile 
getReturnCode $OBODY
getErrorCode $OBODY
if [ "$returncode" -eq "1" ] && [ "$errorcode" -eq "1002" ]; then
    echo " INFO:  missing value for -usr OK"
else
    echo " ERROR:  missing value for -usr failed"
    exit $returncode
fi

echo "Testing missing value for -pwd - ERROR1003"
removeFiles
./signecc -obody $OBODY -usr $USER -sender "test@email.com" -log $AUDITLOG -key $ECCKEY_A_TOK -auxcfg signeccsample-hwaux.cfg -di b64.bin -do $SIGFILE -project RegressionTest -pwd
getReturnCode $OBODY
getErrorCode $OBODY
if [ "$returncode" -eq "1" ] && [ "$errorcode" -eq "1003" ]; then
    echo " INFO: missing value for -pwd OK"
else
    echo " ERROR: missing value for -pwd failed"
    exit $returncode
fi

echo "Testing missing value for -log - ERROR1004 "
removeFiles
./signecc -obody $OBODY -usr $USER -pwd $PWD -sender "test@email.com" -key $ECCKEY_A_TOK -auxcfg signeccsample-hwaux.cfg -di b64.bin -do $SIGFILE -project RegressionTest -log
getReturnCode $OBODY
getErrorCode $OBODY
if [ "$returncode" -eq "1" ] && [ "$errorcode" -eq "1004" ]; then
    echo " INFO: missing value for -log OK"
else
    echo " ERROR: missing value for -log failed"
    exit $returncode
fi

echo "Testing missing value for -sender - ERROR1005"
removeFiles
./signecc -obody $OBODY -usr $USER -pwd $PWD -log $AUDITLOG -key $ECCKEY_A_TOK -auxcfg signeccsample-hwaux.cfg -di b64.bin -do $SIGFILE -project RegressionTest -sender 
getReturnCode $OBODY
getErrorCode $OBODY
if [ "$returncode" -eq "1" ] && [ "$errorcode" -eq "1005" ]; then
    echo " INFO: missing value for -sender OK"
else
    echo " ERROR: missing value for -sender failed"
    exit $returncode
fi

echo "Testing missing value for -project - ERROR1006"
removeFiles
./signecc -obody $OBODY -usr $USER -pwd $PWD -sender "test@email.com" -log $AUDITLOG -key $ECCKEY_A_TOK -auxcfg signeccsample-hwaux.cfg -di b64.bin -do $SIGFILE -project
getReturnCode $OBODY
getErrorCode $OBODY
if [ "$returncode" -eq "1" ] && [ "$errorcode" -eq "1006" ]; then
    echo " INFO: missing value for -project OK"
else
    echo " ERROR: missing value for -project failed"
    exit $returncode
fi

echo "Testing missing value for -key - ERROR1007 "
removeFiles
./signecc -obody $OBODY -usr $USER -pwd $PWD -sender "test@email.com" -log $AUDITLOG -auxcfg signeccsample-hwaux.cfg -di b64.bin -do $SIGFILE -project RegressionTest -key
getReturnCode $OBODY
getErrorCode $OBODY
if [ "$returncode" -eq "1" ] && [ "$errorcode" -eq "1007" ]; then
    echo " INFO: missing value for -key OK"
else
    echo " ERROR: missing value for -key failed"
    exit $returncode
fi

echo "Testing missing value for -auxcfg - ERROR1008"
removeFiles
./signecc -obody $OBODY -usr $USER -pwd $PWD -sender "test@email.com" -log $AUDITLOG -key $ECCKEY_A_TOK -di b64.bin -do $SIGFILE -project RegressionTest -auxcfg 
sendFile signeccsample-hwaux.cfg
getReturnCode $OBODY
getErrorCode $OBODY
if [ "$returncode" -eq "1" ] && [ "$errorcode" -eq "1008" ]; then
    echo " INFO: missing value for -auxcfg OK"
else
    echo " ERROR: missing value for -auxcfg failed"
    exit $returncode
fi

echo "Testing missing value for -di - ERROR1009"
removeFiles
./signecc -obody $OBODY -usr $USER -pwd $PWD -sender "test@email.com" -log $AUDITLOG -key $ECCKEY_A_TOK -auxcfg signeccsample-hwaux.cfg -do $SIGFILE -project RegressionTest -di
getReturnCode $OBODY
getErrorCode $OBODY
if [ "$returncode" -eq "1" ] && [ "$errorcode" -eq "1009" ]; then
    echo " INFO: missing value for -di OK"
else
    echo " ERROR: missing value for -di failed"
    exit $returncode
fi

echo "Testing missing value for -do - ERROR1010"
removeFiles
./signecc -obody $OBODY -usr $USER -pwd $PWD -sender "test@email.com" -log $AUDITLOG -key $ECCKEY_A_TOK -auxcfg signeccsample-hwaux.cfg -di b64.bin -project RegressionTest -do 
getReturnCode $OBODY
getErrorCode $OBODY
if [ "$returncode" -eq "1" ] && [ "$errorcode" -eq "1010" ]; then
    echo " INFO: missing value for -do OK"
else
    echo " ERROR: missing value for -do failed"
    exit $returncode
fi

echo "Testing missing -usr - ERROR1011 "
removeFiles
./signecc -obody $OBODY -pwd $PWD -sender "test@email.com" -log $AUDITLOG -key $ECCKEY_A_TOK -auxcfg signeccsample-hwaux.cfg -di b64.bin -do $SIGFILE -project RegressionTest
getReturnCode $OBODY
getErrorCode $OBODY
if [ "$returncode" -eq "1" ] && [ "$errorcode" -eq "1011" ]; then
    echo " INFO: missing -usr OK"
else
    echo " ERROR: missing -usr failed"
    exit $returncode
fi

echo "Testing bad usr - ERROR1024 "
removeFiles
./signecc -obody $OBODY -usr ${USER}x -pwd $PWD -sender "test@email.com" -log $AUDITLOG -key $ECCKEY_A_TOK -auxcfg signeccsample-hwaux.cfg -di b64.bin -do $SIGFILE -project RegressionTest
getReturnCode $OBODY
getErrorCode $OBODY
if [ "$returncode" -eq "1" ] && [ "$errorcode" -eq "1024" ]; then
    echo " INFO: bad usr OK"
else
    echo " ERROR: bad usr failed"
    exit $returncode
fi

echo "Testing missing -pwd - ERROR1012 "
removeFiles
./signecc -obody $OBODY -usr $USER -sender "test@email.com" -log $AUDITLOG -key $ECCKEY_A_TOK -auxcfg signeccsample-hwaux.cfg -di b64.bin -do $SIGFILE -project RegressionTest
getReturnCode $OBODY
getErrorCode $OBODY
if [ "$returncode" -eq "1" ] && [ "$errorcode" -eq "1012" ]; then
    echo " INFO: missing -pwd OK"
else
    echo " ERROR: missing -pwd failed"
    exit $returncode
fi

echo "Testing bad -pwd - ERROR1024 "
removeFiles
./signecc -obody $OBODY -usr $USER -pwd aaaaa -sender "test@email.com" -log $AUDITLOG -key $ECCKEY_A_TOK -auxcfg signeccsample-hwaux.cfg -di b64.bin -do $SIGFILE -project RegressionTest
getReturnCode $OBODY
getErrorCode $OBODY
if [ "$returncode" -eq "1" ] && [ "$errorcode" -eq "1024" ]; then
    echo " INFO: bad -pwd OK"
else
    echo " ERROR: bad -pwd failed"
    exit $returncode
fi

echo "Testing missing -sender - ERROR1013 "
removeFiles
./signecc -obody $OBODY -usr $USER -pwd $PWD -log $AUDITLOG -key $ECCKEY_A_TOK -auxcfg signeccsample-hwaux.cfg -di b64.bin -do $SIGFILE -project RegressionTest
sendFile signeccsample-hwaux.cfg
getReturnCode $OBODY
getErrorCode $OBODY
if [ "$returncode" -eq "1" ] && [ "$errorcode" -eq "1013" ]; then
    echo " INFO: OK"
else
    echo " ERROR: failed"
    exit $returncode
fi

echo "Testing missing -log - ERROR1014 "
removeFiles
./signecc -obody $OBODY -usr $USER -pwd $PWD -sender "test@email.com" -key $ECCKEY_A_TOK -auxcfg signeccsample-hwaux.cfg -di b64.bin -do $SIGFILE -project RegressionTest
sendFile signeccsample-hwaux.cfg
getReturnCode $OBODY
getErrorCode $OBODY
if [ "$returncode" -eq "1" ] && [ "$errorcode" -eq "1014" ]; then
    echo " INFO: OK"
else
    echo " ERROR: failed"
    exit $returncode
fi

echo "Testing missing -key - ERROR1015 "
removeFiles
./signecc -obody $OBODY -usr $USER -pwd $PWD -sender "test@email.com" -log $AUDITLOG -auxcfg signeccsample-hwaux.cfg -di b64.bin -do $SIGFILE -project RegressionTest
sendFile signeccsample-hwaux.cfg
getReturnCode $OBODY
getErrorCode $OBODY
if [ "$returncode" -eq "1" ] && [ "$errorcode" -eq "1015" ]; then
    echo " INFO: OK"
else
    echo " ERROR: failed"
    exit $returncode
fi

echo "Testing missing -auxcfg - ERROR1026 "
removeFiles
./signecc -obody $OBODY -usr $USER -pwd $PWD -sender "test@email.com" -log $AUDITLOG -key $ECCKEY_A_TOK -di b64.bin -do $SIGFILE -project RegressionTest
sendFile signeccsample-hwaux.cfg
getReturnCode $OBODY
getErrorCode $OBODY
if [ "$returncode" -eq "1" ] && [ "$errorcode" -eq "1026" ]; then
    echo " INFO: OK"
else
    echo " ERROR: failed"
    exit $returncode
fi

echo "Testing missing -di - ERROR1016 "
removeFiles
./signecc -obody $OBODY -usr $USER -pwd $PWD -sender "test@email.com" -log $AUDITLOG -key $ECCKEY_A_TOK -auxcfg signeccsample-hwaux.cfg -do $SIGFILE -project RegressionTest
sendFile signeccsample-hwaux.cfg
getReturnCode $OBODY
getErrorCode $OBODY
if [ "$returncode" -eq "1" ] && [ "$errorcode" -eq "1016" ]; then
    echo " INFO: OK"
else
    echo " ERROR: failed"
    exit $returncode
fi

echo "Testing missing -do - ERROR1017 "
removeFiles
./signecc -obody $OBODY -usr $USER -pwd $PWD -sender "test@email.com" -log $AUDITLOG -key $ECCKEY_A_TOK -auxcfg signeccsample-hwaux.cfg -di b64.bin -project RegressionTest
sendFile signeccsample-hwaux.cfg
getReturnCode $OBODY
getErrorCode $OBODY
if [ "$returncode" -eq "1" ] && [ "$errorcode" -eq "1017" ]; then
    echo " INFO: OK"
else
    echo " ERROR: failed"
    exit $returncode
fi

echo ""
echo "Tests Passed"
echo ""

removeFiles
rm $SIGFILE
rm $AUDITLOG
rm ${ECCKEY_A_TOK}.save

rm -f $ECCKEY_A_TOK
rm -f $ECCKEY_B_TOK
rm -f $ECCKEY_C_TOK
rm -f $ECCKEY_P_TOK
rm -f $ECCKEY_Q_TOK
rm -f $ECCKEY_R_TOK

rm -f $ECCKEY_A_BIN
rm -f $ECCKEY_B_BIN
rm -f $ECCKEY_C_BIN
rm -f $ECCKEY_P_BIN
rm -f $ECCKEY_Q_BIN
rm -f $ECCKEY_R_BIN

exit 0

