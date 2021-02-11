#!/bin/bash
#
#			sign_cert Regression Test
#			     Written by Ken Goldman, Ported by Nick Child (2021)
#		       IBM Thomas J. Watson Research Center
#	      $Id: regression.sh 433 2014-03-05 21:58:40Z kgoldman $
#
#			       IBM Confidential
#			     OCO Source Materials
#			 (c) Copyright IBM Corp. 2013
#
#	   The source code for this program is not published or otherwise
#	   divested of its trade secrets, irrespective of what has been
#	   deposited with the U.S. Copyright Office
#

# Run this script from client side

# before running, make sure to run generateTestFiles on server, and set test config as framework config

#also fill below fields with valid infomation: GOOD_USR, USR_EPWD, USR_PKEY, FRMWRK_HOST 
#to run ./sign_cert_tests <private key password>

rm regression.log

#currently storing password, FIXME
P=$1

OUT_DIR=out
rm -r $OUT_DIR
mkdir $OUT_DIR

MSG_FILE=${OUT_DIR}/msg.txt
GOOD_USR=foob #userid for signing framework
USR_EPWD=pswd.txt  #encrypted userid password
USR_PKEY=id_rsa	#private key for sftp connection
FRMWRK_HOST=machine.example.com
#sample name for a valid project
SAMPLE_ROOT=issuer_root
SAMPLE_FINAL=issuer_final
SAMPLE_PROJECT=code_signer
#base name of projects
BASE_ROOT=issuer_root_test
BASE_FINAL=issuer_final_test
BASE_CERTIFY=code_signer_test

TEST_CTR=0

# $1 project
# $2 -certify_project
# $3 -out
# sets RC to return code
sendCommand()
{
	echo $P | ./sf_client -project $1 -comments "Testing sign cert" -param "-certify_project $2 -usr $GOOD_USR" -url sftp://${GOOD_USR}@${FRMWRK_HOST} -epwd $USR_EPWD -pkey $USR_PKEY -o $3 -stdout > $MSG_FILE
	RC=$?

}
# $1 ROOT project
# $2 CA project
# $3 certify project

sendTestCase()
{
    echo "Self signed root"
    sendCommand $1 $1 ${OUT_DIR}/certroot.der
    if [ "$RC" -eq 0 ]; then
	echo " INFO: success case"
    else
	echo " ERROR: failed success case"
	exit 1
    fi  

    echo "Root signing certifier"
    sendCommand $1 $2 ${OUT_DIR}/certsign.der
    if [ "$RC" -eq 0 ]; then
	echo " INFO: success case"
    else
	echo " ERROR: failed success case"
	exit 1
    fi  

    echo "Certifier signing code signing key"
    sendCommand ${2} ${3} ${OUT_DIR}/certproject.der
    if [ "$RC" -eq 0 ]; then
	echo " INFO: success case"
    else
	echo " ERROR: failed success case"
	exit 1
    fi  

    echo "Converting certificates from der to pem"
    openssl x509 -in ${OUT_DIR}/certroot.der    -inform DER -out ${OUT_DIR}/certroot.pem
    openssl x509 -in ${OUT_DIR}/certsign.der    -inform DER -out ${OUT_DIR}/certsign.pem
    openssl x509 -in ${OUT_DIR}/certproject.der -inform DER -out ${OUT_DIR}/certproject.pem

    echo "Creating the certificate chain"

    cat ${OUTDIR}/certroot.pem ${OUTDIR}/certsign.pem ${OUTDIR}/certproject.pem > ${OUTDIR}/certchain.pem
    
    echo "Writing the certificates to dump files"
    openssl x509 -text -in ${OUTDIR}/certroot.pem    -noout > ${OUTDIR}/certroot.dump
    openssl x509 -text -in ${OUTDIR}/certsign.pem    -noout > ${OUTDIR}/certsign.dump
    openssl x509 -text -in ${OUTDIR}/certproject.pem -noout > ${OUTDIR}/certproject.dump

    # openssl bug - returns 0 on failure - thus the grep for error

    echo "Verifying self signed root"
    openssl verify -check_ss_sig -CAfile ${OUTDIR}/certchain.pem ${OUTDIR}/certroot.pem > ${OUTDIR}/run.log
    grep error ${OUTDIR}/run.log > ${OUTDIR}/run.tmp
    ERR=$?
    if [ $ERR -eq 0 ]; then
	echo " ERROR: Could not verify the root certificate against the root certificate"
	exit 1
    else
	echo " INFO: Could verify the root certificate against the root certificate"
    fi

    echo "Verifying signing certificate"
    openssl verify -check_ss_sig -CAfile ${OUTDIR}/certchain.pem ${OUTDIR}/certsign.pem > ${OUTDIR}/run.log
    grep error ${OUTDIR}/run.log > ${OUTDIR}/run.tmp
    ERR=$?
    if [ $ERR -eq 0 ]; then
	echo " ERROR: Could not verify the signing certificate against the root certificate"
	exit 1
    else
	echo " INFO: Could verify the signing certificate against the root certificate"
    fi

    echo "Verifying project certificate"
    openssl verify -check_ss_sig -CAfile ${OUTDIR}/certchain.pem ${OUTDIR}/certproject.pem > ${OUTDIR}/run.log
    grep error ${OUTDIR}/run.log > ${OUTDIR}/run.tmp
    ERR=$?
    if [ $ERR -eq 0 ]; then
	echo " ERROR: Could not verify project the certificate against the signing certificate"
	exit 1
    else
	echo " INFO: Could verify the project certificate against the signing certificate"
    fi
}

getErrorCode()
{
    errorcode=`grep "ERROR" $1 | gawk '{print $1}' | sed s/ERROR// | sed s/:// `
    return $errorcode
}

#
# Initialization
#

#
# Test Cases Start Here
#

date


echo ""
echo "Command Line Option Error Cases"
echo ""

echo "Test -h"
echo $P | ./sf_client -project $SAMPLE_ROOT -comments "Testing sign cert" -param "-h" -url sftp://$GOOD_USR@${FRMWRK_HOST} -epwd $USR_EPWD -pkey $USR_PKEY -o ${OUT_DIR}/help.txt -stdout > $MSG_FILE
RC=$?

if [ $RC -ne 0 ]; then
    echo " ERROR: -h"
    exit 1
else
    echo " INFO: -h"
fi

echo "Test -usr missing"
echo $P | ./sf_client -project $SAMPLE_ROOT -comments "Testing sign cert" -param "-certify_project $BASE_FINAL" -url sftp://$GOOD_USR@${FRMWRK_HOST} -epwd $USR_EPWD -pkey $USR_PKEY -o ${OUT_DIR}/out.txt -stdout > $MSG_FILE
RC=$?
getErrorCode $MSG_FILE
if [ "$RC" -ne 0 ] && [ "$errorcode" -eq "1011" ]; then
    echo " INFO: -usr missing"
else
    echo " ERROR: -usr missing"
    exit 1
fi  

echo "Test -pwd missing"
sendCommand ${BASE_ROOT}${TEST_CTR} $SAMPLE_FINAL ${OUT_DIR}/out.txt 
getErrorCode $MSG_FILE
if [ "$RC" -ne 0 ] && [ "$errorcode" -eq "1012" ]; then
    echo " INFO: -pwd missing"
else
    echo " ERROR: -pwd missing"
    exit 1
fi  
((TEST_CTR+=1))


echo "Test -auxcfg missing"
sendCommand ${BASE_ROOT}${TEST_CTR} $SAMPLE_FINAL ${OUT_DIR}/out.txt
getErrorCode $MSG_FILE
if [ "$RC" -ne 0 ] && [ "$errorcode" -eq "1014" ]; then
    echo " INFO: -auxcfg missing"
else
    echo " ERROR: -auxcfg missing"
    exit 1
fi  
((TEST_CTR+=1))


echo "Test -certify_project missing"
echo $P | ./sf_client -project $SAMPLE_ROOT -comments "Testing sign cert" -param "-usr $GOOD_USR" -url sftp://$GOOD_USR@${FRMWRK_HOST} -epwd $USR_EPWD -pkey $USR_PKEY -o ${OUT_DIR}/out.txt -stdout > $MSG_FILE
RC=$?
getErrorCode $MSG_FILE
if [ "$RC" -ne 0 ] && [ "$errorcode" -eq "1017" ]; then
    echo " INFO: -certify_project missing"
else
    echo " ERROR: -certify_project missing"
    exit 1
fi  

echo "Test -key missing"
sendCommand ${BASE_ROOT}${TEST_CTR} $SAMPLE_FINAL ${OUT_DIR}/out.txt
getErrorCode $MSG_FILE
if [ "$RC" -ne 0 ] && [ "$errorcode" -eq "1018" ]; then
    echo " INFO: -key missing"
else
    echo " ERROR: -key missing"
    exit 1
fi  
((TEST_CTR+=1))

echo "Test -do missing"
sendCommand ${BASE_ROOT}${TEST_CTR} $SAMPLE_FINAL ${OUT_DIR}/out.txt
getErrorCode $MSG_FILE
if [ "$RC" -ne 0 ] && [ "$errorcode" -eq "1019" ]; then
    echo " INFO: -do missing"
else
    echo " ERROR: -do missing"
    exit 1
fi  
((TEST_CTR+=1))

echo ""
echo "Auxiliary Configuration File Error Cases"
echo ""

echo "Test auxcfg missing sign_algorithm"
sendCommand ${BASE_ROOT}${TEST_CTR} $SAMPLE_FINAL ${OUT_DIR}/out.txt
getErrorCode $MSG_FILE
if [ "$RC" -ne 0 ] && [ "$errorcode" -eq "1053" ]; then
    echo " INFO: auxcfg missing sign_algorithm"
else
    echo " ERROR: auxcfg missing sign_algorithm"
    exit 1
fi  
((TEST_CTR+=1))

echo "Test auxcfg bad sign_algorithm"
sendCommand ${BASE_ROOT}${TEST_CTR} $SAMPLE_FINAL ${OUT_DIR}/out.txt
getErrorCode $MSG_FILE
if [ "$RC" -ne 0 ] && [ "$errorcode" -eq "1202" ]; then
    echo " INFO: auxcfg bad sign_algorithm"
else
    echo " ERROR: auxcfg bad sign_algorithm"
    exit 1
fi  
((TEST_CTR+=1))

echo "Test auxcfg missing digest_algorithm"
sendCommand ${BASE_ROOT}${TEST_CTR} $SAMPLE_FINAL ${OUT_DIR}/out.txt
getErrorCode $MSG_FILE
if [ "$RC" -ne 0 ] && [ "$errorcode" -eq "1054" ]; then
    echo " INFO: auxcfg missing digest_algorithm"
else
    echo " ERROR: auxcfg missing digest_algorithm"
    exit 1
fi  
((TEST_CTR+=1))

echo "Test auxcfg bad digest_algorithm"
sendCommand ${BASE_ROOT}${TEST_CTR} $SAMPLE_FINAL ${OUT_DIR}/out.txt
getErrorCode $MSG_FILE
if [ "$RC" -ne 0 ] && [ "$errorcode" -eq "1201" ]; then
    echo " INFO: auxcfg bad digest_algorithm"
else
    echo " ERROR: auxcfg bad digest_algorithm"
    exit 1
fi  
((TEST_CTR+=1))

echo "Test auxcfg missing validity"
sendCommand ${BASE_ROOT}${TEST_CTR} $SAMPLE_FINAL ${OUT_DIR}/out.txt
getErrorCode $MSG_FILE
if [ "$RC" -ne 0 ] && [ "$errorcode" -eq "1055" ]; then
    echo " INFO: auxcfg missing validity"
else
    echo " ERROR: auxcfg missing validity"
    exit 1
fi  
((TEST_CTR+=1))

echo "Test auxcfg bad validity"
sendCommand ${BASE_ROOT}${TEST_CTR} $SAMPLE_FINAL ${OUT_DIR}/out.txt
getErrorCode $MSG_FILE
if [ "$RC" -ne 0 ] && [ "$errorcode" -eq "1055" ]; then
    echo " INFO: auxcfg bad validity"
else
    echo " ERROR: auxcfg bad validity"
    exit 1
fi  
((TEST_CTR+=1))

echo "Test auxcfg missing issuerCountryName"
sendCommand ${BASE_ROOT}${TEST_CTR} $SAMPLE_FINAL ${OUT_DIR}/out.txt
getErrorCode $MSG_FILE
if [ "$RC" -ne 0 ] && [ "$errorcode" -eq "1211" ]; then
    echo " INFO: auxcfg missing issuerCountryName"
else
    echo " ERROR: auxcfg missing issuerCountryName"
    exit 1
fi  
((TEST_CTR+=1))

echo "Test auxcfg missing issuerStateOrProvinceName"
sendCommand ${BASE_ROOT}${TEST_CTR} $SAMPLE_FINAL ${OUT_DIR}/out.txt
getErrorCode $MSG_FILE
if [ "$RC" -ne 0 ] && [ "$errorcode" -eq "1211" ]; then
    echo " INFO: auxcfg missing issuerStateOrProvinceName"
else
    echo " ERROR: auxcfg missing issuerStateOrProvinceName"
    exit 1
fi  
((TEST_CTR+=1))

echo "Test auxcfg missing issuerLocalityName"
sendCommand ${BASE_ROOT}${TEST_CTR} $SAMPLE_FINAL ${OUT_DIR}/out.txt
getErrorCode $MSG_FILE
if [ "$RC" -ne 0 ] && [ "$errorcode" -eq "1211" ]; then
    echo " INFO: auxcfg missing issuerLocalityName"
else
    echo " ERROR: auxcfg missing issuerLocalityName"
    exit 1
fi  
((TEST_CTR+=1))

echo "Test auxcfg missing issuerOrganizationName"
sendCommand ${BASE_ROOT}${TEST_CTR} $SAMPLE_FINAL ${OUT_DIR}/out.txt
getErrorCode $MSG_FILE
if [ "$RC" -ne 0 ] && [ "$errorcode" -eq "1211" ]; then
    echo " INFO: auxcfg missing issuerOrganizationName"
else
    echo " ERROR: auxcfg missing issuerOrganizationName"
    exit 1
fi  
((TEST_CTR+=1))

echo "Test auxcfg missing issuerCommonName"
sendCommand ${BASE_ROOT}${TEST_CTR} $SAMPLE_FINAL ${OUT_DIR}/out.txt
getErrorCode $MSG_FILE
if [ "$RC" -ne 0 ] && [ "$errorcode" -eq "1211" ]; then
    echo " INFO: auxcfg missing issuerCommonName"
else
    echo " ERROR: auxcfg missing issuerCommonName"
    exit 1
fi  
((TEST_CTR+=1))

echo "Test auxcfg missing final"
sendCommand ${BASE_ROOT}${TEST_CTR} $SAMPLE_FINAL ${OUT_DIR}/out.txt
getErrorCode $MSG_FILE
if [ "$RC" -ne 0 ] && [ "$errorcode" -eq "1056" ]; then
    echo " INFO: auxcfg missing final"
else
    echo " ERROR: auxcfg missing final"
    exit 1
fi  
((TEST_CTR+=1))

echo "Test auxcfg bad final"
sendCommand ${BASE_ROOT}${TEST_CTR} $SAMPLE_FINAL ${OUT_DIR}/out.txt
getErrorCode $MSG_FILE
if [ "$RC" -ne 0 ] && [ "$errorcode" -eq "1056" ]; then
    echo " INFO: auxcfg bad final"
else
    echo " ERROR: auxcfg bad final"
    exit 1
fi  
((TEST_CTR+=1))

echo "Test auxcfg bad final"
sendCommand ${BASE_FINAL}${TEST_CTR} $SAMPLE_PROJECT ${OUT_DIR}/out.txt
getErrorCode $MSG_FILE
if [ "$RC" -ne 0 ] && [ "$errorcode" -eq "1056" ]; then
    echo " INFO: auxcfg bad final"
else
    echo " ERROR: auxcfg bad final"
    exit 1
fi  
((TEST_CTR+=1))

echo "Test auxcfg missing subjectCountryName"
sendCommand ${BASE_FINAL}${TEST_CTR} $SAMPLE_PROJECT ${OUT_DIR}/out.txt
getErrorCode $MSG_FILE
if [ "$RC" -ne 0 ] && [ "$errorcode" -eq "1212" ]; then
    echo " INFO: auxcfg missing subjectCountryName"
else
    echo " ERROR: auxcfg missing subjectCountryName"
    exit 1
fi  
((TEST_CTR+=1))

echo "Test auxcfg missing subjectStateOrProvinceName"
sendCommand ${BASE_FINAL}${TEST_CTR} $SAMPLE_PROJECT ${OUT_DIR}/out.txt
getErrorCode $MSG_FILE
if [ "$RC" -ne 0 ] && [ "$errorcode" -eq "1212" ]; then
    echo " INFO: auxcfg missing subjectStateOrProvinceName"
else
    echo " ERROR: auxcfg missing subjectStateOrProvinceName"
    exit 1
fi  
((TEST_CTR+=1))

echo "Test auxcfg missing subjectLocalityName"
sendCommand ${BASE_FINAL}${TEST_CTR} $SAMPLE_PROJECT ${OUT_DIR}/out.txt
getErrorCode $MSG_FILE
if [ "$RC" -ne 0 ] && [ "$errorcode" -eq "1212" ]; then
    echo " INFO: auxcfg missing subjectLocalityName"
else
    echo " ERROR: auxcfg missing subjectLocalityName"
    exit 1
fi  
((TEST_CTR+=1))

echo "Test auxcfg missing subjectOrganizationName"
sendCommand ${BASE_FINAL}${TEST_CTR} $SAMPLE_PROJECT ${OUT_DIR}/out.txt
getErrorCode $MSG_FILE
if [ "$RC" -ne 0 ] && [ "$errorcode" -eq "1212" ]; then
    echo " INFO: auxcfg missing subjectOrganizationName"
else
    echo " ERROR: auxcfg missing subjectOrganizationName"
    exit 1
fi  
((TEST_CTR+=1))

echo ""
echo "Key to be Certified Project Configuration File Error Cases"
echo ""

echo "Test key to be certified project configuration file key"
sendCommand ${SAMPLE_ROOT} ${BASE_FINAL}${TEST_CTR} ${OUT_DIR}/out.txt
getErrorCode $MSG_FILE
if [ "$RC" -ne 0 ] && [ "$errorcode" -eq "1106" ]; then
    echo " INFO: key to be certified project configuration file key"
else
    echo " ERROR: key to be certified project configuration file key"
    exit 1
fi  
((TEST_CTR+=1))

echo "Test key to be certified project configuration file auxcfg"
sendCommand ${SAMPLE_ROOT} ${BASE_FINAL}${TEST_CTR} ${OUT_DIR}/out.txt
getErrorCode $MSG_FILE
FRAMEWORK_CONFIG_FILE=regression.cfg
if [ "$RC" -ne 0 ] && [ "$errorcode" -eq "1107" ]; then
    echo " INFO: key to be certified project configuration file key"
else
    echo " ERROR: key to be certified project configuration file key"
    exit 1
fi  
((TEST_CTR+=1))


echo ""
echo "Other parameter errors"
echo ""

echo "Bad -usr"
echo $P | ./sf_client -project $SAMPLE_ROOT -comments "Testing sign cert" -param "-certify_project $SAMPLE_FINAL -usr ${GOOD_USR}xxx" -url sftp://$GOOD_USR@${FRMWRK_HOST} -epwd $USR_EPWD -pkey $USR_PKEY -o ${OUT_DIR}/out.txt -stdout > $MSG_FILE
RC=$?
getErrorCode $MSG_FILE
if [ "$RC" -ne 0 ] && [ "$errorcode" -eq "1155" ]; then
    echo " INFO: Bad -usr"
else
    echo " ERROR: Bad -usr"
    exit 1
fi
echo "Test a success case to reset the fail count"
echo $P | ./sf_client -project $SAMPLE_ROOT -comments "Testing sign cert" -param "-certify_project $SAMPLE_FINAL -usr ${GOOD_USR}" -url sftp://$GOOD_USR@${FRMWRK_HOST} -epwd $USR_EPWD -pkey $USR_PKEY -o ${OUT_DIR}/out.txt -stdout > $MSG_FILE
RC=$?
if [ "$RC" -eq 0 ]; then
    echo " INFO: Success Case"
else
    echo " ERROR: Success Case"
    exit 1
fi  

echo "Bad -pwd"
sendCommand ${BASE_ROOT}${TEST_CTR} ${SAMPLE_FINAL} ${OUT_DIR}/out.txt
getErrorCode $MSG_FILE
if [ "$RC" -ne 0 ] && [ "$errorcode" -eq "1155" ]; then
    echo " INFO: Bad -pwd"
else
    echo " ERROR: Bad -pwd"
    exit 1
fi
echo "Test a success case to reset the fail count"
echo $P | ./sf_client -project $SAMPLE_ROOT -comments "Testing sign cert" -param "-certify_project $SAMPLE_FINAL -usr ${GOOD_USR}" -url sftp://$GOOD_USR@${FRMWRK_HOST} -epwd $USR_EPWD -pkey $USR_PKEY -o ${OUT_DIR}/out.txt -stdout > $MSG_FILE
RC=$?
if [ "$RC" -eq 0 ]; then
    echo " INFO: Success Case"
else
    echo " ERROR: Success Case"
    exit 1
fi
((TEST_CTR+=1))

echo "Test -key bad token"
sendCommand ${BASE_ROOT}${TEST_CTR} ${SAMPLE_FINAL} ${OUT_DIR}/out.txt
getErrorCode $MSG_FILE
if [ "$RC" -ne 0 ] && [ "$errorcode" -eq "1035" ]; then
    echo " INFO: -key bad token"
else
    echo " ERROR: -key bad token"
    exit 1
fi  
((TEST_CTR+=1))


echo "Test -key bad key to be certified token"
sendCommand ${SAMPLE_ROOT} ${BASE_FINAL}${TEST_CTR} ${OUT_DIR}/out.txt
getErrorCode $MSG_FILE
if [ "$RC" -ne 0 ] && [ "$errorcode" -eq "1153" ]; then
    echo " INFO: -key bad key to be certified token"
else
    echo " ERROR: -key bad key to be certified token"
    exit 1
fi  
((TEST_CTR+=1))
 
ROOT_SHA1=${BASE_ROOT}${TEST_CTR}
((TEST_CTR+=1))
FINAL_SHA1=${BASE_FINAL}${TEST_CTR}

ROOT_SHA256=$SAMPLE_ROOT
FINAL_SHA256=$SAMPLE_FINAL 

echo ""
echo "SHA-256 Test Case"
echo ""

sendTestCase $ROOT_SHA256 $FINAL_SHA256 $SAMPLE_PROJECT

echo ""
echo "SHA-1 Test Case"
echo ""

sendTestCase $ROOT_SHA1 $FINAL_SHA1 $SAMPLE_PROJECT

echo ""
echo "SHA-1 root signing SHA-256 Test Case"
echo ""

sendTestCase $ROOT_SHA1 $FINAL_SHA256 $SAMPLE_PROJECT

echo ""
echo "SHA-256 root signing SHA-1 Test Case"
echo ""

sendTestCase $ROOT_SHA256 $FINAL_SHA1 $SAMPLE_PROJECT

#
# Cleanup
#

rm -r ${OUT_DIR}

echo ""
echo "Tests Passed"
echo ""
exit 0
