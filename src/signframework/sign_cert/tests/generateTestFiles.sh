#!/bin/bash
#
#			sign_cert Regression Test
#			     Written by Ken Goldman ported by Nick Child (2021)
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

# Run this script locally

# before running the first time
#
# > ../../keygen -sz 2048 -k issuer_root.tok -p issuer_root.bin
# > ../../keygen -sz 2048 -k issuer_final.tok -p issuer_final.bin
# > ../../keygen -sz 2048 -k sign_code.tok -p sign_code.bin
#then edit the senders section of issuer_root, issuer_final and sign _code configs

#this script generates all the test cases for generating a certificate
#by creating several projects and config files
#remember to export FRAMEWORK_CONFIG_FILE to regression.cfg 
#when this finishes, you can run the client side tests with ./sign_cert_test.sh <sftp key pswd>

# starting files
BASE_FRAMEWORK_CONFIG_FILE=base_regression.cfg

BASE_ROOT_AUX_FILE=issuer_root_sample_aux.cfg
BASE_ROOT_FILE=issuer_root_sample.cfg
BASE_FINAL_FILE=issuer_final_sample.cfg
BASE_FINAL_AUX_FILE=issuer_final_sample_aux.cfg

BASE_PROJECT_FILE=code_signer_sample.cfg

# temporary for bad case
ROOT_FILE=issuer_root_test
ROOT_AUX_FILE=issuer_root_aux_test
FINAL_FILE=issuer_final_test
FINAL_AUX_FILE=issuer_final_aux_test
PROJECT_FILE=code_signer_test

# normal case

FRAMEWORK_CONFIG_FILE=regression.cfg
cp $BASE_FRAMEWORK_CONFIG_FILE $FRAMEWORK_CONFIG_FILE
TEST_CTR=0
OUT_DIR=sign_cert/tests
TMP=tmp.cfg
# Initialization
#

#
# Test Case Generation Start Here
#

date

echo ""
echo "Generating Projects..."
echo ""

#sign_cert -project issuer_root -usr t -pwd aaaaaa -log regression.log -auxcfg issuer_root_sample_aux.cfg -sender "Kenneth Goldman/Watson/IBM" -certify_project issuer_root -key issuer_root.tok -do certroot.der  

#generate cfg and add to projects
#$1 sed find/replace string
#$2 base file
#$3 new_file
generateProject()
{
	sed "${1}" $2 > ${3}${TEST_CTR}.cfg
	#append new project to frameworkcfg
	echo "${3}${TEST_CTR}=${OUT_DIR}/${3}${TEST_CTR}.cfg " >> $FRAMEWORK_CONFIG_FILE
	((TEST_CTR+=1))
}


#generate cfg and aux cfg and add to configs
#$1 sed
#$2 base aux file
#$3 new aux file
#$4 base file
#$5 new file
generateProjectWAux()
{
	#make new aux cfg file
	sed "${1}" $2 > ${3}${TEST_CTR}.cfg
	#make new project
	generateProject s:${2}:${3}${TEST_CTR}.cfg: $4 $5
}
#pwd missing
generateProject 's:needpwd=true:needpwd=false:' $BASE_ROOT_FILE  $ROOT_FILE

#auxcfg missing
generateProject 's:needauxcfg=true:needauxcfg=false:' $BASE_ROOT_FILE  $ROOT_FILE 

#key missing
generateProject 's:needkey=true:needkey=false:' $BASE_ROOT_FILE  $ROOT_FILE

#do missing
generateProject 's:needoatt=true:needoatt=false:' $BASE_ROOT_FILE $ROOT_FILE

#no sign alg
generateProjectWAux 's:sign_algorithm:sign_algorithmxx:' $BASE_ROOT_AUX_FILE $ROOT_AUX_FILE  $BASE_ROOT_FILE $ROOT_FILE

#bad sign alg
generateProjectWAux 's:RSA:RSAXX:' $BASE_ROOT_AUX_FILE $ROOT_AUX_FILE  $BASE_ROOT_FILE $ROOT_FILE

#no digest alg
generateProjectWAux 's:digest_algorithm:digest_algortihmxxx:' $BASE_ROOT_AUX_FILE $ROOT_AUX_FILE  $BASE_ROOT_FILE $ROOT_FILE

#bad digest alg
generateProjectWAux 's:SHA:SHAxxx:' $BASE_ROOT_AUX_FILE $ROOT_AUX_FILE  $BASE_ROOT_FILE $ROOT_FILE

#no validity
generateProjectWAux 's:validity:validityxxx:' $BASE_ROOT_AUX_FILE $ROOT_AUX_FILE  $BASE_ROOT_FILE $ROOT_FILE

#bad validity
generateProjectWAux 's:validity=:validity=xxx:' $BASE_ROOT_AUX_FILE $ROOT_AUX_FILE  $BASE_ROOT_FILE $ROOT_FILE

#no issuerCountryName
generateProjectWAux 's:issuerCountryName:issuerCountryNamexxx:' $BASE_ROOT_AUX_FILE $ROOT_AUX_FILE  $BASE_ROOT_FILE $ROOT_FILE

#no issuerStateOrProvince
generateProjectWAux 's:issuerStateOrProvinceName:issuerStateOrProvinceNamexxx:' $BASE_ROOT_AUX_FILE $ROOT_AUX_FILE  $BASE_ROOT_FILE $ROOT_FILE

#no issuerLocalityName
generateProjectWAux 's:issuerLocalityName:issuerLocalityNamexxx:' $BASE_ROOT_AUX_FILE $ROOT_AUX_FILE  $BASE_ROOT_FILE $ROOT_FILE

#no issuerOrganizationName
generateProjectWAux 's:issuerOrganizationName:issuerOrganizationNamexxx:' $BASE_ROOT_AUX_FILE $ROOT_AUX_FILE  $BASE_ROOT_FILE $ROOT_FILE

#no issuerCommonName
generateProjectWAux 's:issuerCommonName:issuerCommonNamexxx:' $BASE_ROOT_AUX_FILE $ROOT_AUX_FILE  $BASE_ROOT_FILE $ROOT_FILE

#no final
generateProjectWAux 's:final:finalxxx:' $BASE_ROOT_AUX_FILE $ROOT_AUX_FILE  $BASE_ROOT_FILE $ROOT_FILE

#bad final
generateProjectWAux 's:final=false:final=falsexxxx:' $BASE_ROOT_AUX_FILE $ROOT_AUX_FILE  $BASE_ROOT_FILE $ROOT_FILE

#bad final for final
generateProjectWAux 's:final=true:final=truexxx:' $BASE_FINAL_AUX_FILE $FINAL_AUX_FILE $BASE_FINAL_FILE $FINAL_FILE

#no subjectCountryName
generateProjectWAux 's:subjectCountryName:subjectCountryNamexxx:' $BASE_FINAL_AUX_FILE $FINAL_AUX_FILE $BASE_FINAL_FILE $FINAL_FILE

#no subjectStateOrProvince
generateProjectWAux 's:subjectStateOrProvinceName:subjectStateOrProvinceNamexxx:' $BASE_FINAL_AUX_FILE $FINAL_AUX_FILE $BASE_FINAL_FILE $FINAL_FILE

#no subjectLocalityName
generateProjectWAux 's:subjectLocalityName:subjectLocalityNamexxx:' $BASE_FINAL_AUX_FILE $FINAL_AUX_FILE $BASE_FINAL_FILE $FINAL_FILE

#no subjectOrganizationName
generateProjectWAux 's:subjectOrganizationName:subjectOrganizationNamexxx:' $BASE_FINAL_AUX_FILE $FINAL_AUX_FILE $BASE_FINAL_FILE $FINAL_FILE

#no key for project to be certified
sed s:needkey=true:needkey=false: $BASE_FINAL_FILE >  $TMP
generateProject 's:key=sign_cert/tests/issuer_final.tok::' $TMP  $FINAL_FILE

#no auxcfg for project to be certified
sed s:needauxcfg=true:needauxcfg=false: $BASE_FINAL_FILE >  $TMP
generateProject 's:auxcfg=sign_cert/tests/issuer_final_sample_aux.cfg::' $TMP $FINAL_FILE

#bad pswd
sed s:needpwd=true:needpwd=false: $BASE_ROOT_FILE >  $TMP
generateProject 's:program=sign_cert/sign_cert:program=sign_cert/sign_cert -pwd foo:' $TMP $ROOT_FILE


#bad key
sed s:needkey=true:needkey=false: $BASE_ROOT_FILE >  $TMP
generateProject 's:program=sign_cert/sign_cert:program=sign_cert/sign_cert -key sign_cert/tests/issuer_root_sample_aux.cfg:' $TMP  $ROOT_FILE

#bad key to be certified
sed s:needkey=true:needkey=false: $BASE_FINAL_FILE >  $TMP
generateProject 's:key=sign_cert/tests/issuer_final.tok:key=sign_cert/tests/issuer_root_sample_aux.cfg:' $TMP  $FINAL_FILE

#generate root signer with sha1
generateProject 's:SHA-256:SHA-1:' $BASE_ROOT_FILE $ROOT_FILE

#generate final signer with sha1
generateProject 's:SHA-256:SHA-1:' $BASE_FINAL_FILE $FINAL_FILE
echo "Done"
exit 0
