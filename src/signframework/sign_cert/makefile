#
#				Sign Certificate Makefile
#			     Written by Ken Goldman
#		       IBM Thomas J. Watson Research Center
#		$Id: makefile 379 2013-06-11 13:56:46Z kgoldman $
#
#			       IBM Confidential
#			     OCO Source Materials
#			 (c) Copyright IBM Corp. 2013
#			      All Rights Reserved
#
#	   The source code for this program is not published or otherwise
#	   divested of its trade secrets, irrespective of what has been
#	   deposited with the U.S. Copyright Office
#

ARCH = $(shell uname)

CC = /usr/bin/gcc 
CCFLAGS =  -Wall -W -Wmissing-declarations -Wmissing-prototypes -Wnested-externs -c -ggdb \
	-D$(ARCH) -DUNIX \
	-I/opt/ibm/4767/include

# for all programs
LNFLAGS = -ggdb -lcrypto -lcrypto -lcsulcca -ljson-c
	#-lcsulsapi -lcsulsecy -lds30 -lcsulcall

all:		sign_cert

HEADERS = \
	debug.h \
	cca_functions.h \
	cca_structures.h \
	ossl_functions.h \
	ossl_certificate.h \
	utils.h

# signer program

sign_cert:	sign_cert.o \
		cca_functions.o cca_structures.o ossl_functions.o ossl_certificate.o utils.o debug.o
		$(CC) $(LNFLAGS) sign_cert.o \
		cca_functions.o cca_structures.o ossl_functions.o ossl_certificate.o utils.o debug.o \
		-o sign_cert

# create links from common programs in FRAMEWORK_DIR

FRAMEWORK_DIR = ..

cca_functions.c:
	ln -s $(FRAMEWORK_DIR)/cca_functions.c .
cca_functions.h:
	ln -s $(FRAMEWORK_DIR)/cca_functions.h .
cca_structures.c:
	ln -s $(FRAMEWORK_DIR)/cca_structures.c .
cca_structures.h:
	ln -s $(FRAMEWORK_DIR)/cca_structures.h .
debug.c:
	ln -s $(FRAMEWORK_DIR)/debug.c .
debug.h:
	ln -s $(FRAMEWORK_DIR)/debug.h .
ossl_functions.c:
	ln -s $(FRAMEWORK_DIR)/ossl_functions.c .
ossl_functions.h:
	ln -s $(FRAMEWORK_DIR)/ossl_functions.h .
ossl_certificate.c:
	ln -s $(FRAMEWORK_DIR)/ossl_certificate.c .
ossl_certificate.h:
	ln -s $(FRAMEWORK_DIR)/ossl_certificate.h .
utils.c:
	ln -s $(FRAMEWORK_DIR)/utils.c .
utils.h:
	ln -s $(FRAMEWORK_DIR)/utils.h .

sign_cert.o:			$(HEADERS)
cca_functions.o:		$(HEADERS)
cca_structures.o:		$(HEADERS)
debug.o:			$(HEADERS)
ossl_functions.o:		$(HEADERS)
utils.o:			$(HEADERS)

.c.o:
	$(CC) $(CCFLAGS) $<

clean:
	rm *.o sign_cert
	rm -f tests/*test*
	rm -f tests/tmp.cfg tests/regression.cfg
	rm -f tests/*.log
