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

ARCH = $(shell uname)

CC = /usr/bin/gcc 
CCFLAGS =  -Wall -W -Wmissing-declarations -Wmissing-prototypes -Wnested-externs -c -ggdb \
	-D$(ARCH) -DUNIX \
	-I/opt/ibm/4767/include \
	-I/usr/local/ssl/include  -DADD_ECC

#OPENSSLDIR = /usr/local/ssl/lib

# for all programs
LNFLAGS = -ggdb -Wl,-rpath-link -lssl -lcrypto -lcsulcca

all:		signecc getkeysecc

HEADERS = \
	debug.h \
	cca_functions.h \
	cca_functions_ecc.h \
	cca_structures.h \
	cca_structures_ecc.h \
	eccutils.h \
	ossl_functions.h \
	ossl_functions_ecc.h \
	utils.h

# signer program

signecc:	signecc.o \
		cca_functions.o cca_functions_ecc.o cca_structures_ecc.o \
		ossl_functions.o ossl_functions_ecc.o \
		debug.o utils.o eccutils.o
		$(CC) $(LNFLAGS) signecc.o \
		cca_functions.o cca_functions_ecc.o cca_structures_ecc.o \
		ossl_functions.o ossl_functions_ecc.o \
		debug.o utils.o eccutils.o \
		-o signecc

getkeysecc:	getkeysecc.o \
		ossl_functions.o cca_structures_ecc.o \
		debug.o utils.o eccutils.o
		$(CC) $(LNFLAGS) getkeysecc.o \
		ossl_functions.o cca_structures_ecc.o \
		debug.o utils.o eccutils.o \
		-o getkeysecc

# create links from common programs in FRAMEWORK_DIR

FRAMEWORK_DIR = ..

cca_functions.c:
	ln -s $(FRAMEWORK_DIR)/cca_functions.c .
cca_functions.h:
	ln -s $(FRAMEWORK_DIR)/cca_functions.h .
cca_functions_ecc.c:
	ln -s $(FRAMEWORK_DIR)/cca_functions_ecc.c .
cca_functions_ecc.h:
	ln -s $(FRAMEWORK_DIR)/cca_functions_ecc.h .
cca_structures.h:
	ln -s $(FRAMEWORK_DIR)/cca_structures.h .
cca_structures_ecc.c:
	ln -s $(FRAMEWORK_DIR)/cca_structures_ecc.c .
cca_structures_ecc.h:
	ln -s $(FRAMEWORK_DIR)/cca_structures_ecc.h .
debug.c:
	ln -s $(FRAMEWORK_DIR)/debug.c .
debug.h:
	ln -s $(FRAMEWORK_DIR)/debug.h .
ossl_functions.c:
	ln -s $(FRAMEWORK_DIR)/ossl_functions.c .
ossl_functions.h:
	ln -s $(FRAMEWORK_DIR)/ossl_functions.h .
ossl_functions_ecc.c:
	ln -s $(FRAMEWORK_DIR)/ossl_functions_ecc.c .
ossl_functions_ecc.h:
	ln -s $(FRAMEWORK_DIR)/ossl_functions_ecc.h .
utils.c:
	ln -s $(FRAMEWORK_DIR)/utils.c .
utils.h:
	ln -s $(FRAMEWORK_DIR)/utils.h .

cca_functions.o:		$(HEADERS)
cca_functions_ecc.o:		$(HEADERS)
cca_structures_ecc.o:		$(HEADERS)
debug.o:			$(HEADERS)
signecc.o:			$(HEADERS)
ossl_functions.o:		$(HEADERS)
ossl_functions_ecc.o:		$(HEADERS)
utils.o:			$(HEADERS)
eccutils.o:			$(HEADERS)

.c.o:
		$(CC) $(CCFLAGS) $<

clean:
	rm -f *.o signecc getkeysecc
