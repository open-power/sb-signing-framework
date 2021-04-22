# Copyright 2021 IBM Corp.
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
	-I/opt/ibm/4767/include

# for all programs
LNFLAGS = -ggdb -lcrypto -lcrypto -lcsulcca -ljson-c


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
