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
	-I/opt/ibm/4767/include

# for all programs
LNFLAGS = -ggdb -Wl,-rpath-link -lssl -lcrypto -lcsulcca

all:		sign_sha512

HEADERS = \
	debug.h \
	cca_functions.h \
	cca_structures.h \
	ossl_functions.h \
	utils.h

# signer program

sign_sha512:	sign_sha512.o \
		cca_functions.o cca_structures.o ossl_functions.o utils.o debug.o
		$(CC) $(LNFLAGS) sign_sha512.o \
		cca_functions.o cca_structures.o ossl_functions.o utils.o debug.o \
		-o sign_sha512

sign_sha512.o:			$(HEADERS)
cca_functions.o:		$(HEADERS)
cca_structures.o:		$(HEADERS)
debug.o:			$(HEADERS)
ossl_functions.o:		$(HEADERS)
utils.o:			$(HEADERS)

.c.o:
	$(CC) $(CCFLAGS) $<

clean:
	rm *.o sign_sha512
