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

# HSM tools install path
HSMPATH = /opt/ibm/4767

CC = /usr/bin/gcc
CCFLAGS =  -Wall -W -Wmissing-declarations -Wmissing-prototypes -Wnested-externs -c -ggdb -D$(ARCH) -DUNIX \
	-I$(HSMPATH)/include -DADD_ECC
CCFLAGS += $(EXTRA_CCFLAGS)
# -DDEBUG


# for all programs
LNFLAGS =  -ggdb -lcrypto -lcsulcca -ljson-c
#-lcsulsapi -lcsulsecy -lds30 -lcsulcall

all:    framework framework_test frameworkkey_generate keygen password_generate password_change \
		keygeneccp521 audit sender_validate audit_archive getpubkey getpubkeyecc setclock
#all:		ccatest  
#		signature_verify \
#		audit_archive t

OBJECTS = framework.o utils.o framework_utils.o debug.o ossl_functions.o ossl_functions_ecc.o \
          mail.o dropbox_utils.o cca_functions.o cca_structures.o cca_structures_ecc.o \
          cca_functions_ecc.o framework_test.o frameworkkey_generate.o keygen.o \
          password_generate.o password_change.o audit.o keygeneccp521.o sender_validate.o \
          audit_archive.o getpubkey.o getpubkeyecc.o setclock.o

HEADERS = \
	cca_functions.h \
	cca_structures.h \
	cca_structures_ecc.h \
	cca_functions_ecc.h \
	debug.h \
	framework_utils.h \
	ossl_functions.h \
	dropbox_utils.h \
	utils.h


LDAPOBJ =
# Use the following to include ldap lookups, comment out to remove
LNFLAGS += -lldap
LDAPOBJ = ldap_lookup.o
OBJECTS += ldap_lookup.o
HEADER += ldap_lookup.h
CCFLAGS += -DLDAP_VERIFY

# the main program
framework: framework.o utils.o framework_utils.o debug.o ossl_functions.o \
        mail.o dropbox_utils.o cca_functions.o cca_structures.o cca_structures_ecc.o \
        cca_functions_ecc.o $(LDAPOBJ)
		$(CC) $(LNFLAGS) $^ -o framework


# regression test driver

t:		t.o \
		utils.o debug.o
		$(CC) $(LNFLAGS) $(LNNFLAGS) t.o \
		utils.o debug.o \
		-o t

# unit test program

ccatest:	ccatest.o \
		framework_utils.o cca_functions.o cca_structures.o ossl_functions.o \
		utils.o debug.o notesmail.o
		$(CC) $(LNFLAGS) $(LNNFLAGS) $^ -o ccatest

# stub signer program

framework_test:	framework_test.o utils.o debug.o ossl_functions.o ossl_functions_ecc.o \
        cca_functions_ecc.o cca_structures_ecc.o cca_functions.o cca_structures.o $(LDAPOBJ)
		$(CC) $(LNFLAGS) $^ -o framework_test

# auditistrator programs

audit:		audit.o utils.o
		$(CC) $(LNFLAGS) $^ -o audit

frameworkkey_generate:	frameworkkey_generate.o \
		framework_utils.o cca_functions.o cca_structures.o ossl_functions.o \
		utils.o debug.o mail.o dropbox_utils.o cca_structures_ecc.o cca_functions_ecc.o $(LDAPOBJ)
	$(CC) $(LNFLAGS) $(LNNFLAGS) $^ -o frameworkkey_generate

password_generate:	password_generate.o \
		framework_utils.o cca_functions.o cca_structures.o ossl_functions.o \
		utils.o debug.o mail.o dropbox_utils.o cca_structures_ecc.o cca_functions_ecc.o $(LDAPOBJ)
		$(CC) $(LNFLAGS) $(LNNFLAGS) $^ -o password_generate

password_change:	password_change.o \
		framework_utils.o cca_functions.o cca_structures.o ossl_functions.o \
		utils.o debug.o mail.o dropbox_utils.o  cca_structures_ecc.o cca_functions_ecc.o $(LDAPOBJ)
		$(CC) $(LNFLAGS) $(LNNFLAGS) $^ -o password_change

sender_validate:	sender_validate.o \
			framework_utils.o cca_functions.o cca_structures.o ossl_functions.o \
			utils.o debug.o mail.o dropbox_utils.o  cca_structures_ecc.o cca_functions_ecc.o $(LDAPOBJ)
			$(CC) $(LNFLAGS) $(LNNFLAGS) $^ -o sender_validate

getpubkey:	getpubkey.o \
		framework_utils.o cca_structures.o cca_functions.o ossl_functions.o mail.o \
		utils.o debug.o dropbox_utils.o  cca_structures_ecc.o cca_functions_ecc.o $(LDAPOBJ)
		$(CC) $(LNFLAGS) $(LNNFLAGS) $^ -o getpubkey

signature_verify:	signature_verify.o \
		ossl_functions.o \
		utils.o debug.o
		$(CC) $(LNFLAGS) $(LNNFLAGS) $^ -o signature_verify

keygen:		keygen.o cca_functions.o cca_structures.o  \
		ossl_functions.o utils.o debug.o
		$(CC) $(LNFLAGS) $^ -o keygen

setclock:	setclock.o \
		cca_functions.o ossl_functions.o utils.o debug.o
		$(CC) $(LNFLAGS) $^ -o setclock

audit_archive:	audit_archive.o \
		framework_utils.o cca_structures.o cca_functions.o ossl_functions.o mail.o \
		utils.o debug.o  dropbox_utils.o  cca_structures_ecc.o cca_functions_ecc.o $(LDAPOBJ)
		$(CC) $(LNFLAGS) $(LNNFLAGS) $^ -o audit_archive

getpubkeyecc:	getpubkeyecc.o \
        framework_utils.o cca_structures_ecc.o cca_functions.o ossl_functions.o mail.o \
        utils.o debug.o dropbox_utils.o cca_functions_ecc.o cca_structures.o $(LDAPOBJ)
		$(CC) $(LNFLAGS) $(LNNFLAGS) $^ -o getpubkeyecc

keygeneccp521:	keygeneccp521.o \
	cca_functions.o cca_structures_ecc.o cca_functions_ecc.o \
	ossl_functions.o utils.o debug.o
	$(CC) $(LNFLAGS) $(LNNFLAGS) $^ -o keygeneccp521

$(OBJECTS): %.o: %.c $(HEADERS)
	$(CC) $(CCFLAGS) $< -o $@

clean:
	rm -f *.o framework ccatest framework_test audit \
	frameworkkey_generate password_generate password_change \
	signature_verify keygen keygeneccp521 setclock sender_validate \
	getpubkeyecc getpubkey audit_archive

# geteccpubkey keygeneccp521
