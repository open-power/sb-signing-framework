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


CC=gcc
CFLAGS+=-std=gnu99 -Wall -pedantic -I.
CLIB=-ljson-c -lm -lcurl -lssl -lcrypto
DEPS = pscp_sftp.h pscp_json.h
CLIENT_OBJ = client.o 
SFTP_T_OBJ = pscp_sftp_test.o
COMMON_OBJ = pscp_sftp.o pscp_json.o
CEXEC=sf_client sftp-test

%.o: %.c $(DEPS)
		$(CC) -c -o $@ $< $(CFLAGS)

sf_client: $(CLIENT_OBJ) $(COMMON_OBJ)
		gcc -o $@ $^ $(CFLAGS) $(CLIB)

sftp-test: $(SFTP_T_OBJ) $(COMMON_OBJ)
		gcc -o $@ $^ $(CFLAGS) $(CLIB)

default: sf_client

all: $(CEXEC)

clean:
		rm -f $(CEXEC) $(SFTP_T_OBJ) $(CLIENT_OBJ) $(DECRYPT_OBJ) $(COMMON_OBJ)
