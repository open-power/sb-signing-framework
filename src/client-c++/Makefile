ifeq ($(shell uname),AIX)
	CFLAGS+=-std=c++11 -O2 -DNO_GETOPT_LONG -I/opt/freeware/include
	CXX=xlC
else
	CFLAGS+=-std=c++11 -O2 -Wall -Wextra
	CXX=g++
endif

all: sf_client

clean:
	rm -f *.o sf_client git_hash.h

cli_main.o: cli_main.cpp
	@sed 's/@GIT_VERSION@/$(shell git rev-parse --short HEAD)/g' git_hash.h.in > git_hash.h
	$(CXX) -c -g $(CFLAGS) -Isf_utils/include -Isf_client_lib/include -I. $^ -o $@

sf_client.o: sf_client_lib/sf_client.cpp
	$(CXX) -c -g $(CFLAGS) -Isf_utils/include -Isf_client_lib/include -I. $^ -o $@

sf_curl.o: sf_client_lib/sf_curl.cpp
	$(CXX) -c -g $(CFLAGS) -Isf_utils/include -Isf_client_lib/include -I. $^ -o $@

sf_json.o: sf_client_lib/sf_json.cpp
	$(CXX) -c -g $(CFLAGS) -Isf_utils/include -Isf_client_lib/include -I. $^ -o $@

sf_utils.o: sf_utils/sf_utils.cpp
	$(CXX) -c -g $(CFLAGS) -Isf_utils/include -Isf_client_lib/include -I. $^ -o $@


sf_client: cli_main.o sf_client.o sf_curl.o sf_json.o sf_utils.o
	$(CXX) -g $(CFLAGS) -Wall -Wextra -I. $^ -o $@ -lssl -lcrypto -lcurl -ljson-c

