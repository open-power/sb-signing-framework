/* Copyright 2017 IBM Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * 	http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef PSCP_JSON_H
#define PSCP_JSON_H

#include <stdbool.h>

int createJsonString(char** rtnStr, const char* pscp_project, const char* pscp_parameters, const char* pscp_user, const char* pscp_comment, const char* pscp_epwd_path, const char* pscp_payload_path, const bool verbose);
//int encryptJsonString(const char * in, char** out, const size_t in_len, size_t* out_len, bool verbose);
int parseServerResponse(const char * responseFile, unsigned char** res_payload, size_t* res_payload_len, char** res_stdout, size_t* res_stdout_len, int* res_retval, bool verbose);

#endif
