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

#ifndef LDAP_LOOKUP_H
#define LDAP_LOOKUP_H

#include <stdbool.h>
#include "framework_utils.h"

// Returns number of LDAP entries matching the specified email
int ldapLookupByEmail(FrameworkConfig* configParm,
                      const char* email, char** employeeId, bool verbose);

#endif
