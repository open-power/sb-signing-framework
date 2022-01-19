/* Copyright 2020 IBM Corp.
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
#include <string>
#include <vector>

#ifndef _PKCS11_SF_JSON_H
#define _PKCS11_SF_JSON_H

struct PKCS11_SF_SESSION_PROJECTS
{
    std::string mName;
    std::string mKeyType;
    std::string mHashAlgorithm;
};

struct PKCS11_SF_SESSION_CONFIG
{
    std::string                             mUrl;
    std::vector<PKCS11_SF_SESSION_PROJECTS> mProjects;
    std::string                             mEpwdPath;
    std::string                             mPrivateKeyPath;
};

bool ParseJsonConfig(const std::string& jsonPath, PKCS11_SF_SESSION_CONFIG& configParm);

#endif