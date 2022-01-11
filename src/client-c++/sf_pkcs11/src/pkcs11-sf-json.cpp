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
#include <iostream>
#include <json-c/json.h>
#include <sf_utils/sf_utils.h>
#include <string>
#include <vector>

#include "pkcs11-sf-json.h"
#include "pkcs11-sf-types.h"

static bool
decodeJsonString(json_object* jsonParentParm, const std::string& tagParm, std::string& valueParm)
{
    bool sIsSuccess = false;
    valueParm.clear();
    if(jsonParentParm)
    {
        json_object* sJsonChild = NULL;
        json_object_object_get_ex(jsonParentParm, tagParm.c_str(), &sJsonChild);

        if(sJsonChild)
        {
            const char* sJsonString = json_object_get_string(sJsonChild);
            if(sJsonString)
            {
                valueParm  = std::string(sJsonString);
                sIsSuccess = true;
            }
        }
    }
    return sIsSuccess;
}

static bool
decodeJsonArray(json_object* jsonParentParm, const std::string& tagParm, json_object*& valueParm)
{
    bool sIsSuccess = false;
    if(jsonParentParm)
    {
        json_object* sJsonChild = NULL;
        json_object_object_get_ex(jsonParentParm, tagParm.c_str(), &sJsonChild);

        if(sJsonChild)
        {
            if(json_object_is_type(sJsonChild, json_type_array))
            {
                valueParm = sJsonChild;
            }
        }
    }
    return sIsSuccess;
}

bool ParseJsonConfig(const std::string& jsonPath, PKCS11_SF_SESSION_CONFIG& configParm)
{
    std::vector<uint8_t> sJsonData;

    bool sIsSuccess = ReadFile(jsonPath, sJsonData);

    std::string sJsonString((char*)sJsonData.data(), (char*)sJsonData.data() + sJsonData.size());

    struct json_object* sRootObject = json_tokener_parse(sJsonString.c_str());

    if(sRootObject)
    {
        sIsSuccess &= decodeJsonString(sRootObject, SfJsonKey_Url, configParm.mUrl);
        sIsSuccess &= decodeJsonString(sRootObject, SfJsonKey_Epwd, configParm.mEpwdPath);
        sIsSuccess &= decodeJsonString(
            sRootObject, SfJsonKey_PrivateKeyPath, configParm.mPrivateKeyPath);

        json_object* sArray = NULL;
        decodeJsonArray(sRootObject, SfJsonKey_ProjectArray, sArray);
        if(sArray)
        {
            for(std::size_t i = 0; i < json_object_array_length(sArray); i++)
            {
                PKCS11_SF_SESSION_PROJECTS sProject;

                sIsSuccess &= decodeJsonString(
                    json_object_array_get_idx(sArray, i), SfJsonKey_ProjectName, sProject.mName);

                sIsSuccess &= decodeJsonString(
                    json_object_array_get_idx(sArray, i), SfJsonKey_ProjectType, sProject.mKeyType);

                sIsSuccess &= decodeJsonString(json_object_array_get_idx(sArray, i),
                                               SfJsonKey_HashAlgorithm,
                                               sProject.mHashAlgorithm);

                configParm.mProjects.push_back(sProject);

#ifdef DEBUG
                std::cout << "JSON Parsed: " << sProject.mName << std::endl;
#endif
            }
        }

        json_object_put(sRootObject);
    }
    return sIsSuccess;
}