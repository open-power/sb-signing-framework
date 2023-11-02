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
#include <sf_client/sf_rc.h>
#include <sf_utils/sf_utils.h>
#include <sstream>
#include <string>
#include <vector>

#include "sf_json.h"

const static std::string JsonModeTag      = "project_mode";
const static std::string JsonProjectTag   = "project";
const static std::string JsonParameterTag = "parameters";
const static std::string JsonUserTag      = "user";
const static std::string JsonCommentTag   = "comment";
const static std::string JsonEpwdTag      = "epwd";
const static std::string JsonPayloadTag   = "payload";

const static std::string JsonResultTag = "result";
const static std::string JsonStdOutTag = "stdout";
const static std::string JsonRetValTag = "retval";

enum TagNotFoundBehavior
{
    ErrorOnTagNotFound,
    SuccessOnTagNotFound
};

#define ENCODE_JSON_STRING(return_code, root_node, tag, value)                                     \
    if(success == (return_code))                                                                   \
    {                                                                                              \
        (return_code) = EncodeString((root_node), (tag), (value));                                 \
    }

#define ENCODE_JSON_BINARY(return_code, root_node, tag, value)                                     \
    if(success == (return_code))                                                                   \
    {                                                                                              \
        (return_code) = EncodeString((root_node), (tag), GetHexStringFromBinary(value));           \
    }

#define DECODE_JSON_STRING(return_code, root_node, tag, value, tag_not_found_behavior)             \
    if(success == (return_code))                                                                   \
    {                                                                                              \
        (return_code) = DecodeString((root_node), (tag), (value), (tag_not_found_behavior));       \
    }

#define DECODE_JSON_BINARY(return_code, root_node, tag, value, tag_not_found_behavior)             \
    if(success == (return_code))                                                                   \
    {                                                                                              \
        std::string sTmpString;                                                                    \
        (return_code) = DecodeString((root_node), (tag), sTmpString, (tag_not_found_behavior));    \
        (value)       = GetBinaryFromHexString(sTmpString);                                        \
    }
#define DECODE_JSON_INT(return_code, root_node, tag, value, tag_not_found_behavior)                \
    if(success == (return_code))                                                                   \
    {                                                                                              \
        (return_code) = DecodeInt((root_node), (tag), (value), (tag_not_found_behavior));          \
    }

sf_client::rc EncodeString(struct json_object* jsonParentParm,
                           const std::string&  tagParm,
                           const std::string&  valueParm)
{
    sf_client::rc sRc = sf_client::success;

    if(jsonParentParm)
    {
        struct json_object* sJsonString = json_object_new_string(valueParm.c_str());
        if(sJsonString)
        {
            json_object_object_add(jsonParentParm, tagParm.c_str(), sJsonString);
        }
        else
        {
            sRc = sf_client::json_new_obj_fail;
        }
    }
    else
    {
        sRc = sf_client::json_invalid_parm;
    }
    return sRc;
}

sf_client::rc DecodeString(struct json_object*       jsonParentParm,
                           const std::string&        tagParm,
                           std::string&              valueParm,
                           const TagNotFoundBehavior tagNotFoundBehaviorParm)
{
    sf_client::rc sRc = sf_client::success;
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
                valueParm = std::string(sJsonString);
            }
            else
            {
                sRc = sf_client::json_invalid_object_type;
            }
        }
        else
        {
            if(tagNotFoundBehaviorParm == ErrorOnTagNotFound)
            {
                // Tag not found, nothing to parse
                sRc = sf_client::json_tag_not_found;
            }
        }
    }
    else
    {
        sRc = sf_client::json_invalid_parm;
    }

    return sRc;
}

sf_client::rc DecodeInt(struct json_object*       jsonParentParm,
                        const std::string&        tagParm,
                        int&                      valueParm,
                        const TagNotFoundBehavior tagNotFoundBehaviorParm)
{
    sf_client::rc sRc = sf_client::success;
    valueParm         = 0;

    if(jsonParentParm)
    {
        json_object* sJsonChild = NULL;
        json_object_object_get_ex(jsonParentParm, tagParm.c_str(), &sJsonChild);

        if(sJsonChild)
        {
            valueParm = json_object_get_int(sJsonChild);
        }
        else
        {
            if(tagNotFoundBehaviorParm == ErrorOnTagNotFound)
            {
                // Tag not found, nothing to parse
                sRc = sf_client::json_tag_not_found;
            };
        }
    }
    else
    {
        sRc = sf_client::json_invalid_parm;
    }

    return sRc;
}

sf_client::rc sf_client::createCommandRequestJsonV1(const Json_CommandRequestV1& requestParm,
                                                    std::string&                 dstJsonParm)
{
    rc sRc = success;

    struct json_object* sRootObject = NULL;

    sRootObject = json_object_new_object();

    if(!sRootObject)
    {
        sRc = json_new_obj_fail;
    }

    ENCODE_JSON_STRING(sRc, sRootObject, JsonProjectTag, requestParm.mProject);
    ENCODE_JSON_STRING(sRc, sRootObject, JsonParameterTag, requestParm.mParms);
    ENCODE_JSON_STRING(sRc, sRootObject, JsonUserTag, requestParm.mSelfReportedUser);
    ENCODE_JSON_STRING(sRc, sRootObject, JsonCommentTag, requestParm.mComment);
    ENCODE_JSON_STRING(sRc, sRootObject, JsonEpwdTag, requestParm.mEpwdHex);
    ENCODE_JSON_BINARY(sRc, sRootObject, JsonPayloadTag, requestParm.mPayload);

    if(success == sRc)
    {
        const char* sEncodedJsonPtr = json_object_to_json_string(sRootObject);
        if(sEncodedJsonPtr)
        {
            dstJsonParm = std::string(sEncodedJsonPtr);
        }
        else
        {
            sRc = json_convert_to_string_fail;
        }
    }

    if(sRootObject)
        json_object_put(sRootObject);

    return sRc;
}

sf_client::rc sf_client::createCommandRequestJsonV2(const Json_CommandRequestV2& requestParm,
                                                    std::string&                 dstJsonParm)
{
    rc sRc = success;

    struct json_object* sRootObject = NULL;

    sRootObject = json_object_new_object();

    if(!sRootObject)
    {
        sRc = json_new_obj_fail;
    }

    ENCODE_JSON_STRING(sRc, sRootObject, JsonModeTag, requestParm.mMode);
    ENCODE_JSON_STRING(sRc, sRootObject, JsonProjectTag, requestParm.mProject);
    ENCODE_JSON_STRING(sRc, sRootObject, JsonParameterTag, requestParm.mParms);
    ENCODE_JSON_STRING(sRc, sRootObject, JsonCommentTag, requestParm.mComment);
    ENCODE_JSON_STRING(sRc, sRootObject, JsonEpwdTag, requestParm.mEpwd);
    ENCODE_JSON_BINARY(sRc, sRootObject, JsonPayloadTag, requestParm.mPayload);

    if(success == sRc)
    {
        const char* sEncodedJsonPtr = json_object_to_json_string(sRootObject);
        if(sEncodedJsonPtr)
        {
            dstJsonParm = std::string(sEncodedJsonPtr);
        }
        else
        {
            sRc = json_convert_to_string_fail;
        }
    }

    if(sRootObject)
        json_object_put(sRootObject);

    return sRc;
}

sf_client::rc sf_client::parseCommandResponseJsonV1(const std::string&      jsonParm,
                                                    Json_CommandResponseV1& dstResponseParm)
{
    rc sRc = success;
    dstResponseParm.clear();

    struct json_object* sRootObject = json_tokener_parse(jsonParm.c_str());

    if(!sRootObject)
    {
        sRc = json_parse_root_fail;
    }

    DECODE_JSON_INT(
        sRc, sRootObject, JsonRetValTag, dstResponseParm.mReturnValue, ErrorOnTagNotFound);

    DECODE_JSON_BINARY(
        sRc, sRootObject, JsonResultTag, dstResponseParm.mResult, SuccessOnTagNotFound);
    DECODE_JSON_STRING(
        sRc, sRootObject, JsonStdOutTag, dstResponseParm.mStandardOut, SuccessOnTagNotFound);

    if(sRootObject)
        json_object_put(sRootObject);

    return sRc;
}