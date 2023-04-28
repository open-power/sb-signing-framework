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
#include <sf_client/sf_client.h>
#include <sf_utils/sf_utils.h>
#include <stdlib.h>
#include <string.h>
#include "sf_curl.h"
#include "sf_json.h"

sf_client::Session::Session() { mCurlSession = new Curl_Session(); }

sf_client::Session::~Session() { delete mCurlSession; }

bool PrivateKeyEncrypted(const std::string& keyPathParm)
{
    bool  encrypted = false;
    FILE* key       = fopen(keyPathParm.c_str(), "r");
    if(key)
    {
        fseek(key, 0, SEEK_END);
        int len = ftell(key);
        rewind(key);

        char* privKey = (char*)calloc(len + 1, 1);
        if(privKey)
        {
            int read_len = fread(privKey, 1, len, key);

            if(read_len == len)
            {
                char* location = strstr(privKey, "ENCRYPTED");
                if(location)
                {
                    encrypted = true;
                }
            }
            free(privKey);
            privKey = NULL;
        }
        fclose(key);
    }
    else
    {
        std::cerr << "ERROR: Unable to open ssh key file " << keyPathParm << std::endl;
    }
    return encrypted;
}

static bool ValidateRequiredArgsV1(const sf_client::CommandArgsV1& argsParm)
{
    if(argsParm.mProject.empty())
    {
        return false;
    }
    else if(argsParm.mComment.empty())
    {
        return false;
    }
    else
    {
        return true;
    }
}

sf_client::rc sf_client::connectToServer(const ServerInfoV1& serverParm, Session& sessionParm)
{
    if(!sessionParm.mCurlSession)
    {
        return failure;
    }
    else if(0 != serverParm.mPrivateKeyPath.length()
            && !PrivateKeyEncrypted(serverParm.mPrivateKeyPath))
    {
        return pkey_not_encrypted;
    }

    Curl_ServerInfo sServerInfo;
    sServerInfo.mUrl            = serverParm.mUrl;
    sServerInfo.mPrivateKeyPath = serverParm.mPrivateKeyPath;
    if(0 != sServerInfo.mPrivateKeyPath.length())
    {
        sServerInfo.mPublicKeyPath = serverParm.mPrivateKeyPath + ".pub";
    }
    else
    {
        sServerInfo.mPublicKeyPath.clear();
    }
    sServerInfo.mPasswordPtr = serverParm.mPasswordPtr;
    sServerInfo.mEpwdPath    = serverParm.mEpwdPath;
    sServerInfo.mVerbose     = serverParm.mVerbose;
    sServerInfo.mCurlDebug   = serverParm.mCurlDebug;
    sServerInfo.mUseSshAgent = serverParm.mUseSshAgent;

    return curlConnectToServer(sServerInfo, *sessionParm.mCurlSession);
}

sf_client::rc sf_client::disconnect(Session& sessionParm)
{
    if(!sessionParm.mCurlSession)
    {
        return failure;
    }
    curlDisconnectServer(*sessionParm.mCurlSession);
    return success;
}

sf_client::rc sf_client::sendCommandV1(Session&                        sessionParm,
                                       const sf_client::CommandArgsV1& argsParm,
                                       sf_client::CommandResponseV1&   responseParm)
{
    rc sRc = success;

    std::string sJsonRequestString;
    std::string sJsonResponseString;

    Json_CommandRequestV1  sJsonRequest;
    Json_CommandResponseV1 sJsonResponse;

    if(!ValidateRequiredArgsV1(argsParm))
    {
        sRc = invalid_parm;
    }

    if(success == sRc)
    {
        std::vector<uint8_t> sEpwdBinary;
        bool sIsSuccess = ReadFile(sessionParm.mCurlSession->mEpwdPath, sEpwdBinary);
        if(sIsSuccess)
        {
            // File is ASCII, copy directly into the string.
            sJsonRequest.mEpwdHex = std::string(sEpwdBinary.begin(), sEpwdBinary.end());
            RemoveAllWhitespace(sJsonRequest.mEpwdHex);
        }
        else
        {
            sRc = epwd_read_fail;
        }
    }

    if(success == sRc)
    {
        sJsonRequest.mComment          = argsParm.mComment;
        sJsonRequest.mParms            = argsParm.mExtraServerParms;
        sJsonRequest.mPayload          = argsParm.mPayload;
        sJsonRequest.mProject          = argsParm.mProject;
        sJsonRequest.mSelfReportedUser = GetLocalUser() + "@" + GetLocalHost();

        sRc = createCommandRequestJsonV1(sJsonRequest, sJsonRequestString);
    }

    if(success == sRc)
    {
        sRc = sendAndReceiveCommand(
            *sessionParm.mCurlSession, sJsonRequestString, sJsonResponseString);
    }

    if(success == sRc)
    {
        sRc = parseCommandResponseJsonV1(sJsonResponseString, sJsonResponse);
    }

    if(success == sRc)
    {
        responseParm.mOutput     = sJsonResponse.mResult;
        responseParm.mStdOut     = sJsonResponse.mStandardOut;
        responseParm.mReturnCode = sJsonResponse.mReturnValue;
    }

    return sRc;
}

sf_client::rc sf_client::sendCommandV2(Session&                        sessionParm,
                                       const sf_client::CommandArgsV2& argsParm,
                                       sf_client::CommandResponseV2&   responseParm)
{
    rc sRc = success;

    std::string sJsonRequestString;
    std::string sJsonResponseString;

    Json_CommandRequestV2  sJsonRequest;
    Json_CommandResponseV1 sJsonResponse;

    if(success == sRc)
    {
        std::vector<uint8_t> sEpwdBinary;
        bool sIsSuccess = ReadFile(sessionParm.mCurlSession->mEpwdPath, sEpwdBinary);
        if(sIsSuccess)
        {
            // File is ASCII, copy directly into the string.
            sJsonRequest.mEpwd = std::string(sEpwdBinary.begin(), sEpwdBinary.end());
            RemoveAllWhitespace(sJsonRequest.mEpwd);
        }
        else
        {
            sRc = epwd_read_fail;
        }
    }

    if(success == sRc)
    {
        sJsonRequest.mMode    = argsParm.mMode;
        sJsonRequest.mProject = argsParm.mProject;
        sJsonRequest.mComment = argsParm.mComment;
        sJsonRequest.mParms   = argsParm.mExtraServerParms;
        sJsonRequest.mPayload = argsParm.mPayload;

        sRc = createCommandRequestJsonV2(sJsonRequest, sJsonRequestString);
    }

    if(success == sRc)
    {
        sRc = sendAndReceiveCommand(
            *sessionParm.mCurlSession, sJsonRequestString, sJsonResponseString);
    }

    if(success == sRc)
    {
        sRc = parseCommandResponseJsonV1(sJsonResponseString, sJsonResponse);
    }

    if(success == sRc)
    {
        responseParm.mOutput     = sJsonResponse.mResult;
        responseParm.mStdOut     = sJsonResponse.mStandardOut;
        responseParm.mReturnCode = sJsonResponse.mReturnValue;
    }

    return sRc;
}
