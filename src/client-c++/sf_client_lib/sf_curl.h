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
#include <curl/curl.h>
#include <sf_client/sf_rc.h>
#include <string>

#ifndef _SFCURL_H
#define _SFCURL_H

namespace sf_client
{
    struct Curl_ServerInfo
    {
        Curl_ServerInfo()
        : mVerbose(false)
        , mCurlDebug(false)
        {
        }
        std::string mUrl;
        std::string mPrivateKeyPath;
        std::string mPublicKeyPath;
        std::string mEpwdPath;
        const char* mPasswordPtr;
        bool        mVerbose;
        bool        mCurlDebug;
    };

    struct Curl_Session
    {
        Curl_Session()
        : mCurlPtr(NULL)
        , mVerbose(false)
        {
        }
        CURL*       mCurlPtr;
        std::string mUrl;
        std::string mEpwdPath;
        bool        mVerbose;
    };

    rc   curlConnectToServer(const Curl_ServerInfo& serverInfoParm, Curl_Session& curlSessionParm);
    void curlDisconnectServer(Curl_Session& curlSessionParm);

    rc sendAndReceiveCommand(Curl_Session&      serverInfoParm,
                             const std::string& commandParm,
                             std::string&       responseParm);

} // namespace sf_client

#endif