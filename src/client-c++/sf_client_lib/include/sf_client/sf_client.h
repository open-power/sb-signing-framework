/* Copyright 2022 IBM Corp.
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
#include <stdint.h>
#include <string>
#include <vector>

#include <sf_client/sf_rc.h>

#ifndef _SFCLIENT_H
#define _SFCLIENT_H

namespace sf_client
{
    struct Curl_Session;

    struct CommandResponse
    {
        std::vector<uint8_t> mOutput;
        std::string          mStdOut;
        int                  mReturnCode;
    };

    struct ServerInfo
    {
        ServerInfo()
        : mUseSshAgent(false)
        , mVerbose(false)
        , mCurlDebug(false)
        {
        }
        std::string mUrl;
        std::string mPrivateKeyPath;
        std::string mEpwdPath;
        bool        mUseSshAgent;
        const char* mPasswordPtr;
        bool        mVerbose;
        bool        mCurlDebug;
    };

    struct CommandArgs
    {
        CommandArgs()
        : mPasswordPtr(NULL)
        {
        }
        std::string          mMode;
        std::string          mProject;
        std::string          mComment;
        std::string          mExtraServerParms;
        std::vector<uint8_t> mPayload;
        char*                mPasswordPtr; // c_str (null-terminated)
    };

    typedef CommandResponse CommandResponse;

    struct Session
    {
        Session();
        ~Session();

        Curl_Session* mCurlSession;
    };

    rc connectToServer(const ServerInfo& serverParm, Session& sessionParm);

    rc disconnect(Session& sessionParm);

    rc
    sendCommandV1(Session& sessionParm, const CommandArgs& argsParm, CommandResponse& responseParm);

    rc
    sendCommandV2(Session& sessionParm, const CommandArgs& argsParm, CommandResponse& responseParm);
} // namespace sf_client

#endif
