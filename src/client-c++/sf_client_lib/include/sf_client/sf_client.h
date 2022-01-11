#include <stdint.h>
#include <string>
#include <vector>

#include <sf_client/sf_rc.h>

#ifndef _SFCLIENT_H
#define _SFCLIENT_H

namespace sf_client
{
    class Curl_Session;

    struct CommandArgsV1
    {
        CommandArgsV1()
        : mPasswordPtr(NULL)
        {
        }
        std::string          mProject;
        std::string          mComment;
        std::string          mExtraServerParms;
        std::vector<uint8_t> mPayload;
        char*                mPasswordPtr; // c_str (null-terminated)
    };

    struct CommandResponseV1
    {
        std::vector<uint8_t> mOutput;
        std::string          mStdOut;
        int                  mReturnCode;
    };

    struct ServerInfoV1
    {
        ServerInfoV1()
        : mVerbose(false)
        , mCurlDebug(false)
        {
        }
        std::string mUrl;
        std::string mPrivateKeyPath;
        std::string mEpwdPath;
        const char* mPasswordPtr;
        bool        mVerbose;
        bool        mCurlDebug;
    };

    struct Session
    {
        Session();
        ~Session();

        Curl_Session* mCurlSession;
    };

    rc connectToServer(const ServerInfoV1& serverParm, Session& sessionParm);

    rc disconnect(Session& sessionParm);

    rc sendCommandV1(Session&             sessionParm,
                     const CommandArgsV1& argsParm,
                     CommandResponseV1&   responseParm);
} // namespace sf_client

#endif
