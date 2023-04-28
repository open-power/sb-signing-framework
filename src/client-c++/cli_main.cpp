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
#include <algorithm>
#include <csignal>
#include <cstdio>
#include <cstring> // strlen
#include <fstream>
#include <iostream>
#include <openssl/crypto.h> // Used for OpenSSL_malloc
#include <sf_utils/sf_utils.h>
#include <string>
#include <termios.h>
#include <unistd.h>
#include <vector>

#ifndef NO_GETOPT_LONG
#include <getopt.h>
#else
struct option
{
    const char* name;
    int         has_arg;
    int*        flag;
    int         val;
};
enum
{
    required_argument = 1,
    no_argument       = 0,
};
#endif

#include <sf_client/sf_client.h>

enum OptOptions
{
    // Required Args (must be grouped first for dynamic help text)
    Mode,
    Project,
    Comment,
    Epwd,
    Url,
    PrivateKey,
    Payload,

    // Optional Args
    PasswordEnvVar,
    Param,
    Output,
    Verbose,
    Debug,
    Help,

    NumOptOptions
};

enum
{
    MaxPasswordSize     = 1024,
    MaxPasswordAttempts = 3,
};

// clang-format off
struct option create_long_options[NumOptOptions + 1] =
{
    {"mode",     required_argument, NULL, 'm'},
    {"project",  required_argument, NULL, 'p'},
    {"comments", required_argument, NULL, 'c'},
    {"epwd",     required_argument, NULL, 'e'},
    {"url",      required_argument, NULL, 'u'},
    {"pkey",     required_argument, NULL, 'k'},
    {"payload",  required_argument, NULL, 'i'},
    {"password", required_argument, NULL, 'a'},
    {"param",    required_argument, NULL, 'r'},
    {"output",   required_argument, NULL, 'o'},
    {"verbose",  no_argument,       NULL, 'v'},
    {"debug",    no_argument,       NULL, 'd'},
    {"help",     no_argument,       NULL, 'h'},
    {0, 0, 0, 0}
};

const std::string OptOptionsHelpText[NumOptOptions] =
{
    // Required
    "sign|getpublickey|epwd|log|config|block",
    "Name of the project",
    "Identifier/Message for audit log",
    "File path to the hsm encrypted password",
    "sftp url. Example: sftp://user@address:Port",
    "File path to the *encrypted* private key file",
    "File path to the binary to be signed",
    // Optional
    "Environment variable to read the password from",
    "Parameters to be passed to the signing framework. Ex '-v' or '-h'",
    "output file to save the return payload",
    "verbose tracing",
    "debug mode",
    "Display help text",
};
// clang-format on

struct SfClientArgs
{
    SfClientArgs()
    : mVerbose(false)
    , mDebug(false)
    , mHelp(false)
    {
    }
    std::string mMode;
    std::string mProject;
    std::string mComment;
    std::string mEpwdPath;
    std::string mUrl;
    std::string mPrivateKeyPath;
    std::string mPayloadPath;
    std::string mExtraServerParms;
    std::string mOutputPath;
    std::string mPasswordEnvVar;
    bool        mVerbose;
    bool        mDebug;
    bool        mHelp;
};

struct SfClientArgsRequired
{
    bool mProject;
    bool mComment;
    bool mEpwdPath;
    bool mUrl;
    bool mPrivateKeyPath;
    bool mPayloadPath;
    bool mExtraServerParms;
    bool mOutputPath;
};

bool CaseInsensitiveCompareChar(char lhs, char rhs)
{
    return std::toupper(lhs) == std::toupper(rhs);
}

bool CaseInsensitiveCompare(const std::string& lhs, const std::string& rhs)
{
    if(lhs.size() != rhs.size())
    {
        return false;
    }
    return std::equal(lhs.begin(), lhs.end(), rhs.begin(), CaseInsensitiveCompareChar);
}

SfClientArgsRequired GetRequiredArgsForMode(const std::string& modeParm)
{
    SfClientArgsRequired sRequired;
    sRequired.mUrl            = true;
    sRequired.mPrivateKeyPath = true;

    if(CaseInsensitiveCompare("sign", modeParm))
    {
        sRequired.mProject          = true;
        sRequired.mComment          = true;
        sRequired.mEpwdPath         = true;
        sRequired.mPayloadPath      = true;
        sRequired.mExtraServerParms = false;
        sRequired.mOutputPath       = true;
    }
    else if(CaseInsensitiveCompare("getpublickey", modeParm))
    {
        sRequired.mProject          = true;
        sRequired.mComment          = false;
        sRequired.mEpwdPath         = false;
        sRequired.mPayloadPath      = false;
        sRequired.mExtraServerParms = false;
        sRequired.mOutputPath       = true;
    }
    else if(CaseInsensitiveCompare("epwd", modeParm))
    {
        sRequired.mProject          = false;
        sRequired.mComment          = false;
        sRequired.mEpwdPath         = false;
        sRequired.mPayloadPath      = true;
        sRequired.mExtraServerParms = false;
        sRequired.mOutputPath       = true;
    }
    else if(CaseInsensitiveCompare("log", modeParm))
    {
        sRequired.mProject          = true;
        sRequired.mComment          = false;
        sRequired.mEpwdPath         = false;
        sRequired.mPayloadPath      = false;
        sRequired.mExtraServerParms = false;
        sRequired.mOutputPath       = true;
    }
    else if(CaseInsensitiveCompare("config", modeParm))
    {
        sRequired.mProject          = true;
        sRequired.mComment          = false;
        sRequired.mEpwdPath         = false;
        sRequired.mPayloadPath      = false;
        sRequired.mExtraServerParms = false;
        sRequired.mOutputPath       = true;
    }
    else if(CaseInsensitiveCompare("block", modeParm))
    {
        sRequired.mProject          = true;
        sRequired.mComment          = false;
        sRequired.mEpwdPath         = false;
        sRequired.mPayloadPath      = false;
        sRequired.mExtraServerParms = false;
        sRequired.mOutputPath       = false;
    }
    else
    {
        // Unknown mode, defaults to V1 API. Use "signing" mode
        sRequired.mProject          = true;
        sRequired.mComment          = true;
        sRequired.mEpwdPath         = true;
        sRequired.mPayloadPath      = true;
        sRequired.mExtraServerParms = false;
        sRequired.mOutputPath       = true;
    }
    return sRequired;
}

bool ParseArgs(const int argcParm, char** argvParm, SfClientArgs& argsParm)
{
    std::string sShortOptions = "";

    for(std::size_t sIdx = 0; sIdx < NumOptOptions; sIdx++)
    {
        sShortOptions += create_long_options[sIdx].val;
        if(required_argument == create_long_options[sIdx].has_arg)
        {
            sShortOptions += ":";
        }
    }

    int sOption;
    while(1)
    {

#ifdef NO_GETOPT_LONG
        sOption = getopt(argcParm, argvParm, sShortOptions.c_str());
#else
        int sOptionIndex = 0;
        // Use getopt_long_only to enable long options using only a single dash (i.e. -project).
        // This allows scripts using the old sf_client (in C) to use this version without having to
        // be rewritten.
        sOption = getopt_long_only(
            argcParm, argvParm, sShortOptions.c_str(), create_long_options, &sOptionIndex);
#endif

        if(-1 == sOption)
        {
            break;
        }
        else if(sOption == create_long_options[Mode].val)
        {
            argsParm.mMode = optarg;
        }
        else if(sOption == create_long_options[Project].val)
        {
            argsParm.mProject = optarg;
        }
        else if(sOption == create_long_options[Comment].val)
        {
            argsParm.mComment = optarg;
        }
        else if(sOption == create_long_options[Epwd].val)
        {
            argsParm.mEpwdPath = optarg;
        }
        else if(sOption == create_long_options[Url].val)
        {
            argsParm.mUrl = optarg;
        }
        else if(sOption == create_long_options[PrivateKey].val)
        {
            argsParm.mPrivateKeyPath = optarg;
        }
        else if(sOption == create_long_options[Payload].val)
        {
            argsParm.mPayloadPath = optarg;
        }
        else if(sOption == create_long_options[PasswordEnvVar].val)
        {
            argsParm.mPasswordEnvVar = optarg;
        }
        else if(sOption == create_long_options[Param].val)
        {
            argsParm.mExtraServerParms = optarg;
        }
        else if(sOption == create_long_options[Output].val)
        {
            argsParm.mOutputPath = optarg;
        }
        else if(sOption == create_long_options[Verbose].val)
        {
            argsParm.mVerbose = true;
        }
        else if(sOption == create_long_options[Debug].val)
        {
            argsParm.mDebug = true;
        }
        else if(sOption == create_long_options[Help].val)
        {
            argsParm.mHelp = true;
        }
    }

    return true;
}

void PrintHelp(const std::string& programNameParm)
{
    std::size_t sLongestOption = 0;
    for(std::size_t sIdx = 0; sIdx < NumOptOptions; sIdx++)
    {
        std::size_t sLength = strlen(create_long_options[sIdx].name);
        sLongestOption      = std::max(sLength, sLongestOption);
    }

    std::cout << "Usage: " << programNameParm << std::endl;
#ifdef NO_GETOPT_LONG
    std::cout << "Version: C++ NO_GETOPT_LONG" << std::endl;
#else
    std::cout << "Version: C++" << std::endl;
#endif
    for(std::size_t sIdx = 0; sIdx < NumOptOptions; sIdx++)
    {
#ifdef NO_GETOPT_LONG
        std::cout << "\t-" << (char)create_long_options[sIdx].val;
#else
        std::size_t sCurrentOptionLength = strlen(create_long_options[sIdx].name);
        std::cout << "\t-" << (char)create_long_options[sIdx].val << " -"
                  << create_long_options[sIdx].name;
        for(std::size_t sPadIdx = 0; sPadIdx < (sLongestOption - sCurrentOptionLength); sPadIdx++)
        {
            std::cout << " ";
        }
        std::cout << " --" << create_long_options[sIdx].name;
        for(std::size_t sPadIdx = 0; sPadIdx < (sLongestOption - sCurrentOptionLength); sPadIdx++)
        {
            std::cout << " ";
        }
#endif
        std::cout << " | " << OptOptionsHelpText[sIdx] << std::endl;
    }
}

void Verbose_PrintArgs(const SfClientArgs& argsParm)
{
    std::cout << "Mode:               " << argsParm.mMode << std::endl;
    std::cout << "Project:            " << argsParm.mProject << std::endl;
    std::cout << "Comment:            " << argsParm.mComment << std::endl;
    std::cout << "Epwd Path:          " << argsParm.mEpwdPath << std::endl;
    std::cout << "URL:                " << argsParm.mUrl << std::endl;
    std::cout << "Private Key Path:   " << argsParm.mPrivateKeyPath << std::endl;
    std::cout << "Payload Path:       " << argsParm.mPayloadPath << std::endl;
    std::cout << "Extra Server Parms: " << argsParm.mExtraServerParms << std::endl;
    std::cout << "Output Path:        " << argsParm.mOutputPath << std::endl;
    std::cout << "Password ENV:        " << argsParm.mPasswordEnvVar << std::endl;
    std::cout << std::endl;
    std::cout << "Verbose:  " << (argsParm.mVerbose ? "true" : "false") << std::endl;
    std::cout << "Debug:    " << (argsParm.mDebug ? "true" : "false") << std::endl;
}

int main(int argc, char** argv)
{
    std::string sProgramName = argv[0];
    bool        sIsSuccess   = true;

    sf_client::ServerInfoV1      sSfServerV1;
    sf_client::CommandArgsV2     sSfArgsV2;
    sf_client::CommandResponseV1 sSfResponseV1;
    sf_client::Session           sSession;

    SfClientArgs sArgs;
    sIsSuccess = ParseArgs(argc, argv, sArgs);

    if(sArgs.mVerbose)
    {
        Verbose_PrintArgs(sArgs);
    }

    if(!sIsSuccess || sArgs.mHelp)
    {
        PrintHelp(sProgramName);
        return -1; // Early return for simplicity
    }

    if(sIsSuccess)
    {
        SfClientArgsRequired sRequiredArgs = GetRequiredArgsForMode(sArgs.mMode);

        std::string sModeToPrint = (sArgs.mMode.empty()) ? "V1_COMPAT_API" : sArgs.mMode;

        if(sRequiredArgs.mProject && sArgs.mProject.empty())
        {
            sIsSuccess = false;
            printf("\"%s\" is required for \"%s\" mode.\n",
                   create_long_options[Project].name,
                   sModeToPrint.c_str());
        }

        if(sRequiredArgs.mComment && sArgs.mComment.empty())
        {
            sIsSuccess = false;
            printf("\"%s\" is required for \"%s\" mode.\n",
                   create_long_options[Comment].name,
                   sModeToPrint.c_str());
        }

        if(sRequiredArgs.mEpwdPath && sArgs.mEpwdPath.empty())
        {
            sIsSuccess = false;
            printf("\"%s\" is required for \"%s\" mode.\n",
                   create_long_options[Epwd].name,
                   sModeToPrint.c_str());
        }

        if(sRequiredArgs.mUrl && sArgs.mUrl.empty())
        {
            sIsSuccess = false;
            printf("\"%s\" is required for \"%s\" mode.\n",
                   create_long_options[Url].name,
                   sModeToPrint.c_str());
        }

        if(sRequiredArgs.mPrivateKeyPath && sArgs.mPrivateKeyPath.empty())
        {
            sIsSuccess = false;
            printf("\"%s\" is required for \"%s\" mode.\n",
                   create_long_options[PrivateKey].name,
                   sModeToPrint.c_str());
        }

        if(sRequiredArgs.mPayloadPath && sArgs.mPayloadPath.empty())
        {
            sIsSuccess = false;
            printf("\"%s\" is required for \"%s\" mode.\n",
                   create_long_options[Payload].name,
                   sModeToPrint.c_str());
        }

        if(sRequiredArgs.mOutputPath && sArgs.mOutputPath.empty())
        {
            sIsSuccess = false;
            printf("\"%s\" is required for \"%s\" mode.\n",
                   create_long_options[Output].name,
                   sModeToPrint.c_str());
        }

        if(sRequiredArgs.mExtraServerParms && sArgs.mExtraServerParms.empty())
        {
            sIsSuccess = false;
            printf("\"%s\" is required for \"%s\" mode.\n",
                   create_long_options[Param].name,
                   sModeToPrint.c_str());
        }
    }

    if(sIsSuccess && !sArgs.mPayloadPath.empty())
    {
        sIsSuccess = ReadFile(sArgs.mPayloadPath, sSfArgsV2.mPayload);
    }

    if(sIsSuccess)
    {
        sSfServerV1.mUrl            = sArgs.mUrl;
        sSfServerV1.mEpwdPath       = sArgs.mEpwdPath;
        sSfServerV1.mCurlDebug      = sArgs.mDebug;
        sSfServerV1.mVerbose        = sArgs.mVerbose;
        sSfServerV1.mPrivateKeyPath = sArgs.mPrivateKeyPath;
        sSfServerV1.mPasswordPtr    = NULL;

        sSfArgsV2.mProject          = sArgs.mProject;
        sSfArgsV2.mComment          = sArgs.mComment;
        sSfArgsV2.mMode             = sArgs.mMode;
        sSfArgsV2.mExtraServerParms = sArgs.mExtraServerParms;
    }

    // For each connection attempt sIsSuccess = false is an unrecoverable failure. If a connection
    // attempt fails, sIsSuccess will be true, but sIsConnected will be false.

    bool sIsConnected = false;

    // Attempt Agent First
    if(sIsSuccess && !sIsConnected)
    {
        // Attempt connection using ssh-agent. The password field is not required. If the key is NOT
        // in the agent, then curl will fail instead of using an unencrypted key.
        sf_client::rc sRc        = sf_client::failure;
        sSfServerV1.mUseSshAgent = true;
        sRc                      = sf_client::connectToServer(sSfServerV1, sSession);
        if(sf_client::success == sRc)
        {
            sIsConnected = true;
            std::cout << "Established connection using SSH_AGENT" << std::endl;
        }
    }

    // Attempt ENV (if defined)
    if(sIsSuccess && !sIsConnected && !sArgs.mPasswordEnvVar.empty())
    {
        sSfServerV1.mUseSshAgent = false;
        sSfServerV1.mPasswordPtr = getenv(sArgs.mPasswordEnvVar.c_str());
        sf_client::rc sRc        = sf_client::connectToServer(sSfServerV1, sSession);
        if(sf_client::success == sRc)
        {
            sIsConnected = true;
            std::cout << "Established connection using ENV password" << std::endl;
        }
    }

    // Attempt password
    if(sIsSuccess && !sIsConnected)
    {
        // Provide private key to any other connection attempts
        sSfServerV1.mUseSshAgent = false;
        sf_client::rc sRc        = sf_client::success;

        char* sPasswordPtr = (char*)OPENSSL_malloc(MaxPasswordSize);
        if(sPasswordPtr)
            memset(sPasswordPtr, 0, MaxPasswordSize);

        if(!sPasswordPtr)
        {
            std::cerr << "Unable to allocate memory for password buffer" << std::endl;
        }
        else
        {
            std::size_t sNumAttempts = 0;
            do
            {
                sNumAttempts++;

                uint64_t sPasswordLength = 0;

                const bool sResult = GetPassword(
                    sPasswordPtr, MaxPasswordSize, sPasswordLength, sArgs.mVerbose);

                if(sArgs.mVerbose)
                {
                    std::cout << "GetPassword Result: " << (sResult ? "true" : "false")
                              << std::endl;
                }

                if(sResult)
                {
                    sSfServerV1.mPasswordPtr = sPasswordPtr;
                    sRc                      = sf_client::connectToServer(sSfServerV1, sSession);
                }

                if(sArgs.mVerbose)
                {
                    std::cout << "Finishing Attempt #" << sNumAttempts << std::endl;
                }
            } while(sf_client::password_retry == sRc && sNumAttempts < MaxPasswordAttempts);

            memset(sPasswordPtr, 0, MaxPasswordSize);
            OPENSSL_free(sPasswordPtr);

            if(sf_client::success == sRc)
            {
                sIsConnected = true;
                std::cout << "Established connection using prompt" << std::endl;
            }
            else
            {
                std::cout << "Unable to connect to server, rc = " << sRc << std::endl;
            }
        }
    }

    if(!sIsConnected)
    {
        std::cout << "Unable to establish connection to server" << std::endl;
        sIsSuccess = false;
    }

    if(sIsSuccess)
    {
        sf_client::rc sRc = sf_client::sendCommandV2(sSession, sSfArgsV2, sSfResponseV1);
        if(sf_client::success != sRc)
        {
            sIsSuccess = false;
            std::cout << "Send Command Failed with rc: " << (int)sRc << std::endl;
        }
    }

    if(sIsSuccess)
    {
        std::cout << std::endl;
        std::cout << "==== Begin Standard Out ====" << std::endl;
        std::cout << std::endl;
        std::cout << sSfResponseV1.mStdOut << std::endl;
        std::cout << "==== End of Standard Out ====" << std::endl;

        if(0 != sSfResponseV1.mReturnCode)
        {
            std::cerr << "Signing server responded with failure: " << sSfResponseV1.mReturnCode
                      << std::endl;
        }

        if(!sArgs.mOutputPath.empty())
        {
            sIsSuccess = WriteFile(sArgs.mOutputPath, sSfResponseV1.mOutput);
        }
    }

    if(sIsSuccess)
        std::cout << "DONE" << std::endl;
    else
        std::cout << "FAILED" << std::endl;

    return (sIsSuccess) ? sSfResponseV1.mReturnCode : -1;
}
