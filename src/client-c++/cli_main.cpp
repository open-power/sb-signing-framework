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
#include <csignal>
#include <cstdio>
#include <cstring> // strlen
#include <fstream>
#include <getopt.h>
#include <iostream>
#include <openssl/crypto.h> // Used for OpenSSL_malloc
#include <sf_utils/sf_utils.h>
#include <string>
#include <termios.h>
#include <vector>

#include <sf_client/sf_client.h>

enum OptOptions
{
    // Required Args (must be grouped first for dynamic help text)
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
    ServerStdOut,
    Verbose,
    Debug,
    Help,

    NumOptOptions
};

enum
{
    NumRequiredArgs     = 6,
    MaxPasswordSize     = 1024,
    MaxPasswordAttempts = 3,
};

// clang-format off
struct option create_long_options[NumOptOptions + 1] =
{
    // Required
    {"project",  required_argument, NULL, 'p'},
    {"comments", required_argument, NULL, 'c'},
    {"epwd",     required_argument, NULL, 'e'},
    {"url",      required_argument, NULL, 'u'},
    {"pkey",     required_argument, NULL, 'k'},
    {"payload",  required_argument, NULL, 'i'},
    // Optional
    {"password", required_argument, NULL, 'a'},
    {"param",    required_argument, NULL, 'r'},
    {"output",   required_argument, NULL, 'o'},
    {"stdout",   no_argument,       NULL, 's'},
    {"verbose",  no_argument,       NULL, 'v'},
    {"debug",    no_argument,       NULL, 'd'},
    {"help",     no_argument,       NULL, 'h'},
    {0, 0, 0, 0}
};

const std::string OptOptionsHelpText[NumOptOptions] =
{
    // Required
    "Name of the project",
    "Identifier/Message for audit log",
    "File path to the hsm encrypted password",
    "sftp url. Example: sftp://user@address",
    "File path to the *encrypted* private key file",
    "File path to the binary to be signed",
    // Optional
    "Environment variable to read the password from",
    "Parameters to be passed to the signing framework. Ex '-v' or '-h'",
    "output file to save the return payload",
    "Displays the stdout from the server",
    "verbose tracing",
    "debug mode - files will not be deleted",
    "Display help text",
};
// clang-format on

struct SfClientArgs
{
    SfClientArgs()
    : mServerStdOut(false)
    , mVerbose(false)
    , mDebug(false)
    {
    }
    std::string mProject;
    std::string mComment;
    std::string mEpwdPath;
    std::string mUrl;
    std::string mPrivateKeyPath;
    std::string mPayloadPath;
    std::string mExtraServerParms;
    std::string mOutputPath;
    std::string mPasswordEnvVar;
    bool        mServerStdOut;
    bool        mVerbose;
    bool        mDebug;
    bool        mHelp;
};

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
    int sNumRequiredArgsFound = 0;
    while(1)
    {
        int sOptionIndex = 0;

        // Use getopt_long_only to enable long options using only a single dash (i.e. -project).
        // This allows scripts using the old sf_client (in C) to use this version without having to
        // be rewritten.
        sOption = getopt_long_only(
            argcParm, argvParm, sShortOptions.c_str(), create_long_options, &sOptionIndex);

        if(-1 == sOption)
        {
            break;
        }
        else if(sOption == create_long_options[Project].val)
        {
            sNumRequiredArgsFound++;
            argsParm.mProject = optarg;
        }
        else if(sOption == create_long_options[Comment].val)
        {
            sNumRequiredArgsFound++;
            argsParm.mComment = optarg;
        }
        else if(sOption == create_long_options[Epwd].val)
        {
            sNumRequiredArgsFound++;
            argsParm.mEpwdPath = optarg;
        }
        else if(sOption == create_long_options[Url].val)
        {
            sNumRequiredArgsFound++;
            argsParm.mUrl = optarg;
        }
        else if(sOption == create_long_options[PrivateKey].val)
        {
            sNumRequiredArgsFound++;
            argsParm.mPrivateKeyPath = optarg;
        }
        else if(sOption == create_long_options[Payload].val)
        {
            sNumRequiredArgsFound++;
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
        else if(sOption == create_long_options[ServerStdOut].val)
        {
            argsParm.mServerStdOut = true;
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
    std::cout << "Required:" << std::endl;
    for(std::size_t sIdx = 0; sIdx < NumOptOptions; sIdx++)
    {
        // Assumes that the required args always are grouped first in the list
        if(NumRequiredArgs == sIdx)
        {
            std::cout << std::endl << "Optional:" << std::endl;
        }
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
        std::cout << " | " << OptOptionsHelpText[sIdx] << std::endl;
    }
}

void Verbose_PrintArgs(const SfClientArgs& argsParm)
{
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
    std::cout << "StdOut:   " << (argsParm.mServerStdOut ? "true" : "false") << std::endl;
    std::cout << "Verbose:  " << (argsParm.mVerbose ? "true" : "false") << std::endl;
    std::cout << "Debug:    " << (argsParm.mDebug ? "true" : "false") << std::endl;
}

int main(int argc, char** argv)
{
    std::string sProgramName = argv[0];
    bool        sIsSuccess   = true;
    bool        sIsConnected = false;

    sf_client::ServerInfoV1      sSfServerV1;
    sf_client::CommandArgsV1     sSfArgsV1;
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

    if(sIsSuccess && !sArgs.mPayloadPath.empty())
    {
        sIsSuccess = ReadFile(sArgs.mPayloadPath, sSfArgsV1.mPayload);
    }

    // Make life easier: if the project is "password_change" turn on stdout automatically.
    // Otherwise the password will be changed but the result will not be presented to the
    // caller.
    if(sIsSuccess && sArgs.mProject == std::string("password_change"))
    {
        sArgs.mServerStdOut = true;
        std::cout << "Set std out true" << std::endl;
    }

    if(sIsSuccess)
    {
        sSfServerV1.mUrl            = sArgs.mUrl;
        sSfServerV1.mEpwdPath       = sArgs.mEpwdPath;
        sSfServerV1.mCurlDebug      = sArgs.mDebug;
        sSfServerV1.mVerbose        = sArgs.mVerbose;
        sSfServerV1.mPasswordPtr    = NULL;

        sSfArgsV1.mProject          = sArgs.mProject;
        sSfArgsV1.mComment          = sArgs.mComment;
        sSfArgsV1.mExtraServerParms = sArgs.mExtraServerParms;
    }

    if(sIsSuccess &&
       (NULL != getenv("SSH_AUTH_SOCK") ||
        NULL != getenv("SSH_AGENT_PID")) )
    {
        sf_client::rc sRc        = sf_client::failure;
        // Attempt a connection without providing a password. If the key is registered in an agent
        // then the connection will work without needing user interaction.
        sRc = sf_client::connectToServer(sSfServerV1, sSession);

        sIsConnected = (sf_client::success == sRc);
    }

    // Provide private key to any other connection attempts
    sSfServerV1.mPrivateKeyPath = sArgs.mPrivateKeyPath;

    if(sIsSuccess && !sIsConnected && !sArgs.mPasswordEnvVar.empty())
    {
        sSfServerV1.mPasswordPtr = getenv(sArgs.mPasswordEnvVar.c_str());
        sf_client::rc sRc        = sf_client::connectToServer(sSfServerV1, sSession);
        sIsSuccess               = sf_client::success == sRc;
        // The password was provided in the environment. If it is wrong there is nothing else to be
        // done.
    }
    else if(sIsSuccess && !sIsConnected)
    {

        sf_client::rc sRc = sf_client::success;

        char* sPasswordPtr = (char*)OPENSSL_malloc(MaxPasswordSize);
        if(sPasswordPtr)
            memset(sPasswordPtr, 0, MaxPasswordSize);

        if(!sPasswordPtr)
        {
            std::cerr << "Unable to allocate memory for password buffer" << std::endl;
            sIsSuccess = false;
        }
        else
        {
            std::size_t sNumAttempts = 0;
            do
            {
                sNumAttempts++;

                std::size_t sPasswordLength = 0;

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
                    sRc = sf_client::connectToServer(sSfServerV1, sSession);
                }

                if(sArgs.mVerbose)
                {
                    std::cout << "Finishing Attempt #" << sNumAttempts << std::endl;
                }
            } while(sf_client::password_retry == sRc && sNumAttempts < MaxPasswordAttempts);

            memset(sPasswordPtr, 0, MaxPasswordSize);
            OPENSSL_free(sPasswordPtr);

            sIsSuccess = (sf_client::success == sRc);
        }
        if(!sIsSuccess)
        {
            std::cout << "Unable to connect to server, rc = " << sRc << std::endl;
        }
    }

    if(sIsSuccess)
    {
        sf_client::rc sRc = sf_client::sendCommandV1(sSession, sSfArgsV1, sSfResponseV1);
        sIsSuccess        = sf_client::success == sRc;
    }

    if(sIsSuccess)
    {
        if(sArgs.mServerStdOut)
        {
            std::cout << std::endl;
            std::cout << "==== Begin Standard Out ====" << std::endl;
            std::cout << std::endl;
            std::cout << sSfResponseV1.mStdOut << std::endl;
            std::cout << "==== End of Standard Out ====" << std::endl;
        }

        if(0 != sSfResponseV1.mReturnCode)
        {
            std::cerr << "Signing server responded with failure: " << sSfResponseV1.mReturnCode
                      << std::endl
                      << "Rerun with -stdout to see server output" << std::endl;
        }

        if(!sArgs.mOutputPath.empty())
        {
            sIsSuccess = WriteFile(sArgs.mOutputPath, sSfResponseV1.mOutput);
        }
    }

    if(sIsSuccess)
        std::cout << "DONE" << std::endl;

    return sIsSuccess ? 0 : -1;
}
