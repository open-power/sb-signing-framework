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
#include <cstring>
#include <curl/curl.h>
#include <errno.h>
#include <iostream>
#include <sf_client/sf_rc.h>
#include <sf_utils/sf_utils.h>
#include <sstream>
#include <string>
#include <time.h>
#include <unistd.h>

#include "sf_curl.h"

#define SET_CURL_OPTION(return_code, session, option, value)                                       \
    if(CURLE_OK == (return_code))                                                                  \
    {                                                                                              \
        (return_code) = curl_easy_setopt((session).mCurlPtr, (option), (value));                   \
    }

#define RUN_CURL_SESSION(return_code, session)                                                     \
    if(CURLE_OK == (return_code))                                                                  \
    {                                                                                              \
        (return_code) = curl_easy_perform((session).mCurlPtr);                                     \
    }

#define WRITE_TO_SERVER(return_code, session, url, data)                                           \
    if(CURLE_OK == (return_code))                                                                  \
    {                                                                                              \
        (return_code) = WriteToServer((session), (url), (data));                                   \
    }

#define READ_FROM_SERVER(return_code, session, url, data)                                          \
    if(CURLE_OK == (return_code))                                                                  \
    {                                                                                              \
        (return_code) = ReadFromServer((session), (url), (data));                                  \
    }

enum
{
    MaxPollingTimeInSeconds = 50,
    PollingWaitInSeconds    = 1,
    MaxPollingAttempts      = MaxPollingTimeInSeconds / PollingWaitInSeconds,
};

const static std::string RequestExtension    = ".request";
const static std::string RequestGoExtension  = ".request.go";
const static std::string ResponseExtension   = ".response";
const static std::string ResponseGoExtension = ".response.go";
const static std::string ServerDirectory     = "dropbox/";

static std::string GetFilePrefix()
{
    std::stringstream ss;
    ss << GetLocalUser() << "_" << GetLocalHost() << "_" << time(NULL);
    return ss.str();
}

struct SessionFilenames
{
    SessionFilenames(const std::string& urlParm)
    {
        const std::string sPrefix = urlParm + "/" + ServerDirectory + "/" + GetFilePrefix();

        mCommandFile    = sPrefix + RequestExtension;
        mCommandFileGo  = sPrefix + RequestGoExtension;
        mResponseFile   = sPrefix + ResponseExtension;
        mResponseFileGo = sPrefix + ResponseGoExtension;
    }
    std::string mCommandFile;
    std::string mCommandFileGo;
    std::string mResponseFile;
    std::string mResponseFileGo;
};

struct CurlPayload
{
    CurlPayload(bool verboseParm)
    {
        mBytesProccessed = 0;
        mVerbose         = verboseParm;
    }
    CurlPayload(const std::string& dataParm, bool verboseParm)
    {
        mBytesProccessed = 0;
        mData            = dataParm;
        mVerbose         = verboseParm;
    }
    std::size_t mBytesProccessed;
    std::string mData;
    bool        mVerbose;
};

// The buffer by default will be 16K. This should be plenty.
size_t read_callback(char*  dataToSendPtrParm,
                     size_t memberSizeParm,
                     size_t numMembersParm,
                     void*  localDataToReadParm)
{
    if(!dataToSendPtrParm || !dataToSendPtrParm)
    {
        return CURL_READFUNC_ABORT;
    }
    CurlPayload& sDataToRead          = *(CurlPayload*)localDataToReadParm;
    const size_t sTotalBytesAvailable = memberSizeParm * numMembersParm;
    const size_t sBytesRemaining      = sDataToRead.mData.size() - sDataToRead.mBytesProccessed;
    const size_t sBytesToRead         = std::min(sTotalBytesAvailable, sBytesRemaining);

    const char* sReadPtr = sDataToRead.mData.c_str() + sDataToRead.mBytesProccessed;
    memcpy(dataToSendPtrParm, sReadPtr, sBytesToRead);

    sDataToRead.mBytesProccessed += sBytesToRead;

    if(sDataToRead.mVerbose)
        std::cout << "Sent " << sBytesToRead << " bytes" << std::endl;

    return sBytesToRead;
}

CURLcode WriteToServer(sf_client::Curl_Session& curlSessionParm,
                       const std::string&       urlParm,
                       const std::string&       srcParm)
{
    CURLcode sRc = CURLE_OK;
    if(curlSessionParm.mVerbose)
    {
        std::cout << "WRITE_TO_SERVER: " << srcParm << std::endl;
    }

    SET_CURL_OPTION(sRc, curlSessionParm, CURLOPT_URL, urlParm.c_str());
    SET_CURL_OPTION(sRc, curlSessionParm, CURLOPT_UPLOAD, 1L);
    SET_CURL_OPTION(sRc, curlSessionParm, CURLOPT_READFUNCTION, read_callback);

    // For some reason CURLOPT_READDATA and std::string do not work properly when CurlPayload is
    // allocated on the stack.
    CurlPayload* sPayload = new CurlPayload(srcParm, curlSessionParm.mVerbose);

    if(sPayload)
    {
        SET_CURL_OPTION(sRc, curlSessionParm, CURLOPT_READDATA, sPayload);

        RUN_CURL_SESSION(sRc, curlSessionParm);
        delete sPayload;
    }
    else
    {
        sRc = CURLE_OUT_OF_MEMORY;
    }

    return sRc;
}

size_t write_callback(char*  receivedDataPtrParm,
                      size_t memberSizeParm,
                      size_t numMembersParm,
                      void*  localDataToWriteParm)
{
    if(!receivedDataPtrParm || !localDataToWriteParm)
    {
        return 0;
    }

    CurlPayload& sDataToWrite  = *(CurlPayload*)localDataToWriteParm;
    std::string& sDstString    = sDataToWrite.mData;
    const size_t sBytesToWrite = memberSizeParm * numMembersParm;

    sDstString += std::string(receivedDataPtrParm, receivedDataPtrParm + sBytesToWrite);
    sDataToWrite.mBytesProccessed += sBytesToWrite;

    if(sDataToWrite.mVerbose)
    {
        std::cout << "Received " << sBytesToWrite << " bytes" << std::endl;
    }

    return sBytesToWrite;
}

CURLcode ReadFromServer(sf_client::Curl_Session& curlSessionParm,
                        const std::string&       urlParm,
                        std::string&             dstParm)
{
    CURLcode sRc = CURLE_OK;

    SET_CURL_OPTION(sRc, curlSessionParm, CURLOPT_URL, urlParm.c_str());
    SET_CURL_OPTION(sRc, curlSessionParm, CURLOPT_UPLOAD, 0L);
    SET_CURL_OPTION(sRc, curlSessionParm, CURLOPT_WRITEFUNCTION, write_callback);

    // For some reason CURLOPT_READDATA and std::string do not work properly when CurlPayload is
    // allocated on the stack.

    CurlPayload* sPayload = new CurlPayload(curlSessionParm.mVerbose);
    if(sPayload)
    {
        SET_CURL_OPTION(sRc, curlSessionParm, CURLOPT_WRITEDATA, sPayload);

        RUN_CURL_SESSION(sRc, curlSessionParm);

        if(CURLE_OK == sRc)
        {
            dstParm = sPayload->mData;
        }
        delete sPayload;
    }
    else
    {
        sRc = CURLE_OUT_OF_MEMORY;
    }

    if(curlSessionParm.mVerbose && (CURLE_OK == sRc))
    {
        std::cout << "READ_FROM_SERVER: " << dstParm << std::endl;
    }

    return sRc;
}

sf_client::rc sf_client::curlConnectToServer(const Curl_ServerInfo& serverInfoParm,
                                             Curl_Session&          curlSessionParm)
{
    CURLcode sRc             = CURLE_OK;
    curlSessionParm.mCurlPtr = NULL;

    curlSessionParm.mVerbose  = serverInfoParm.mVerbose;
    curlSessionParm.mEpwdPath = serverInfoParm.mEpwdPath;

    // Init curl library
    if(CURLE_OK == sRc)
    {
        sRc = curl_global_init(CURL_GLOBAL_ALL);
    }

    if(CURLE_OK == sRc)
    {
        curlSessionParm.mCurlPtr = curl_easy_init();

        sRc = ((NULL != curlSessionParm.mCurlPtr) ? CURLE_OK : CURLE_FAILED_INIT);
    }

    if(serverInfoParm.mCurlDebug)
        SET_CURL_OPTION(sRc, curlSessionParm, CURLOPT_VERBOSE, 1L);

    if (0 != serverInfoParm.mPrivateKeyPath.length())
        SET_CURL_OPTION(
            sRc, curlSessionParm, CURLOPT_SSH_PRIVATE_KEYFILE, serverInfoParm.mPrivateKeyPath.c_str());
    if (0 != serverInfoParm.mPublicKeyPath.length())
        SET_CURL_OPTION(
            sRc, curlSessionParm, CURLOPT_SSH_PUBLIC_KEYFILE, serverInfoParm.mPublicKeyPath.c_str());

    SET_CURL_OPTION(sRc, curlSessionParm, CURLOPT_URL, serverInfoParm.mUrl.c_str());
    SET_CURL_OPTION(sRc, curlSessionParm, CURLOPT_PROTOCOLS, CURLPROTO_SFTP);

    SET_CURL_OPTION(sRc, curlSessionParm, CURLOPT_CONNECT_ONLY, 1L);

    if(serverInfoParm.mPasswordPtr)
        SET_CURL_OPTION(sRc, curlSessionParm, CURLOPT_KEYPASSWD, serverInfoParm.mPasswordPtr);

    if(CURLE_OK == sRc)
    {
        sRc = curl_easy_perform(curlSessionParm.mCurlPtr);
    }

    SET_CURL_OPTION(sRc, curlSessionParm, CURLOPT_CONNECT_ONLY, 0L);

    if(curlSessionParm.mCurlPtr)
    {
        if(CURLE_OK == sRc)
        {
            curlSessionParm.mUrl = serverInfoParm.mUrl;
        }
        else
        {
            curl_easy_cleanup(curlSessionParm.mCurlPtr);
            curlSessionParm.mCurlPtr = NULL;
        }
    }

    return (CURLE_OK == sRc) ? success : curl_init_failure;
}

void sf_client::curlDisconnectServer(Curl_Session& curlSessionParm)
{
    if(curlSessionParm.mCurlPtr)
    {
        curl_easy_cleanup(curlSessionParm.mCurlPtr);
    }
    curlSessionParm.mUrl.clear();
    curlSessionParm.mVerbose = false;
}

sf_client::rc sf_client::sendAndReceiveCommand(Curl_Session&      curlSessionParm,
                                               const std::string& commandParm,
                                               std::string&       responseParm)
{
    CURLcode sRc = CURLE_OK;

    // Automatically creates four strings with the filenames for this specific session
    SessionFilenames sSessionFileNames(curlSessionParm.mUrl);

    // Init curl library
    sRc = ((NULL != curlSessionParm.mCurlPtr) ? CURLE_OK : CURLE_FAILED_INIT);

    if(curlSessionParm.mVerbose)
        std::cout << "Prepare to WRITE" << std::endl;

    WRITE_TO_SERVER(sRc, curlSessionParm, sSessionFileNames.mCommandFile, commandParm);

    if(curlSessionParm.mVerbose)
        std::cout << "Prepare to WRITE 2" << std::endl;
    WRITE_TO_SERVER(sRc, curlSessionParm, sSessionFileNames.mCommandFileGo, "1");

    std::size_t sNumPolls = 0;
    do
    {
        sNumPolls++;

        if(CURLE_REMOTE_FILE_NOT_FOUND == sRc)
        {
            // Reset the return code so that READ_FROM_SERVER will execute
            sRc = CURLE_OK;
        }

        std::string sResponseGo;
        READ_FROM_SERVER(sRc, curlSessionParm, sSessionFileNames.mResponseFileGo, sResponseGo);

        if(CURLE_REMOTE_FILE_NOT_FOUND == sRc)
        {
            // TODO: Figure out sub second polling
            sleep(PollingWaitInSeconds);
        }
    } while(CURLE_REMOTE_FILE_NOT_FOUND == sRc && sNumPolls < MaxPollingAttempts);

    if(curlSessionParm.mVerbose)
        std::cout << "Prepare to READ 2" << std::endl;
    READ_FROM_SERVER(sRc, curlSessionParm, sSessionFileNames.mResponseFile, responseParm);

    return (CURLE_OK == sRc) ? success : curl_failure;
}
