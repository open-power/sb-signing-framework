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
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdlib.h>
#include <string>
#include <termios.h>
#include <unistd.h>
#include <vector>

#include "sf_utils/sf_utils.h"

static void SignalHandler(int val)
{
    (void)val;
    struct termios term;
    tcgetattr(fileno(stdin), &term);

    term.c_lflag |= ECHO;
    term.c_lflag &= ~ECHONL;

    tcsetattr(fileno(stdin), TCSAFLUSH, &term);
    exit(-2);
}

bool GetPassword(char*          dstParm,
                 const uint64_t dstSizeParm,
                 uint64_t&      bytesWrittenParm,
                 const bool     verboseParm)
{
    bool sResult = false;

    struct sigaction newSa;
    newSa.sa_handler = SignalHandler;
    sigemptyset(&newSa.sa_mask);
    newSa.sa_flags = SA_RESTART;

    struct sigaction oldSigInt;
    struct sigaction oldSigTerm;
    struct sigaction oldSigQuit;

    if(sigaction(SIGINT, &newSa, &oldSigInt) == -1)
    {
        if(verboseParm)
            std::cerr << "ERROR: unable to change SIGINT handler" << std::endl;
        return false;
    }
    if(sigaction(SIGTERM, &newSa, &oldSigTerm) == -1)
    {
        if(verboseParm)
            std::cerr << "ERROR: unable to change SIGTERM handler" << std::endl;
        return false;
    }
    if(sigaction(SIGQUIT, &newSa, &oldSigQuit) == -1)
    {
        if(verboseParm)
            std::cerr << "ERROR: unable to change SIGQUIT handler" << std::endl;
        return false;
    }

    struct termios oldTerm, newTerm;
    tcgetattr(fileno(stdin), &oldTerm);

    newTerm = oldTerm;

    newTerm.c_lflag &= ~ECHO;
    newTerm.c_lflag |= ECHONL;

    tcsetattr(fileno(stdin), TCSAFLUSH, &newTerm);

    printf("Key Passphrase: ");
    fflush(stdout);

    char        sChar             = getchar();
    std::size_t sPassphraseLength = 0;

    while(sChar != '\n' && sChar != '\f' && sChar != '\r')
    {
        if(sPassphraseLength < dstSizeParm)
        {
            dstParm[sPassphraseLength] = sChar;
            sPassphraseLength++;
            sChar = getchar();
        }
        else
        {
            sResult = false;
            break;
        }
    }

    bytesWrittenParm = sPassphraseLength;
    sResult          = bytesWrittenParm > 0;

    if(verboseParm && 0 == bytesWrittenParm)
    {
        std::cout << "Password was length zero" << std::endl;
    }

    tcsetattr(fileno(stdin), TCSANOW, &oldTerm);

    if(sigaction(SIGINT, &oldSigInt, NULL) == -1)
    {
        if(verboseParm)
            std::cerr << "ERROR: unable to change SIGINT handler" << std::endl;
        sResult = false;
    }
    if(sigaction(SIGTERM, &oldSigTerm, NULL) == -1)
    {
        if(verboseParm)
            std::cerr << "ERROR: unable to change SIGTERM handler" << std::endl;
        sResult = false;
    }
    if(sigaction(SIGQUIT, &oldSigQuit, NULL) == -1)
    {
        if(verboseParm)
            std::cerr << "ERROR: unable to change SIGQUIT handler" << std::endl;
        sResult = false;
    }

    return sResult;
}

bool ReadFile(const std::string& filePathParm, std::vector<uint8_t>& dstParm)
{
    std::ifstream sFile;
    if(!filePathParm.empty())
    {
        sFile.open(filePathParm.c_str(), std::ios::in | std::ios::binary);
        if(sFile.is_open())
        {
            // Get the size of the file
            sFile.seekg(0, std::ios::end);
            std::streampos sFileByteSize = sFile.tellg();
            sFile.seekg(0, std::ios::beg);

            dstParm.reserve(sFileByteSize);
            dstParm.assign(sFileByteSize, 0);

            sFile.read((char*)dstParm.data(), sFileByteSize);
            sFile.close();

            return true;
        }
        else
        {
            std::cout << "Failed to open file " << std::endl;
        }
    }
    else
    {
        std::cout << "filename empty" << std::endl;
    }

    return false;
}

bool IsPathWriteable(const std::string& filePathParm)
{
    std::ofstream sFile;
    if(!filePathParm.empty())
    {
        sFile.open(filePathParm.c_str(), std::ios::out | std::ios::app | std::ios::binary);
        if(sFile.is_open())
        {
            sFile.close();
            return true;
        }
    }
    return false;
}

bool WriteFile(const std::string& filePathParm, const std::vector<uint8_t>& srcParm)
{
    std::ofstream sFile;
    if(!filePathParm.empty() && !srcParm.empty())
    {
        sFile.open(filePathParm.c_str(), std::ios::out | std::ios::trunc | std::ios::binary);
        if(sFile.is_open())
        {
            sFile.write((const char*)srcParm.data(), srcParm.size());
            sFile.close();
            return true;
        }
    }
    return false;
}

std::string GetHexStringFromBinary(const std::vector<uint8_t>& binaryParm)
{
    std::stringstream ss;

    for(uint64_t sIdx = 0; sIdx < binaryParm.size(); sIdx++)
    {
        ss.fill('0');
        ss.width(2);
        ss << std::hex << (int)binaryParm[sIdx];
    }

    std::string sString = ss.str();
    // std::cout << "BIN -> HEX: " << binaryParm.size() << " -> " << sString.size() << std::endl;
    return sString;
}

static uint8_t GetNibbleFromHexChar(const char charParm)
{
    switch(charParm)
    {
    case '0':
    case '1':
    case '2':
    case '3':
    case '4':
    case '5':
    case '6':
    case '7':
    case '8':
    case '9':
        return charParm - '0';
    case 'a':
    case 'b':
    case 'c':
    case 'd':
    case 'e':
    case 'f':
        return charParm - 'a' + 0xA;
    case 'A':
    case 'B':
    case 'C':
    case 'D':
    case 'E':
    case 'F':
        return charParm - 'A' + 0xA;
    default:
        return 0;
    }
}

std::vector<uint8_t> GetBinaryFromHexString(const std::string& hexParm)
{
    std::vector<uint8_t> sBinary;
    sBinary.reserve(hexParm.size() / 2);

    for(uint64_t sIdx = 0; !hexParm.empty() && sIdx < hexParm.size() - 1; sIdx += 2)
    {
        uint8_t sUpper = GetNibbleFromHexChar(hexParm[sIdx]);
        uint8_t sLower = GetNibbleFromHexChar(hexParm[sIdx + 1]);
        sBinary.push_back(sUpper << 4 | sLower);
    }
    return sBinary;
}

// Removes any whitespace in the string
void RemoveAllWhitespace(std::string& strParm)
{
    std::string sNewString;
    sNewString.reserve(strParm.size());

    for(std::size_t sIdx = 0; sIdx < strParm.size(); sIdx++)
    {
        char sChar = strParm[sIdx];
        if(!isspace(sChar))
        {
            sNewString.push_back(sChar);
        }
    }

    strParm = sNewString;
}

std::string GetLocalUser()
{
    char sTmpBuffer[1024];

    int rc = getlogin_r(sTmpBuffer, sizeof(sTmpBuffer));
    if(0 == rc)
    {
        return std::string(sTmpBuffer);
    }
    else
    {
        return "UnknownUser";
    }
}

std::string GetLocalHost()
{
    char sTmpBuffer[1024];
    int  rc = gethostname(sTmpBuffer, sizeof(sTmpBuffer));
    if(0 == rc)
    {
        return std::string(sTmpBuffer);
    }
    else
    {
        return "UnknownHost";
    }
}