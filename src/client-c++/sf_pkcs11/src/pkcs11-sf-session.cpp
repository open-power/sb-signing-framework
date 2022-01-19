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
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <string.h>

#include "pkcs11-sf-token.h"

#include "pkcs11-sf-session.h"

PKCS11_SfSession::PKCS11_SfSession(PKCS11_SfToken& tokenParm)
: mToken(tokenParm)
{
}

void PKCS11_SfSession::initSearch(CK_ATTRIBUTE_PTR templateParm, CK_ULONG templateCountParm)
{
    mFindObjectCurrentIndex = 0;
    mSearchTemplate         = templateParm;
    mNumberOfTemplates      = templateCountParm;
}
void PKCS11_SfSession::doSearch(CK_OBJECT_HANDLE_PTR dstObjectsParm,
                                CK_ULONG             dstObjectsSizeParm,
                                CK_ULONG&            objectsWrittenParm)
{
    objectsWrittenParm = 0;

    for(;
        mFindObjectCurrentIndex < mToken.mObjects.size() && objectsWrittenParm < dstObjectsSizeParm;
        mFindObjectCurrentIndex++)
    {
        bool sMatches = true;
        for(CK_ULONG i = 0; i < mNumberOfTemplates; i++)
        {
            uint8_t  sAttribute[100];
            CK_ULONG sAttributeLength = sizeof(sAttribute);

            mToken.mObjects[mFindObjectCurrentIndex].getAttribute(
                mSearchTemplate[i].type, sAttribute, sAttributeLength);

            if(sAttributeLength != mSearchTemplate[i].ulValueLen)
            {
                sMatches = false;
                break;
            }

            if(0 != memcmp(mSearchTemplate[i].pValue, sAttribute, sAttributeLength))
            {
                sMatches = false;
                break;
            }
        }

        if(sMatches)
        {
#ifdef DEBUG
            std::cout << "doSearch MATCH " << std::dec << mFindObjectCurrentIndex << std::endl;
#endif

            dstObjectsParm[objectsWrittenParm] = mFindObjectCurrentIndex;
            objectsWrittenParm++;
        }
    }
}
void PKCS11_SfSession::endSearch()
{
    mSearchTemplate    = NULL_PTR;
    mNumberOfTemplates = 0;
}

const SfKey* PKCS11_SfSession::getKey(CK_OBJECT_HANDLE handleParm)
{
    if(handleParm < mToken.mObjects.size())
    {
        return &mToken.mObjects[handleParm];
    }
    return NULL;
}

void PKCS11_SfSession::initSigning(CK_OBJECT_HANDLE keyParm) { mSignKey = keyParm; }

bool PKCS11_SfSession::doSigning(CK_BYTE_PTR srcParm,
                                 CK_ULONG    srcLengthParm,
                                 CK_BYTE_PTR dstParm,
                                 CK_ULONG&   dstLengthParm)
{

    sf_client::CommandArgsV1 sArgsV1;
    sArgsV1.mProject = mToken.mObjects[mSignKey].mProjectName;

    sArgsV1.mComment = "PKCS11: Do sign"; // @TODO: Use a meaningful comment

    if(srcLengthParm > 64)
    {
        // @TODO More elegantly detect if the OID is included on the source parameter.
        // Strip off the 19 bytes of OID to enable mkimage
        sArgsV1.mPayload = std::vector<uint8_t>(srcParm + 19, srcParm + srcLengthParm);
    }
    else
    {
        // Otherwise shove the sha512 into the vector
        sArgsV1.mPayload = std::vector<uint8_t>(srcParm, srcParm + srcLengthParm);
    }

#ifdef DEBUG
    std::cout << "Source Length " << sArgsV1.mPayload.size() << std::endl;
#endif

    sf_client::CommandResponseV1 sResponseV1;

    sf_client::rc sRc = sf_client::sendCommandV1(mToken.mSfClientSession, sArgsV1, sResponseV1);

#ifdef DEBUG
    std::cout << "Do Sign " << sRc << " " << sResponseV1.mReturnCode << std::endl;

    if(sf_client::success == sRc && 0 != sResponseV1.mReturnCode)
    {
        std::cout << sResponseV1.mStdOut << std::endl;
    }

#endif

    if(sRc == sf_client::success && 0 == sResponseV1.mReturnCode)
    {
        memcpy(dstParm, sResponseV1.mOutput.data(), sResponseV1.mOutput.size());
        dstLengthParm = sResponseV1.mOutput.size();
        return true;
    }
    return false;
}
