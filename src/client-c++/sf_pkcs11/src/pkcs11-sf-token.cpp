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
#include <string.h>

#include "pkcs11-sf-json.h"
#include "pkcs11-sf-object.h"
#include "pkcs11-sf-session.h"
#include "pkcs11-sf-types.h"

#include "pkcs11-sf-token.h"

PKCS11_SfToken::PKCS11_SfToken(sf_client::Session&       clientSessionParm,
                               const std::vector<SfKey>& objectParm)
: mLabel(SfTokenLabel)
, mManufacturerId(SfTokenManufacturer)
, mModel(SfTokenModel)
, mSerialNumber(SfTokenSerialNumber)
, mSessionCount(0)
, mReadWriteSessionCount(0)
, mTotalPublicMemory(CK_UNAVAILABLE_INFORMATION)
, mFreePublicMemory(CK_UNAVAILABLE_INFORMATION)
, mTotalPrivateMemory(CK_UNAVAILABLE_INFORMATION)
, mFreePrivateMemory(CK_UNAVAILABLE_INFORMATION)
, mUtcTime()
, mTokenInitalized(true)
, mWriteProtected(true)
, mSfClientSession(clientSessionParm)
, mObjects(objectParm)
, mSession(*this)
, mSessionInUse(false)
{
    mHardwareVersion.major = TokenHardwareVersionMajor;
    mHardwareVersion.minor = TokenHardwareVersionMinor;
    mFirmwareVersion.major = TokenFirmwareVersionMajor;
    mFirmwareVersion.minor = TokenFirmwareVersionMinor;
}

#define COPY_STRING_TO_TOKEN_INFO(dst, src)                                                        \
    {                                                                                              \
        memset((dst), ' ', sizeof((dst)));                                                         \
        memcpy((dst), (src).c_str(), std::min(sizeof(dst), (src).size()));                         \
    }

bool PKCS11_SfToken::getTokenInfo(CK_TOKEN_INFO_PTR tokenInfoParm) const
{
    if(!tokenInfoParm)
    {
        return false;
    }

    COPY_STRING_TO_TOKEN_INFO(tokenInfoParm->label, mLabel);
    COPY_STRING_TO_TOKEN_INFO(tokenInfoParm->manufacturerID, mManufacturerId);
    COPY_STRING_TO_TOKEN_INFO(tokenInfoParm->model, mModel);
    COPY_STRING_TO_TOKEN_INFO(tokenInfoParm->serialNumber, mSerialNumber);

    // TODO
    tokenInfoParm->flags = 0;
    tokenInfoParm->flags = tokenInfoParm->flags | (mTokenInitalized ? CKF_TOKEN_INITIALIZED : 0);
    tokenInfoParm->flags = tokenInfoParm->flags | (mWriteProtected ? CKF_WRITE_PROTECTED : 0);

    tokenInfoParm->ulMaxSessionCount    = MaxSessionCount;
    tokenInfoParm->ulSessionCount       = mSessionCount;
    tokenInfoParm->ulMaxRwSessionCount  = MaxReadWriteSessionCount;
    tokenInfoParm->ulRwSessionCount     = mReadWriteSessionCount;
    tokenInfoParm->ulMaxPinLen          = MaxPinLen;
    tokenInfoParm->ulMinPinLen          = MinPinLen;
    tokenInfoParm->ulTotalPublicMemory  = mTotalPublicMemory;
    tokenInfoParm->ulFreePublicMemory   = mFreePublicMemory;
    tokenInfoParm->ulTotalPrivateMemory = mTotalPrivateMemory;
    tokenInfoParm->ulFreePrivateMemory  = mFreePrivateMemory;
    tokenInfoParm->hardwareVersion      = mHardwareVersion;
    tokenInfoParm->firmwareVersion      = mFirmwareVersion;

    COPY_STRING_TO_TOKEN_INFO(tokenInfoParm->utcTime, mUtcTime);

    return true;
}

bool PKCS11_SfToken::requestSession()
{
    if(!mSessionInUse)
    {
        mSessionInUse = true;
        return true;
    }
    return false;
}
bool PKCS11_SfToken::releaseSession()
{
    if(mSessionInUse)
    {
        mSessionInUse = false;
        return true;
    }
    return false;
}

PKCS11_SfSession& PKCS11_SfToken::getSession() { return mSession; }