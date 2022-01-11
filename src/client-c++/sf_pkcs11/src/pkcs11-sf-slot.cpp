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
#include <string.h>

#include "pkcs11-sf-types.h"

#include "pkcs11-sf-slot.h"

PKCS11_SfSlot::PKCS11_SfSlot(sf_client::Session&       clientSessionParm,
                             const std::vector<SfKey>& objectParm)
: mToken(clientSessionParm, objectParm)
, mId(0)
, mManufacturerId(SfSlotManufacturer)
, mDescription(SfSlotDescription)
, mTokenPresent(true)
, mRemovableDevice(false)
, mIsHardwareSlot(false)
{
    mHardwareVersion.major = SlotHardwareVersionMajor;
    mHardwareVersion.minor = SlotHardwareVersionMinor;
    mFirmwareVersion.major = SlotFirmwareVersionMajor;
    mFirmwareVersion.minor = SlotFirmwareVersionMinor;
}

PKCS11_SfToken& PKCS11_SfSlot::getToken() { return mToken; }

CK_FLAGS PKCS11_SfSlot::getFlags() const
{
    CK_FLAGS sFlags = 0;
    sFlags          = sFlags | (mTokenPresent ? CKF_TOKEN_PRESENT : 0);
    sFlags          = sFlags | (mRemovableDevice ? CKF_REMOVABLE_DEVICE : 0);
    sFlags          = sFlags | (mIsHardwareSlot ? CKF_HW_SLOT : 0);
    return sFlags;
}

void PKCS11_SfSlot::getDescription(CK_UTF8CHAR* dstParm, uint64_t sizeParm) const
{
    memset(dstParm, ' ', sizeParm);
    memcpy(dstParm, mDescription.c_str(), std::min(sizeParm, mDescription.size()));
}

void PKCS11_SfSlot::getManufacturerId(CK_UTF8CHAR* dstParm, uint64_t sizeParm) const
{
    memset(dstParm, ' ', sizeParm);
    memcpy(dstParm, mManufacturerId.c_str(), std::min(sizeParm, mManufacturerId.size()));
}

CK_VERSION PKCS11_SfSlot::getHardwareVersion() const { return mHardwareVersion; }

CK_VERSION PKCS11_SfSlot::getFirmwareVersion() const { return mFirmwareVersion; }
