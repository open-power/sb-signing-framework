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
struct PKCS11_SF_SESSION_CONFIG;

#include "pkcs11-sf-token.h"

#ifndef _PKCS11_SF_SLOT_H
#define _PKCS11_SF_SLOT_H

class PKCS11_SfSlot
{
  public:
    PKCS11_SfSlot(sf_client::Session& clientSessionParm, const std::vector<SfKey>& objectParm);

    CK_FLAGS getFlags() const;

    void getDescription(CK_UTF8CHAR* dstParm, uint64_t sizeParm) const;

    void getManufacturerId(CK_UTF8CHAR* dstParm, uint64_t sizeParm) const;

    CK_VERSION getHardwareVersion() const;

    CK_VERSION getFirmwareVersion() const;

    PKCS11_SfToken& getToken();

  protected:
    PKCS11_SfToken mToken;
    uint64_t       mId;
    std::string    mManufacturerId;
    std::string    mDescription;
    CK_VERSION     mHardwareVersion;
    CK_VERSION     mFirmwareVersion;
    bool           mTokenPresent;
    bool           mRemovableDevice;
    bool           mIsHardwareSlot;
};

#endif