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
#include "pkcs11-sf-slot.h"

#ifndef _PKCS11_SF_MODULE_H
#define _PKCS11_SF_MODULE_H

struct PKCS11_SF_SESSION_CONFIG;

class PKCS11_SfModule
{
  public:
    PKCS11_SfModule();
    ~PKCS11_SfModule();

    CK_FLAGS getFlags() const;

    void getDescription(CK_UTF8CHAR* dstParm, uint64_t sizeParm) const;

    void getManufacturerId(CK_UTF8CHAR* dstParm, uint64_t sizeParm) const;

    CK_VERSION getCryptokiVersion() const;

    CK_VERSION getLibraryVersion() const;

    bool promptPassword();

    const std::string& getPassword() const;

    bool openServerConnection(std::string urlParm, std::string epwdParm, std::string pkeyParm);
    bool closeServerConnection();

    bool initObjects(const PKCS11_SF_SESSION_CONFIG& configParm);

    enum
    {
        mNumberOfSlots = 1,
    };

    PKCS11_SfSlot* getSlot(uint64_t slotIdxParm);

  protected:
    CK_VERSION  mCryptokiVersion;
    std::string mManufacturerID;
    std::string mLibraryDescription;
    CK_VERSION  mLibraryVersion;

    PKCS11_SfSlot mSlot;

    std::string        mServerPassword;
    sf_client::Session mSfClientSession;
    std::string        mUrl;
    std::string        mEpwdPath;
    std::string        mPrivateKeyPath;

    std::vector<SfKey> mObjects;
};
#endif