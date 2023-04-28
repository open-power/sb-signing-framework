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
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <sf_utils/sf_utils.h>
#include <string.h>

#include "pkcs11-sf-json.h"
#include "pkcs11-sf-types.h"

#include "pkcs11-sf-module.h"

PKCS11_SfModule::PKCS11_SfModule()
: mManufacturerID(SfModuleManufacturer)
, mLibraryDescription(SfModuleDescription)
, mSlot(mSfClientSession, mObjects)
{
    mCryptokiVersion.major = ModuleCryptokiVersionMajor;
    mCryptokiVersion.minor = ModuleCryptokiVersionMinor;
    mLibraryVersion.major  = ModuleLibraryVersionMajor;
    mLibraryVersion.minor  = ModuleLibraryVersionMinor;
    // For now, hardcoded to only have one slot.
}

PKCS11_SfModule::~PKCS11_SfModule() {}

PKCS11_SfSlot* PKCS11_SfModule::getSlot(uint64_t slotIdxParm)
{
    if(slotIdxParm < 1)
    {
        return &mSlot;
    }
    return NULL;
}

CK_FLAGS PKCS11_SfModule::getFlags() const
{
    CK_FLAGS sFlags = 0;
    return sFlags;
}

void PKCS11_SfModule::getDescription(CK_UTF8CHAR* dstParm, uint64_t sizeParm) const
{
    memset(dstParm, ' ', sizeParm);
    memcpy(dstParm,
           mLibraryDescription.c_str(),
           std::min<uint64_t>(sizeParm, mLibraryDescription.size()));
}

void PKCS11_SfModule::getManufacturerId(CK_UTF8CHAR* dstParm, uint64_t sizeParm) const
{
    memset(dstParm, ' ', sizeParm);
    memcpy(dstParm, mManufacturerID.c_str(), std::min<uint64_t>(sizeParm, mManufacturerID.size()));
}

CK_VERSION PKCS11_SfModule::getCryptokiVersion() const { return mCryptokiVersion; }

CK_VERSION PKCS11_SfModule::getLibraryVersion() const { return mLibraryVersion; }

bool PKCS11_SfModule::openServerConnection(std::string urlParm,
                                           std::string epwdParm,
                                           std::string pkeyParm)
{

    // if(mServerPassword.empty())
    //    return false;

    mUrl            = urlParm;
    mEpwdPath       = epwdParm;
    mPrivateKeyPath = pkeyParm;

    sf_client::ServerInfoV1 sSfServerV1;
    sSfServerV1.mCurlDebug      = false;
    sSfServerV1.mPasswordPtr    = mServerPassword.c_str();
    sSfServerV1.mPrivateKeyPath = mPrivateKeyPath;
    sSfServerV1.mEpwdPath       = mEpwdPath;
    sSfServerV1.mUrl            = mUrl;
    sSfServerV1.mUseSshAgent    = true;
#ifdef DEBUG
    sSfServerV1.mVerbose = true;
#else
    sSfServerV1.mVerbose = false;
#endif

    sf_client::rc sRc = sf_client::connectToServer(sSfServerV1, mSfClientSession);

#ifdef DEBUG
    std::cout << "Open Connection RC: " << std::hex << sRc << std::dec << std::endl;
    if(sf_client::success != sRc)
    {
        // std::cout << "Password " << mServerPassword << std::endl;
        std::cout << "PrivateKeyPath " << mPrivateKeyPath << std::endl;
        std::cout << "Url " << mUrl << std::endl;
    }
#endif

    return sf_client::success == sRc;
}

bool PKCS11_SfModule::initObjects(const PKCS11_SF_SESSION_CONFIG& configParm)
{

    // For each project name, look up the public key on the server
    for(uint64_t sIdx = 0; sIdx < configParm.mProjects.size(); sIdx++)
    {
        const PKCS11_SF_SESSION_PROJECTS& sProject = configParm.mProjects[sIdx];

        std::cout << "Query server for project: " << sProject.mName << std::endl;

        sf_client::CommandArgsV1 sArgsV1;
        sArgsV1.mProject          = "getpubkey";
        sArgsV1.mComment          = "PKCS11: get pub key to populate library keys";
        sArgsV1.mExtraServerParms = "-format pem -signproject " + sProject.mName;

        sf_client::CommandResponseV1 sResponse;

        sf_client::rc sRc = sf_client::sendCommandV1(mSfClientSession, sArgsV1, sResponse);

        if(sf_client::success != sRc || 0 != sResponse.mReturnCode)
        {
#ifdef DEBUG
            std::cout << "Deleting project " << sProject.mName << ". Unable to get private key."
                      << std::endl;
#endif
        }
        else
        {
#ifdef DEBUG
            std::cout << "Found public key for " << sProject.mName << std::endl;
#endif
            // Extract the modulus and public exponent

            std::vector<uint8_t> sModulus;
            std::vector<uint8_t> sPublicExponent;

            BIO* sMemoryBio = BIO_new(BIO_s_mem());

            // Convert the raw output into a string (BIO expects c_str)
            std::string sPEM(sResponse.mOutput.data(),
                             sResponse.mOutput.data() + sResponse.mOutput.size());
            BIO_puts(sMemoryBio, sPEM.c_str());
            RSA* sPubKey = PEM_read_bio_RSA_PUBKEY(sMemoryBio, NULL, NULL, NULL);

            // FIXME: Add some error handling for NULL pointers
            const BIGNUM* sModulusBN        = RSA_get0_n(sPubKey);
            const BIGNUM* sPublicExponentBN = RSA_get0_e(sPubKey);

            // const BIGNUM* sModulusBN        = sPubKey->n;
            // const BIGNUM* sPublicExponentBN = sPubKey->e;

            sModulus.resize(BN_num_bytes(sModulusBN));
            BN_bn2bin(sModulusBN, sModulus.data());

            sPublicExponent.resize(BN_num_bytes(sPublicExponentBN));
            BN_bn2bin(sPublicExponentBN, sPublicExponent.data());

#ifdef DEBUG
            std::cout << sModulus.size() << " " << sPublicExponent.size() << std::endl;

            for(uint64_t i = 0; i < sModulus.size(); i++)
            {
                std::cout << std::hex << (int)sModulus[i] << std::dec << " ";
            }
            std::cout << std::endl;

            for(uint64_t i = 0; i < sPublicExponent.size(); i++)
            {
                std::cout << std::hex << (int)sPublicExponent[i] << std::dec << " ";
            }
            std::cout << std::endl;
#endif

            if(sPubKey)
                RSA_free(sPubKey);
            if(sMemoryBio)
                BIO_free(sMemoryBio);

            SfKey sPrivateKey(sProject.mName, CKK_RSA, CKM_SHA512_RSA_PKCS, true);
            sPrivateKey.mModulus        = sModulus;
            sPrivateKey.mPublicExponent = sPublicExponent;
            sPrivateKey.mProjectName    = sProject.mName;
            sPrivateKey.mPublicKeyPEM   = sPEM;

            SfKey sPublicKey(sProject.mName, CKK_RSA, CKM_SHA512_RSA_PKCS, false);
            sPublicKey.mModulus        = sModulus;
            sPublicKey.mPublicExponent = sPublicExponent;
            sPublicKey.mProjectName    = sProject.mName;
            sPublicKey.mPublicKeyPEM   = sPEM;

            mObjects.push_back(sPrivateKey);
            mObjects.push_back(sPublicKey);
        }
    }
    std::cout << "Found " << std::dec << mObjects.size() << " objects" << std::endl;
    return !mObjects.empty();
}

bool PKCS11_SfModule::closeServerConnection()
{
    sf_client::disconnect(mSfClientSession);
    return true;
}

bool PKCS11_SfModule::promptPassword()
{
    char sPassword[1024];

    uint64_t sBytesWritten = 0;
    bool     sIsSuccess    = GetPassword(sPassword, sizeof(sPassword), sBytesWritten, false);

    mServerPassword = std::string(sPassword, sPassword + sBytesWritten);

    return sIsSuccess;
}

const std::string& PKCS11_SfModule::getPassword() const { return mServerPassword; }