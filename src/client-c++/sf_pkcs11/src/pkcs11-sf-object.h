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
#include <stdint.h>
#include <string>
#include <vector>

#include "pkcs11-sf-client.h"

#ifndef _PKCS11_SF_OBJECT_H
#define _PKCS11_SF_OBJECT_H

struct Pkcs11Object
{
    void getAttribute(CK_ATTRIBUTE_TYPE attribute, CK_VOID_PTR dst, CK_ULONG& length) const;

    CK_OBJECT_CLASS mObjectClass;
    bool            mToken;
    bool            mPrivate;
    bool            mModifiable;
    std::string     mLabel;
    bool            mCopyable;
    bool            mDestroyable;
};

struct Pkcs11Storage : public Pkcs11Object
{
    void getAttribute(CK_ATTRIBUTE_TYPE attribute, CK_VOID_PTR dst, CK_ULONG& length) const;

    std::string          mApplication;
    std::vector<uint8_t> mObjectId;
    std::vector<uint8_t> mValue;
};

struct Pkcs11Key : public Pkcs11Storage
{

    void getAttribute(CK_ATTRIBUTE_TYPE attribute, CK_VOID_PTR dst, CK_ULONG& length) const;

    CK_KEY_TYPE                    mKeyType;
    std::vector<uint8_t>           mId;
    CK_DATE                        mStartDate;
    CK_DATE                        mEndDate;
    bool                           mDerive;
    bool                           mLocal;
    CK_MECHANISM_TYPE              mKeyGenMechanism;
    std::vector<CK_MECHANISM_TYPE> mAllowedMechanisms;
};

struct Pkcs11RsaKey : Pkcs11Key
{
    void getAttribute(CK_ATTRIBUTE_TYPE attribute, CK_VOID_PTR dst, CK_ULONG& length) const;

    std::vector<uint8_t> mSubject;
    bool                 mSensitive;
    bool                 mDecrypt;
    bool                 mSign;
    bool                 mSignRecover;
    bool                 mUnwrap;
    bool                 mExtractable;
    bool                 mAlwaysSensitive;
    bool                 mNeverExtractable;
    bool                 mWrapWithTrusted;
    // CKA_UNWRAP_TEMPLATE
    bool                 mAlwaysAuthenticate;
    std::vector<uint8_t> mPublicKeyInfo;

    bool mEncrypt;
    bool mVerify;
    bool mVerifyRecover;
    bool mWrap;
    bool mTrusted;
};

struct Pkcs11PrivateKey : public Pkcs11Key
{
    Pkcs11PrivateKey();

    void getAttribute(CK_ATTRIBUTE_TYPE attribute, CK_VOID_PTR dst, CK_ULONG& length) const;

    std::vector<uint8_t> mSubject;
    bool                 mSensitive;
    bool                 mDecrypt;
    bool                 mSign;
    bool                 mSignRecover;
    bool                 mUnwrap;
    bool                 mExtractable;
    bool                 mAlwaysSensitive;
    bool                 mNeverExtractable;
    bool                 mWrapWithTrusted;
    // CKA_UNWRAP_TEMPLATE
    bool                 mAlwaysAuthenticate;
    std::vector<uint8_t> mPublicKeyInfo;
};

struct Pkcs11PublicKey : public Pkcs11Key
{

    void getAttribute(CK_ATTRIBUTE_TYPE attribute, CK_VOID_PTR dst, CK_ULONG& length) const;

    std::vector<uint8_t> mSubject;
    bool                 mEncrypt;
    bool                 mVerify;
    bool                 mVerifyRecover;
    bool                 mWrap;
    bool                 mTrusted;
    // CKA_WRAP_TEMPLATE
    std::vector<uint8_t> mPublicKeyInfo;
};

struct Pkcs11SecretKey : public Pkcs11Key
{
    void getAttribute(CK_ATTRIBUTE_TYPE attribute, CK_VOID_PTR dst, CK_ULONG& length) const;

    bool                 mSensitive;
    bool                 mEncrypt;
    bool                 mDecrypt;
    bool                 mSign;
    bool                 mVerify;
    bool                 mWrap;
    bool                 mUnwrap;
    bool                 mExtractable;
    bool                 mAlwaysSensitive;
    bool                 mNeverExtractable;
    std::vector<uint8_t> mChecksum;
    bool                 mWrapWithTrusted;
    // CKA_WRAP_TEMPLATE
    // CKA_UNWRAP_TEMPLATE
};

struct SfKey : public Pkcs11RsaKey
{
    SfKey(std::string       projectParm,
          CK_KEY_TYPE       keyTypeParm,
          CK_MECHANISM_TYPE allowedMechanismsParm,
          bool              isPrivateParm);

    void getAttribute(CK_ATTRIBUTE_TYPE attribute, CK_VOID_PTR dst, CK_ULONG& length) const;

    std::vector<uint8_t> mModulus;
    std::vector<uint8_t> mPublicExponent;
    std::string          mProjectName;
    std::string          mPublicKeyPEM;
};

#endif