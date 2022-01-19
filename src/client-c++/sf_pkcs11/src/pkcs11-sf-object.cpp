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
#include <string.h>

#include "pkcs11-sf-object.h"

template <class primitive>
void Attribute_GetPrimitive(const primitive& src, CK_VOID_PTR dst, CK_ULONG& length)
{
    if(NULL_PTR != dst && length >= sizeof(primitive))
    {
        *(primitive*)dst = src;
    }
    length = sizeof(primitive);
}

void Attribute_GetBool(const bool& src, CK_VOID_PTR dst, CK_ULONG& length)
{
    if(NULL_PTR != dst && length >= sizeof(CK_BBOOL))
    {
        *(CK_BBOOL*)dst = src ? CK_TRUE : CK_FALSE;
    }
    length = sizeof(CK_BBOOL);
}

#define Attribute_GetULong Attribute_GetPrimitive<CK_ULONG>

template <class type>
void Attribute_GetVector(const std::vector<type>& src, CK_VOID_PTR dst, CK_ULONG& length)
{
    if(NULL_PTR != dst && length >= src.size())
    {
        memcpy(dst, src.data(), src.size() * sizeof(type));
    }
    length = src.size();
}

#define Attribute_GetBytes Attribute_GetVector<uint8_t>

void Attribute_GetString(const std::string& src, CK_VOID_PTR dst, CK_ULONG& length)
{
    if(NULL_PTR != dst && length >= src.size())
    {
        memcpy(dst, src.data(), src.size());
    }
    length = src.size();
}

void Pkcs11Object::getAttribute(CK_ATTRIBUTE_TYPE attribute,
                                CK_VOID_PTR       dst,
                                CK_ULONG&         length) const
{
    switch(attribute)
    {
    case CKA_CLASS:
        Attribute_GetULong(mObjectClass, dst, length);
        break;
    case CKA_TOKEN:
        Attribute_GetBool(mToken, dst, length);
        break;
    case CKA_PRIVATE:
        Attribute_GetBool(mPrivate, dst, length);
        break;
    case CKA_MODIFIABLE:
        Attribute_GetBool(mModifiable, dst, length);
        break;
    case CKA_LABEL:
        Attribute_GetString(mLabel, dst, length);
        break;
    case CKA_COPYABLE:
        Attribute_GetBool(mCopyable, dst, length);
        break;
    case CKA_DESTROYABLE:
        Attribute_GetBool(mDestroyable, dst, length);
        break;
    default:
        length = CK_UNAVAILABLE_INFORMATION;
        break;
    };
}

void Pkcs11Storage::getAttribute(CK_ATTRIBUTE_TYPE attribute,
                                 CK_VOID_PTR       dst,
                                 CK_ULONG&         length) const
{
    switch(attribute)
    {
    case CKA_APPLICATION:
        Attribute_GetString(mApplication, dst, length);
        break;
    case CKA_OBJECT_ID:
        Attribute_GetBytes(mObjectId, dst, length);
        break;
    case CKA_VALUE:
        Attribute_GetBytes(mValue, dst, length);
        break;
    default:
        Pkcs11Object::getAttribute(attribute, dst, length);
        break;
    };
}

void Pkcs11Key::getAttribute(CK_ATTRIBUTE_TYPE attribute, CK_VOID_PTR dst, CK_ULONG& length) const
{
    switch(attribute)
    {
    case CKA_KEY_TYPE:
        Attribute_GetULong(mKeyType, dst, length);
        break;
    case CKA_ID:
        Attribute_GetBytes(mId, dst, length);
        break;
    case CKA_START_DATE:
    case CKA_END_DATE:
        length = CK_UNAVAILABLE_INFORMATION;
        break;
    case CKA_DERIVE:
        Attribute_GetBool(mDerive, dst, length);
        break;
    case CKA_LOCAL:
        Attribute_GetBool(mLocal, dst, length);
        break;
    case CKA_MECHANISM_TYPE:
        Attribute_GetULong(mKeyGenMechanism, dst, length);
        break;
    case CKA_ALLOWED_MECHANISMS:
        Attribute_GetVector<CK_MECHANISM_TYPE>(mAllowedMechanisms, dst, length);
        break;
    default:
        Pkcs11Storage::getAttribute(attribute, dst, length);
        break;
    };
}

Pkcs11PrivateKey::Pkcs11PrivateKey()
: Pkcs11Key()
{
    mObjectClass = CKO_PRIVATE_KEY;
}
void Pkcs11PrivateKey::getAttribute(CK_ATTRIBUTE_TYPE attribute,
                                    CK_VOID_PTR       dst,
                                    CK_ULONG&         length) const
{
    switch(attribute)
    {
    case CKA_SUBJECT:
        Attribute_GetBytes(mSubject, dst, length);
        break;
    case CKA_SENSITIVE:
        Attribute_GetBool(mSensitive, dst, length);
        break;
    case CKA_DECRYPT:
        Attribute_GetBool(mDecrypt, dst, length);
        break;
    case CKA_SIGN:
        Attribute_GetBool(mSign, dst, length);
        break;
    case CKA_SIGN_RECOVER:
        Attribute_GetBool(mSignRecover, dst, length);
        break;
    case CKA_UNWRAP:
        Attribute_GetBool(mUnwrap, dst, length);
        break;
    case CKA_EXTRACTABLE:
        Attribute_GetBool(mExtractable, dst, length);
        break;
    case CKA_ALWAYS_SENSITIVE:
        Attribute_GetBool(mAlwaysSensitive, dst, length);
        break;
    case CKA_NEVER_EXTRACTABLE:
        Attribute_GetBool(mNeverExtractable, dst, length);
        break;
    case CKA_WRAP_WITH_TRUSTED:
        Attribute_GetBool(mWrapWithTrusted, dst, length);
        break;
    case CKA_UNWRAP_TEMPLATE:
        length = CK_UNAVAILABLE_INFORMATION;
        break;
    case CKA_ALWAYS_AUTHENTICATE:
        Attribute_GetBool(mAlwaysAuthenticate, dst, length);
        break;
    case CKA_PUBLIC_KEY_INFO:
        Attribute_GetBytes(mPublicKeyInfo, dst, length);
        break;

    default:
        Pkcs11Key::getAttribute(attribute, dst, length);
        break;
    }
}

void Pkcs11PublicKey::getAttribute(CK_ATTRIBUTE_TYPE attribute,
                                   CK_VOID_PTR       dst,
                                   CK_ULONG&         length) const
{
    switch(attribute)
    {
    case CKA_SUBJECT:
        Attribute_GetBytes(mSubject, dst, length);
        break;
    case CKA_ENCRYPT:
        Attribute_GetBool(mEncrypt, dst, length);
        break;
    case CKA_VERIFY:
        Attribute_GetBool(mVerify, dst, length);
        break;
    case CKA_VERIFY_RECOVER:
        Attribute_GetBool(mVerifyRecover, dst, length);
        break;
    case CKA_WRAP:
        Attribute_GetBool(mWrap, dst, length);
        break;
    case CKA_TRUSTED:
        Attribute_GetBool(mTrusted, dst, length);
        break;
    case CKA_WRAP_TEMPLATE:
        length = CK_UNAVAILABLE_INFORMATION;
        break;
    case CKA_PUBLIC_KEY_INFO:
        Attribute_GetBytes(mPublicKeyInfo, dst, length);
        break;

    default:
        Pkcs11Key::getAttribute(attribute, dst, length);
        break;
    }
}

void Pkcs11RsaKey::getAttribute(CK_ATTRIBUTE_TYPE attribute,
                                CK_VOID_PTR       dst,
                                CK_ULONG&         length) const
{
    switch(attribute)
    {
    case CKA_SUBJECT:
        Attribute_GetBytes(mSubject, dst, length);
        break;
    case CKA_SENSITIVE:
        Attribute_GetBool(mSensitive, dst, length);
        break;
    case CKA_DECRYPT:
        Attribute_GetBool(mDecrypt, dst, length);
        break;
    case CKA_SIGN:
        Attribute_GetBool(mSign, dst, length);
        break;
    case CKA_SIGN_RECOVER:
        Attribute_GetBool(mSignRecover, dst, length);
        break;
    case CKA_UNWRAP:
        Attribute_GetBool(mUnwrap, dst, length);
        break;
    case CKA_EXTRACTABLE:
        Attribute_GetBool(mExtractable, dst, length);
        break;
    case CKA_ALWAYS_SENSITIVE:
        Attribute_GetBool(mAlwaysSensitive, dst, length);
        break;
    case CKA_NEVER_EXTRACTABLE:
        Attribute_GetBool(mNeverExtractable, dst, length);
        break;
    case CKA_WRAP_WITH_TRUSTED:
        Attribute_GetBool(mWrapWithTrusted, dst, length);
        break;
    case CKA_UNWRAP_TEMPLATE:
        length = CK_UNAVAILABLE_INFORMATION;
        break;
    case CKA_ALWAYS_AUTHENTICATE:
        Attribute_GetBool(mAlwaysAuthenticate, dst, length);
        break;
    case CKA_PUBLIC_KEY_INFO:
        Attribute_GetBytes(mPublicKeyInfo, dst, length);
        break;
    case CKA_ENCRYPT:
        Attribute_GetBool(mEncrypt, dst, length);
        break;
    case CKA_VERIFY:
        Attribute_GetBool(mVerify, dst, length);
        break;
    case CKA_VERIFY_RECOVER:
        Attribute_GetBool(mVerifyRecover, dst, length);
        break;
    case CKA_WRAP:
        Attribute_GetBool(mWrap, dst, length);
        break;
    case CKA_TRUSTED:
        Attribute_GetBool(mTrusted, dst, length);
        break;
    case CKA_WRAP_TEMPLATE:
        length = CK_UNAVAILABLE_INFORMATION;
        break;

    default:
        Pkcs11Key::getAttribute(attribute, dst, length);
        break;
    }
}

void Pkcs11SecretKey::getAttribute(CK_ATTRIBUTE_TYPE attribute,
                                   CK_VOID_PTR       dst,
                                   CK_ULONG&         length) const
{
    switch(attribute)
    {

    case CKA_SENSITIVE:
        Attribute_GetBool(mSensitive, dst, length);
        break;
    case CKA_ENCRYPT:
        Attribute_GetBool(mEncrypt, dst, length);
        break;
    case CKA_DECRYPT:
        Attribute_GetBool(mDecrypt, dst, length);
        break;
    case CKA_SIGN:
        Attribute_GetBool(mSign, dst, length);
        break;
    case CKA_VERIFY:
        Attribute_GetBool(mVerify, dst, length);
        break;
    case CKA_WRAP:
        Attribute_GetBool(mWrap, dst, length);
        break;
    case CKA_UNWRAP:
        Attribute_GetBool(mUnwrap, dst, length);
        break;
    case CKA_EXTRACTABLE:
        Attribute_GetBool(mExtractable, dst, length);
        break;
    case CKA_ALWAYS_SENSITIVE:
        Attribute_GetBool(mAlwaysSensitive, dst, length);
        break;
    case CKA_NEVER_EXTRACTABLE:
        Attribute_GetBool(mNeverExtractable, dst, length);
        break;
    case CKA_CHECK_VALUE:
        Attribute_GetBytes(mChecksum, dst, length);
        break;
    case CKA_WRAP_WITH_TRUSTED:
        Attribute_GetBool(mWrapWithTrusted, dst, length);
        break;
    case CKA_UNWRAP_TEMPLATE:
    case CKA_WRAP_TEMPLATE:
        length = CK_UNAVAILABLE_INFORMATION;
        break;
    default:
        Pkcs11Key::getAttribute(attribute, dst, length);
        break;
    }
}

SfKey::SfKey(std::string       projectParm,
             CK_KEY_TYPE       keyTypeParm,
             CK_MECHANISM_TYPE allowedMechanismParm,
             bool              isPrivateParm)
: mProjectName(projectParm)
{
    if(isPrivateParm)
        mObjectClass = CKO_PRIVATE_KEY;
    else
    {
        mObjectClass = CKO_PUBLIC_KEY;
    }

    // Object
    mPrivate     = true;
    mModifiable  = false;
    mLabel       = projectParm;
    mCopyable    = false;
    mDestroyable = false;

    // Storage
    mApplication.clear();
    mObjectId.clear();
    mValue.clear();

    // Key
    mKeyType = keyTypeParm;
    mId = std::vector<uint8_t>((uint8_t*)mLabel.data(), (uint8_t*)mLabel.data() + mLabel.size());
    memset(&mStartDate, 0, sizeof(mStartDate));
    memset(&mEndDate, 0, sizeof(mEndDate));
    mDerive = false;
    mLocal  = false;
    mAllowedMechanisms.push_back(allowedMechanismParm);

    // Private Key
    mSubject.clear();
    mSensitive          = true;
    mDecrypt            = false;
    mSign               = true;
    mSignRecover        = false;
    mUnwrap             = false;
    mExtractable        = false;
    mAlwaysSensitive    = true;
    mNeverExtractable   = true;
    mWrapWithTrusted    = false;
    mAlwaysAuthenticate = false;
    mPublicKeyInfo.clear();

    mEncrypt       = false;
    mVerify        = false;
    mVerifyRecover = false;
    mWrap          = false;
    mTrusted       = false;

    mPublicExponent.clear();
    mModulus.clear();
}

void SfKey::getAttribute(CK_ATTRIBUTE_TYPE attribute, CK_VOID_PTR dst, CK_ULONG& length) const
{
    switch(attribute)
    {
    case CKA_MODULUS:
        Attribute_GetBytes(mModulus, dst, length);
        break;
    case CKA_PUBLIC_EXPONENT:
        Attribute_GetBytes(mPublicExponent, dst, length);
        break;
    default:
        Pkcs11RsaKey::getAttribute(attribute, dst, length);
        break;
    }
}
