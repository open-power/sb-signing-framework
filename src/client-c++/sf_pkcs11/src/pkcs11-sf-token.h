struct PKCS11_SF_SESSION_CONFIG;

#include <vector>

#include "pkcs11-sf-object.h"
#include "pkcs11-sf-session.h"

#ifndef _PKCS11_SF_TOKEN_H
#define _PKCS11_SF_TOKEN_H

class PKCS11_SfToken
{
  public:
    PKCS11_SfToken(sf_client::Session& clientSessionParm, const std::vector<SfKey>& objectParm);

    enum
    {
        MaxSessionCount          = 1,
        MaxReadWriteSessionCount = 0,
        MaxPinLen                = 0,
        MinPinLen                = 0,
    };

    bool getTokenInfo(CK_TOKEN_INFO_PTR tokenInfoParm) const;

    bool requestSession();
    bool releaseSession();

    PKCS11_SfSession& getSession();

    friend class PKCS11_SfSession;

  protected:
    // PKCS defined values
    std::string mLabel;
    std::string mManufacturerId;
    std::string mModel;
    std::string mSerialNumber;
    // flags:
    CK_ULONG    mSessionCount;
    CK_ULONG    mReadWriteSessionCount;
    CK_ULONG    mTotalPublicMemory;
    CK_ULONG    mFreePublicMemory;
    CK_ULONG    mTotalPrivateMemory;
    CK_ULONG    mFreePrivateMemory;
    CK_VERSION  mHardwareVersion;
    CK_VERSION  mFirmwareVersion;
    std::string mUtcTime;

    // Skipping over unneeded flags
    bool mTokenInitalized;
    bool mWriteProtected;

    // sf_client values
    sf_client::Session&       mSfClientSession;
    const std::vector<SfKey>& mObjects;

    PKCS11_SfSession mSession;
    bool             mSessionInUse;
};

#endif
