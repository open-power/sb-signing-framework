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
#include <curl/curl.h>
#include <fstream>
#include <iostream>
#include <json-c/json.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <sf_client/sf_client.h>
#include <sf_utils/sf_utils.h>
#include <string.h>
#include <string>
#include <termios.h>
#include <vector>

#include "pkcs11-sf-json.h"
#include "pkcs11-sf-module.h"
#include "pkcs11-sf-types.h"

#include "pkcs11-sf-client.h"

#ifdef DEBUG
#undef DEBUG
#define DEBUG(string) std::cout << string << std::endl;
#else
#define DEBUG(string)
#endif

PKCS11_SfModule* SfModule = NULL;

// API defined at:
// http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html

CK_FUNCTION_LIST PKCS11_SF_Client_Functions = {{CryptokiVersionMajor, CryptokiVersionMinor},
                                               &C_Initialize,
                                               &C_Finalize,
                                               &C_GetInfo,
                                               &C_GetFunctionList,
                                               &C_GetSlotList,
                                               &C_GetSlotInfo,
                                               &C_GetTokenInfo,
                                               &C_GetMechanismList,
                                               &C_GetMechanismInfo,
                                               &C_InitToken,
                                               &C_InitPIN,
                                               &C_SetPIN,
                                               &C_OpenSession,
                                               &C_CloseSession,
                                               &C_CloseAllSessions,
                                               &C_GetSessionInfo,
                                               &C_GetOperationState,
                                               &C_SetOperationState,
                                               &C_Login,
                                               &C_Logout,
                                               &C_CreateObject,
                                               &C_CopyObject,
                                               &C_DestroyObject,
                                               &C_GetObjectSize,
                                               &C_GetAttributeValue,
                                               &C_SetAttributeValue,
                                               &C_FindObjectsInit,
                                               &C_FindObjects,
                                               &C_FindObjectsFinal,
                                               &C_EncryptInit,
                                               &C_Encrypt,
                                               &C_EncryptUpdate,
                                               &C_EncryptFinal,
                                               &C_DecryptInit,
                                               &C_Decrypt,
                                               &C_DecryptUpdate,
                                               &C_DecryptFinal,
                                               &C_DigestInit,
                                               &C_Digest,
                                               &C_DigestUpdate,
                                               &C_DigestKey,
                                               &C_DigestFinal,
                                               &C_SignInit,
                                               &C_Sign,
                                               &C_SignUpdate,
                                               &C_SignFinal,
                                               &C_SignRecoverInit,
                                               &C_SignRecover,
                                               &C_VerifyInit,
                                               &C_Verify,
                                               &C_VerifyUpdate,
                                               &C_VerifyFinal,
                                               &C_VerifyRecoverInit,
                                               &C_VerifyRecover,
                                               &C_DigestEncryptUpdate,
                                               &C_DecryptDigestUpdate,
                                               &C_SignEncryptUpdate,
                                               &C_DecryptVerifyUpdate,
                                               &C_GenerateKey,
                                               &C_GenerateKeyPair,
                                               &C_WrapKey,
                                               &C_UnwrapKey,
                                               &C_DeriveKey,
                                               &C_SeedRandom,
                                               &C_GenerateRandom,
                                               &C_GetFunctionStatus,
                                               &C_CancelFunction,
                                               &C_WaitForSlotEvent};

// C_Initialize initializes the Cryptoki library.  pInitArgs either has the value NULL_PTR or points
// to a CK_C_INITIALIZE_ARGS structure containing information on how the library should deal with
// multi-threaded access.
// Return values: CKR_ARGUMENTS_BAD, CKR_CANT_LOCK,
// CKR_CRYPTOKI_ALREADY_INITIALIZED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY,
// CKR_NEED_TO_CREATE_THREADS, CKR_OK.
CK_DECLARE_FUNCTION(CK_RV, C_Initialize)(CK_VOID_PTR pInitArgs)
{
    DEBUG("CINIT START");
    if(pInitArgs)
    {
        DEBUG("CINIT START-1");
        // Received data about locking
        // Contains:
        // CreateMutex, DestroyMutex, LockMutex, UnlockMutex, flags, and pReserved
        CK_C_INITIALIZE_ARGS_PTR sArgsPtr = (CK_C_INITIALIZE_ARGS_PTR)(pInitArgs);

        // pReserved is required to be NULL, if not the spec requires CKR_ARG_BAD to be returned
        if(NULL_PTR != sArgsPtr->pReserved)
        {
            DEBUG("CINIT START-2");
            return CKR_ARGUMENTS_BAD;
        }

        // For simplicity, this library will not support multiple threads. So it doens't care about
        // most of these parms.

        // Application supports native OS locking/thread mechanisms
        if(CKF_OS_LOCKING_OK & sArgsPtr->flags)
        {
            DEBUG("CINIT START-3");
            // Multithreading not supported
            // return CKR_CANT_LOCK;
        }
        else
        {
            // Application is doing multi-threading work and the library must use these functions
            // for mutex-handling
            if(NULL_PTR != sArgsPtr->CreateMutex && NULL_PTR != sArgsPtr->DestroyMutex
               && NULL_PTR != sArgsPtr->LockMutex && NULL_PTR != sArgsPtr->UnlockMutex)
            {
                DEBUG("CINIT START-4");
                return CKR_CANT_LOCK;
            }
            else if(NULL_PTR != sArgsPtr->CreateMutex || NULL_PTR != sArgsPtr->DestroyMutex
                    || NULL_PTR != sArgsPtr->LockMutex || NULL_PTR != sArgsPtr->UnlockMutex)
            {
                DEBUG("CINIT START-5");
                // Either all pointers should be valid or none should be valid. Return an error
                // since only some are valid.
                return CKR_ARGUMENTS_BAD;
            }
            else
            {
                DEBUG("CINIT START-6");
                // Application is not accessing library from multiple threads. Equivalent to
                // pInitArgs being set to NULL_PTR.
            }
        }
    }
    else
    {
        // Did not receive data about locking. Application is not accessing library from multiple
        // threads. No additional checking required.
    }
    DEBUG("CINIT START-7");

    PKCS11_SF_SESSION_CONFIG sConfig;
    // TODO: pull from environment variable

    const char* sJsonPath = getenv("SF_PKCS11_CONFIG");
    if(!sJsonPath)
    {
        std::cout << "SF_PKCS11_CONFIG environment variable not defined" << std::endl;
        return CKR_GENERAL_ERROR;
    }

    bool sJsonSuccess = ParseJsonConfig(sJsonPath, sConfig);
    if(!sJsonSuccess)
        return CKR_GENERAL_ERROR;
    std::cout << sJsonSuccess << std::endl;

    SfModule = new PKCS11_SfModule();
    if(!SfModule)
    {
        return CKR_HOST_MEMORY;
    }

    // DEBUG("ATTEMPT GET PASSWORD:");
    // bool sPasswordSuccess = SfModule->promptPassword();
    // if(!sPasswordSuccess)
    //{
    //    std::cout << "Error setting password" << std::endl;
    //    return CKR_GENERAL_ERROR;
    //}

    DEBUG("ATTEMPT OPEN CONNECTION:");
    bool sCurlSuccess = SfModule->openServerConnection(
        sConfig.mUrl, sConfig.mEpwdPath, sConfig.mPrivateKeyPath);
    if(!sCurlSuccess)
    {
        std::cout << "Error opening connection" << std::endl;
        return CKR_GENERAL_ERROR;
    }

    DEBUG("ATTEMPT INIT OBJECTS:");
    bool sInitSuccess = SfModule->initObjects(sConfig);
    if(!sInitSuccess)
    {
        std::cout << "Error init'ing objects" << std::endl;
        return CKR_GENERAL_ERROR;
    }

    DEBUG("INIT END");

    return CKR_OK;
}

/* C_Finalize indicates that an application is done with the
 * Cryptoki library.
 */
// Return values: CKR_ARGUMENTS_BAD, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_FUNCTION_FAILED,
// CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK.
CK_DECLARE_FUNCTION(CK_RV, C_Finalize)(CK_VOID_PTR pReserved)
{
    DEBUG("C_FINALIZE START");
    (void)pReserved;
    if(SfModule)
    {
        SfModule->closeServerConnection();
        delete SfModule;
        SfModule = NULL;
    }
    return CKR_OK;
}

/* C_GetInfo returns general information about Cryptoki. */
// Return values: CKR_ARGUMENTS_BAD, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_FUNCTION_FAILED,
// CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK.
CK_DECLARE_FUNCTION(CK_RV, C_GetInfo)(CK_INFO_PTR pInfo)
{
    DEBUG("C_GETINFO START")
    if(!SfModule)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if(NULL_PTR == pInfo)
    {
        return CKR_ARGUMENTS_BAD;
    }

    // pkcs11t.h:
    // typedef struct CK_INFO {
    //   CK_VERSION    cryptokiVersion;     /* Cryptoki interface ver */
    //   CK_UTF8CHAR   manufacturerID[32];  /* blank padded */
    //   CK_FLAGS      flags;               /* must be zero */
    //   CK_UTF8CHAR   libraryDescription[32];  /* blank padded */
    //   CK_VERSION    libraryVersion;          /* version of library */
    // } CK_INFO;

    pInfo->cryptokiVersion = SfModule->getCryptokiVersion();
    SfModule->getManufacturerId(pInfo->manufacturerID, sizeof(pInfo->manufacturerID));
    pInfo->flags = SfModule->getFlags();
    SfModule->getDescription(pInfo->libraryDescription, sizeof(pInfo->libraryDescription));
    pInfo->libraryVersion = SfModule->getLibraryVersion();

    return CKR_OK;
}

/* C_GetFunctionList returns the function list. */
// Return values: CKR_ARGUMENTS_BAD, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY,
// CKR_OK.
CK_DECLARE_FUNCTION(CK_RV, C_GetFunctionList)
(CK_FUNCTION_LIST_PTR_PTR ppFunctionList /* receives pointer to function list */)
{
    DEBUG("C_GETFUNCTIONLIST START")
    if(!ppFunctionList)
    {
        return CKR_ARGUMENTS_BAD;
    }

    *ppFunctionList = &PKCS11_SF_Client_Functions;
    DEBUG("C_GETFUNCTIONLIST FINISH")
    return CKR_OK;
}

/* Slot and token management */

/* C_GetSlotList obtains a list of slots in the system. */
// Return values: CKR_ARGUMENTS_BAD, CKR_BUFFER_TOO_SMALL, CKR_CRYPTOKI_NOT_INITIALIZED,
// CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK.
CK_DECLARE_FUNCTION(CK_RV, C_GetSlotList)
(CK_BBOOL       tokenPresent, /* only slots with tokens */
 CK_SLOT_ID_PTR pSlotList,    /* receives array of slot IDs */
 CK_ULONG_PTR   pulCount      /* receives number of slots */
)
{
    DEBUG("C_GetSlotList START");
    if(!SfModule)

    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    if(NULL_PTR == pulCount)
    {
        return CKR_ARGUMENTS_BAD;
    }

    if(NULL_PTR == pSlotList)
    {
        // Application is requesting the number of slots in the library
        *pulCount = SfModule->mNumberOfSlots;
    }
    else
    {
        if(*pulCount < SfModule->mNumberOfSlots)
        {
            return CKR_BUFFER_TOO_SMALL;
        }

        // Slots are always populated with a token, so tokenPresent will not change the output
        (void)tokenPresent;

        // Hardcoded to only have one slot
        pSlotList[0] = 0; // Hardcode to slot index 0
        *pulCount    = 1;
    }
    DEBUG("C_GetSlotList FINISH");
    return CKR_OK;
}

/* C_GetSlotInfo obtains information about a particular slot in
 * the system.
 */
// Return values: CKR_ARGUMENTS_BAD, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR,
// CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_SLOT_ID_INVALID.
CK_DECLARE_FUNCTION(CK_RV, C_GetSlotInfo)
(CK_SLOT_ID       slotID, /* the ID of the slot */
 CK_SLOT_INFO_PTR pInfo   /* receives the slot information */
)
{
    DEBUG("C_GetSlotInfo START");
    if(!SfModule)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if(NULL_PTR == pInfo)
    {
        return CKR_ARGUMENTS_BAD;
    }

    PKCS11_SfSlot* sSlotPtr = SfModule->getSlot(slotID);
    if(!sSlotPtr)
    {
        return CKR_ARGUMENTS_BAD;
    }

    // pkcs11t.h:
    // typedef struct CK_SLOT_INFO {
    //  CK_UTF8CHAR   slotDescription[64];  /* blank padded */
    //  CK_UTF8CHAR   manufacturerID[32];   /* blank padded */
    //  CK_FLAGS      flags;
    //
    //  CK_VERSION    hardwareVersion;  /* version of hardware */
    //  CK_VERSION    firmwareVersion;  /* version of firmware */
    //} CK_SLOT_INFO;

    sSlotPtr->getDescription(pInfo->slotDescription, sizeof(pInfo->slotDescription));
    sSlotPtr->getManufacturerId(pInfo->manufacturerID, sizeof(pInfo->manufacturerID));
    pInfo->flags           = sSlotPtr->getFlags();
    pInfo->hardwareVersion = sSlotPtr->getHardwareVersion();
    pInfo->firmwareVersion = sSlotPtr->getFirmwareVersion();

    return CKR_OK;
}

/* C_GetTokenInfo obtains information about a particular token
 * in the system.
 */
// Return values: CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY,
// CKR_DEVICE_REMOVED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK,
// CKR_SLOT_ID_INVALID, CKR_TOKEN_NOT_PRESENT, CKR_TOKEN_NOT_RECOGNIZED, CKR_ARGUMENTS_BAD.
CK_DECLARE_FUNCTION(CK_RV, C_GetTokenInfo)

(CK_SLOT_ID        slotID, /* ID of the token's slot */
 CK_TOKEN_INFO_PTR pInfo   /* receives the token information */
)
{
    DEBUG("C_GetTokenInfo START");
    if(!SfModule)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if(NULL_PTR == pInfo)
    {
        return CKR_ARGUMENTS_BAD;
    }

    PKCS11_SfSlot* sSlotPtr = SfModule->getSlot(slotID);
    if(!sSlotPtr)
    {
        return CKR_ARGUMENTS_BAD;
    }

    PKCS11_SfToken& sToken = sSlotPtr->getToken();

    bool sIsSuccess = sToken.getTokenInfo(pInfo);
    if(!sIsSuccess)
    {
        return CKR_GENERAL_ERROR;
    }
    return CKR_OK;
}

/* C_GetMechanismList obtains a list of mechanism types
 * supported by a token.
 */
CK_DECLARE_FUNCTION(CK_RV, C_GetMechanismList)

(CK_SLOT_ID            slotID,         /* ID of token's slot */
 CK_MECHANISM_TYPE_PTR pMechanismList, /* gets mech. array */
 CK_ULONG_PTR          pulCount        /* gets # of mechs. */
)
{
    (void)slotID;
    DEBUG("C_GetMechanismList");
    if(!SfModule)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if(NULL_PTR == pulCount)
    {
        return CKR_ARGUMENTS_BAD;
    }

    // TODO
    if(NULL_PTR == pMechanismList)
    {
        *pulCount = 1;
    }
    else
    {
        if(1 > *pulCount)
            return CKR_BUFFER_TOO_SMALL;

        pMechanismList[0] = CKM_SHA512_RSA_PKCS;
    }

    return CKR_OK;
}

/* C_GetMechanismInfo obtains information about a particular
 * mechanism possibly supported by a token.
 */
CK_DECLARE_FUNCTION(CK_RV, C_GetMechanismInfo)

(CK_SLOT_ID            slotID, /* ID of the token's slot */
 CK_MECHANISM_TYPE     type,   /* type of mechanism */
 CK_MECHANISM_INFO_PTR pInfo   /* receives mechanism info */
)
{
    DEBUG("C_GetMechanismInfo");
    (void)slotID;
    (void)type;
    (void)pInfo;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_InitToken initializes a token. */
CK_DECLARE_FUNCTION(CK_RV, C_InitToken)

(CK_SLOT_ID      slotID,   /* ID of the token's slot */
 CK_UTF8CHAR_PTR pPin,     /* the SO's initial PIN */
 CK_ULONG        ulPinLen, /* length in bytes of the PIN */
 CK_UTF8CHAR_PTR pLabel    /* 32-byte token label (blank padded) */
)
{
    DEBUG("C_InitToken");
    (void)slotID;
    (void)pPin;
    (void)ulPinLen;
    (void)pLabel;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_InitPIN initializes the normal user's PIN. */
CK_DECLARE_FUNCTION(CK_RV, C_InitPIN)

(CK_SESSION_HANDLE hSession, /* the session's handle */
 CK_UTF8CHAR_PTR   pPin,     /* the normal user's PIN */
 CK_ULONG          ulPinLen  /* length in bytes of the PIN */
)
{
    DEBUG("C_InitPIN");
    (void)hSession;
    (void)pPin;
    (void)ulPinLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_SetPIN modifies the PIN of the user who is logged in. */
CK_DECLARE_FUNCTION(CK_RV, C_SetPIN)

(CK_SESSION_HANDLE hSession, /* the session's handle */
 CK_UTF8CHAR_PTR   pOldPin,  /* the old PIN */
 CK_ULONG          ulOldLen, /* length of the old PIN */
 CK_UTF8CHAR_PTR   pNewPin,  /* the new PIN */
 CK_ULONG          ulNewLen  /* length of the new PIN */
)
{
    DEBUG("C_SetPIN");
    (void)hSession;
    (void)pOldPin;
    (void)ulOldLen;
    (void)pNewPin;
    (void)ulNewLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/* Session management */

/* C_OpenSession opens a session between an application and a
 * token.
 */
// Return values: CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY,
// CKR_DEVICE_REMOVED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK,
// CKR_SESSION_COUNT, CKR_SESSION_PARALLEL_NOT_SUPPORTED, CKR_SESSION_READ_WRITE_SO_EXISTS,
// CKR_SLOT_ID_INVALID, CKR_TOKEN_NOT_PRESENT, CKR_TOKEN_NOT_RECOGNIZED, CKR_TOKEN_WRITE_PROTECTED,
// CKR_ARGUMENTS_BAD.
bool sessionexists = false;
CK_DECLARE_FUNCTION(CK_RV, C_OpenSession)

(CK_SLOT_ID            slotID,       /* the slot's ID */
 CK_FLAGS              flags,        /* from CK_SESSION_INFO */
 CK_VOID_PTR           pApplication, /* passed to callback */
 CK_NOTIFY             Notify,       /* callback function */
 CK_SESSION_HANDLE_PTR phSession     /* gets session handle */
)
{
    DEBUG("C_OpenSession " << std::hex << flags << std::dec << " " << slotID);

    (void)flags;
    (void)pApplication;
    (void)Notify;

    // Sessions are opened on tokens. For sf_client, there is one token per slot, we can reuse the
    // slotID as the session handle.

    // Deviation from PKCS11: Authentication with user input is for setting up the initial sftp
    // connection. This needs to be established BEFORE PKCS11 would call C_Login since the public
    // key parameters need to be pulled from the signing server to populate the modulus and public
    // exponent of the private key (openssl checks for these).
    // Thus we must authenticate on the session opening, not when we log into the adapter.

    if(!SfModule)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    PKCS11_SfSlot* sSlotPtr = SfModule->getSlot(slotID);
    if(!sSlotPtr)
    {
        return CKR_ARGUMENTS_BAD;
    }

    if(sessionexists)
    {
        *phSession = slotID;
        return CKR_OK;
    }

    bool sIsSuccess = true;

    if(!sIsSuccess)
    {
        return CKR_GENERAL_ERROR;
    }

    PKCS11_SfToken& sToken = sSlotPtr->getToken();

    sIsSuccess = sToken.requestSession();
    if(!sIsSuccess)
    {
        return CKR_SESSION_COUNT;
    }

    *phSession    = slotID;
    sessionexists = true;

    return CKR_OK;
}

/* C_CloseSession closes a session between an application and a
 * token.
 */
// Return values: CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY,
// CKR_DEVICE_REMOVED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK,
// CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID.
CK_DECLARE_FUNCTION(CK_RV, C_CloseSession)

(CK_SESSION_HANDLE hSession /* the session's handle */
)
{
    DEBUG("C_CloseSession");
    if(!SfModule)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    // Session ID == Slot Number
    PKCS11_SfSlot* sSlotPtr = SfModule->getSlot(hSession);
    if(!sSlotPtr)
    {
        return CKR_ARGUMENTS_BAD;
    }

    PKCS11_SfToken& sToken = sSlotPtr->getToken();

    // PKCS11_SfSession& sSession = sToken.getSession();

    // sSession.closeConnection();
    sToken.releaseSession();
    sessionexists = false;

    return CKR_OK;
}

/* C_CloseAllSessions closes all sessions with a token. */
CK_DECLARE_FUNCTION(CK_RV, C_CloseAllSessions)

(CK_SLOT_ID slotID /* the token's slot */
)
{
    DEBUG("C_CloseAllSessions");
    (void)slotID;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_GetSessionInfo obtains information about the session. */
CK_DECLARE_FUNCTION(CK_RV, C_GetSessionInfo)

(CK_SESSION_HANDLE   hSession, /* the session's handle */
 CK_SESSION_INFO_PTR pInfo     /* receives session info */
)
{
    DEBUG("C_GetSessionInfo");
    (void)hSession;
    (void)pInfo;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_GetOperationState obtains the state of the cryptographic operation
 * in a session.
 */
CK_DECLARE_FUNCTION(CK_RV, C_GetOperationState)

(CK_SESSION_HANDLE hSession,            /* session's handle */
 CK_BYTE_PTR       pOperationState,     /* gets state */
 CK_ULONG_PTR      pulOperationStateLen /* gets state length */
)
{
    DEBUG("C_GetOperationState");
    (void)hSession;
    (void)pOperationState;
    (void)pulOperationStateLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_SetOperationState restores the state of the cryptographic
 * operation in a session.
 */
CK_DECLARE_FUNCTION(CK_RV, C_SetOperationState)

(CK_SESSION_HANDLE hSession,            /* session's handle */
 CK_BYTE_PTR       pOperationState,     /* holds state */
 CK_ULONG          ulOperationStateLen, /* holds state length */
 CK_OBJECT_HANDLE  hEncryptionKey,      /* en/decryption key */
 CK_OBJECT_HANDLE  hAuthenticationKey   /* sign/verify key */
)
{
    DEBUG("C_SetOperationState");
    (void)hSession;
    (void)pOperationState;
    (void)ulOperationStateLen;
    (void)hEncryptionKey;
    (void)hAuthenticationKey;

    return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_Login logs a user into a token. */
CK_DECLARE_FUNCTION(CK_RV, C_Login)

(CK_SESSION_HANDLE hSession, /* the session's handle */
 CK_USER_TYPE      userType, /* the user type */
 CK_UTF8CHAR_PTR   pPin,     /* the user's PIN */
 CK_ULONG          ulPinLen  /* the length of the PIN */
)
{
    DEBUG("C_Login");
    (void)hSession;
    (void)userType;
    (void)pPin;
    (void)ulPinLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_Logout logs a user out from a token. */
CK_DECLARE_FUNCTION(CK_RV, C_Logout)

(CK_SESSION_HANDLE hSession /* the session's handle */
)
{
    DEBUG("C_Logout");
    (void)hSession;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/* Object management */

/* C_CreateObject creates a new object. */
CK_DECLARE_FUNCTION(CK_RV, C_CreateObject)

(CK_SESSION_HANDLE    hSession,  /* the session's handle */
 CK_ATTRIBUTE_PTR     pTemplate, /* the object's template */
 CK_ULONG             ulCount,   /* attributes in template */
 CK_OBJECT_HANDLE_PTR phObject   /* gets new object's handle. */
)
{
    DEBUG("C_CreateObject");
    (void)hSession;
    (void)pTemplate;
    (void)ulCount;
    (void)phObject;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_CopyObject copies an object, creating a new object for the
 * copy.
 */
CK_DECLARE_FUNCTION(CK_RV, C_CopyObject)

(CK_SESSION_HANDLE    hSession,   /* the session's handle */
 CK_OBJECT_HANDLE     hObject,    /* the object's handle */
 CK_ATTRIBUTE_PTR     pTemplate,  /* template for new object */
 CK_ULONG             ulCount,    /* attributes in template */
 CK_OBJECT_HANDLE_PTR phNewObject /* receives handle of copy */
)
{
    DEBUG("C_CopyObject");
    (void)hSession;
    (void)hObject;
    (void)pTemplate;
    (void)ulCount;
    (void)phNewObject;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_DestroyObject destroys an object. */
CK_DECLARE_FUNCTION(CK_RV, C_DestroyObject)

(CK_SESSION_HANDLE hSession, /* the session's handle */
 CK_OBJECT_HANDLE  hObject   /* the object's handle */
)
{
    DEBUG("C_Destroy");
    (void)hSession;
    (void)hObject;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_GetObjectSize gets the size of an object in bytes. */
CK_DECLARE_FUNCTION(CK_RV, C_GetObjectSize)

(CK_SESSION_HANDLE hSession, /* the session's handle */
 CK_OBJECT_HANDLE  hObject,  /* the object's handle */
 CK_ULONG_PTR      pulSize   /* receives size of object */
)
{
    DEBUG("C_GetObjectSize");
    (void)hSession;
    (void)hObject;
    (void)pulSize;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_GetAttributeValue obtains the value of one or more object
 * attributes.
 */
CK_DECLARE_FUNCTION(CK_RV, C_GetAttributeValue)

(CK_SESSION_HANDLE hSession,  /* the session's handle */
 CK_OBJECT_HANDLE  hObject,   /* the object's handle */
 CK_ATTRIBUTE_PTR  pTemplate, /* specifies attrs{} gets vals */
 CK_ULONG          ulCount    /* attributes in template */
)
{
    DEBUG("C_GetAttributeValue");

    if(!SfModule)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    // Session ID == Slot Number
    PKCS11_SfSlot* sSlotPtr = SfModule->getSlot(hSession);
    if(!sSlotPtr)
    {
        return CKR_ARGUMENTS_BAD;
    }

    PKCS11_SfToken& sToken = sSlotPtr->getToken();

    PKCS11_SfSession& sSession = sToken.getSession();

    // TODO: handle null ptr
    const SfKey* sKeyPtr = sSession.getKey(hObject);
    if(!sKeyPtr)
    {
        DEBUG("BAD ARGUMENT: hObject " << std::dec << hObject);
        exit(0);
        return CKR_ARGUMENTS_BAD;
    }

    for(CK_ULONG sIdx = 0; sIdx < ulCount; sIdx++)
    {
        CK_ATTRIBUTE& sTemplate = pTemplate[sIdx];

        DEBUG("\tC_GetAttributeValue: " << std::hex << sTemplate.type);

        sKeyPtr->getAttribute(sTemplate.type, sTemplate.pValue, sTemplate.ulValueLen);
    }

    return CKR_OK;
}

/* C_SetAttributeValue modifies the value of one or more object
 * attributes.
 */
CK_DECLARE_FUNCTION(CK_RV, C_SetAttributeValue)

(CK_SESSION_HANDLE hSession,  /* the session's handle */
 CK_OBJECT_HANDLE  hObject,   /* the object's handle */
 CK_ATTRIBUTE_PTR  pTemplate, /* specifies attrs and values */
 CK_ULONG          ulCount    /* attributes in template */
)
{
    DEBUG("C_SetAttributeValue");
    (void)hSession;
    (void)hObject;
    (void)pTemplate;
    (void)ulCount;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_FindObjectsInit initializes a search for token and session
 * objects that match a template.
 */
// Return values: CKR_ARGUMENTS_BAD, CKR_ATTRIBUTE_TYPE_INVALID, CKR_ATTRIBUTE_VALUE_INVALID,
// CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED,
// CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_OPERATION_ACTIVE,
// CKR_PIN_EXPIRED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID.
CK_DECLARE_FUNCTION(CK_RV, C_FindObjectsInit)

(CK_SESSION_HANDLE hSession,  /* the session's handle */
 CK_ATTRIBUTE_PTR  pTemplate, /* attribute values to match */
 CK_ULONG          ulCount    /* attrs in search template */
)
{
    DEBUG("C_FindObjectsInit START");

    if(!SfModule)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    PKCS11_SfSlot* sSlotPtr = SfModule->getSlot(hSession);
    if(!sSlotPtr)
    {
        return CKR_ARGUMENTS_BAD;
    }

    PKCS11_SfToken&   sToken   = sSlotPtr->getToken();
    PKCS11_SfSession& sSession = sToken.getSession();

    sSession.initSearch(pTemplate, ulCount);

    return CKR_OK;
}

/* C_FindObjects continues a search for token and session
 * objects that match a template, obtaining additional object
 * handles.
 */
CK_DECLARE_FUNCTION(CK_RV, C_FindObjects)

(CK_SESSION_HANDLE    hSession,         /* session's handle */
 CK_OBJECT_HANDLE_PTR phObject,         /* gets obj. handles */
 CK_ULONG             ulMaxObjectCount, /* max handles to get */
 CK_ULONG_PTR         pulObjectCount    /* actual # returned */
)
{
    DEBUG("C_FindObjects START");
    if(!SfModule)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    PKCS11_SfSlot* sSlotPtr = SfModule->getSlot(hSession);
    if(!sSlotPtr)
    {
        return CKR_ARGUMENTS_BAD;
    }

    PKCS11_SfToken&   sToken   = sSlotPtr->getToken();
    PKCS11_SfSession& sSession = sToken.getSession();

    sSession.doSearch(phObject, ulMaxObjectCount, *pulObjectCount);

    return CKR_OK;
}

/* C_FindObjectsFinal finishes a search for token and session
 * objects.
 */
CK_DECLARE_FUNCTION(CK_RV, C_FindObjectsFinal)

(CK_SESSION_HANDLE hSession /* the session's handle */
)
{
    DEBUG("C_FindObjectsFinal");

    if(!SfModule)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    PKCS11_SfSlot* sSlotPtr = SfModule->getSlot(hSession);
    if(!sSlotPtr)
    {
        return CKR_ARGUMENTS_BAD;
    }

    PKCS11_SfToken&   sToken   = sSlotPtr->getToken();
    PKCS11_SfSession& sSession = sToken.getSession();

    sSession.endSearch();
    return CKR_OK;
}

/* Encryption and decryption */

/* C_EncryptInit initializes an encryption operation. */
CK_DECLARE_FUNCTION(CK_RV, C_EncryptInit)

(CK_SESSION_HANDLE hSession,   /* the session's handle */
 CK_MECHANISM_PTR  pMechanism, /* the encryption mechanism */
 CK_OBJECT_HANDLE  hKey        /* handle of encryption key */
)
{
    (void)hSession;
    (void)pMechanism;
    (void)hKey;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_Encrypt encrypts single-part data. */
CK_DECLARE_FUNCTION(CK_RV, C_Encrypt)

(CK_SESSION_HANDLE hSession,           /* session's handle */
 CK_BYTE_PTR       pData,              /* the plaintext data */
 CK_ULONG          ulDataLen,          /* bytes of plaintext */
 CK_BYTE_PTR       pEncryptedData,     /* gets ciphertext */
 CK_ULONG_PTR      pulEncryptedDataLen /* gets c-text size */
)
{
    (void)hSession;
    (void)pData;
    (void)ulDataLen;
    (void)pEncryptedData;
    (void)pulEncryptedDataLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_EncryptUpdate continues a multiple-part encryption
 * operation.
 */
CK_DECLARE_FUNCTION(CK_RV, C_EncryptUpdate)

(CK_SESSION_HANDLE hSession,           /* session's handle */
 CK_BYTE_PTR       pPart,              /* the plaintext data */
 CK_ULONG          ulPartLen,          /* plaintext data len */
 CK_BYTE_PTR       pEncryptedPart,     /* gets ciphertext */
 CK_ULONG_PTR      pulEncryptedPartLen /* gets c-text size */
)
{
    (void)hSession;
    (void)pPart;
    (void)ulPartLen;
    (void)pEncryptedPart;
    (void)pulEncryptedPartLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_EncryptFinal finishes a multiple-part encryption
 * operation.
 */
CK_DECLARE_FUNCTION(CK_RV, C_EncryptFinal)

(CK_SESSION_HANDLE hSession,               /* session handle */
 CK_BYTE_PTR       pLastEncryptedPart,     /* last c-text */
 CK_ULONG_PTR      pulLastEncryptedPartLen /* gets last size */
)
{
    (void)hSession;
    (void)pLastEncryptedPart;
    (void)pulLastEncryptedPartLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_DecryptInit initializes a decryption operation. */
CK_DECLARE_FUNCTION(CK_RV, C_DecryptInit)

(CK_SESSION_HANDLE hSession,   /* the session's handle */
 CK_MECHANISM_PTR  pMechanism, /* the decryption mechanism */
 CK_OBJECT_HANDLE  hKey        /* handle of decryption key */
)
{
    (void)hSession;
    (void)pMechanism;
    (void)hKey;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_Decrypt decrypts encrypted data in a single part. */
CK_DECLARE_FUNCTION(CK_RV, C_Decrypt)

(CK_SESSION_HANDLE hSession,           /* session's handle */
 CK_BYTE_PTR       pEncryptedData,     /* ciphertext */
 CK_ULONG          ulEncryptedDataLen, /* ciphertext length */
 CK_BYTE_PTR       pData,              /* gets plaintext */
 CK_ULONG_PTR      pulDataLen          /* gets p-text size */
)
{
    (void)hSession;
    (void)pEncryptedData;
    (void)ulEncryptedDataLen;
    (void)pData;
    (void)pulDataLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_DecryptUpdate continues a multiple-part decryption
 * operation.
 */
CK_DECLARE_FUNCTION(CK_RV, C_DecryptUpdate)

(CK_SESSION_HANDLE hSession,           /* session's handle */
 CK_BYTE_PTR       pEncryptedPart,     /* encrypted data */
 CK_ULONG          ulEncryptedPartLen, /* input length */
 CK_BYTE_PTR       pPart,              /* gets plaintext */
 CK_ULONG_PTR      pulPartLen          /* p-text size */
)
{
    (void)hSession;
    (void)pEncryptedPart;
    (void)ulEncryptedPartLen;
    (void)pPart;
    (void)pulPartLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_DecryptFinal finishes a multiple-part decryption
 * operation.
 */
CK_DECLARE_FUNCTION(CK_RV, C_DecryptFinal)

(CK_SESSION_HANDLE hSession,      /* the session's handle */
 CK_BYTE_PTR       pLastPart,     /* gets plaintext */
 CK_ULONG_PTR      pulLastPartLen /* p-text size */
)
{
    (void)hSession;
    (void)pLastPart;
    (void)pulLastPartLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/* Message digesting */

/* C_DigestInit initializes a message-digesting operation. */
CK_DECLARE_FUNCTION(CK_RV, C_DigestInit)

(CK_SESSION_HANDLE hSession,  /* the session's handle */
 CK_MECHANISM_PTR  pMechanism /* the digesting mechanism */
)
{
    (void)hSession;
    (void)pMechanism;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_Digest digests data in a single part. */
CK_DECLARE_FUNCTION(CK_RV, C_Digest)

(CK_SESSION_HANDLE hSession,    /* the session's handle */
 CK_BYTE_PTR       pData,       /* data to be digested */
 CK_ULONG          ulDataLen,   /* bytes of data to digest */
 CK_BYTE_PTR       pDigest,     /* gets the message digest */
 CK_ULONG_PTR      pulDigestLen /* gets digest length */
)
{
    (void)hSession;
    (void)pData;
    (void)ulDataLen;
    (void)pDigest;
    (void)pulDigestLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_DigestUpdate continues a multiple-part message-digesting
 * operation.
 */
CK_DECLARE_FUNCTION(CK_RV, C_DigestUpdate)

(CK_SESSION_HANDLE hSession, /* the session's handle */
 CK_BYTE_PTR       pPart,    /* data to be digested */
 CK_ULONG          ulPartLen /* bytes of data to be digested */
)
{
    (void)hSession;
    (void)pPart;
    (void)ulPartLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_DigestKey continues a multi-part message-digesting
 * operation, by digesting the value of a secret key as part of
 * the data already digested.
 */
CK_DECLARE_FUNCTION(CK_RV, C_DigestKey)

(CK_SESSION_HANDLE hSession, /* the session's handle */
 CK_OBJECT_HANDLE  hKey      /* secret key to digest */
)
{
    (void)hSession;
    (void)hKey;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_DigestFinal finishes a multiple-part message-digesting
 * operation.
 */
CK_DECLARE_FUNCTION(CK_RV, C_DigestFinal)

(CK_SESSION_HANDLE hSession,    /* the session's handle */
 CK_BYTE_PTR       pDigest,     /* gets the message digest */
 CK_ULONG_PTR      pulDigestLen /* gets byte count of digest */
)
{
    (void)hSession;
    (void)pDigest;
    (void)pulDigestLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/* Signing and MACing */

/* C_SignInit initializes a signature (private key encryption)
 * operation, where the signature is (will be) an appendix to
 * the data, and plaintext cannot be recovered from the
 * signature.
 */
CK_DECLARE_FUNCTION(CK_RV, C_SignInit)

(CK_SESSION_HANDLE hSession,   /* the session's handle */
 CK_MECHANISM_PTR  pMechanism, /* the signature mechanism */
 CK_OBJECT_HANDLE  hKey        /* handle of signature key */
)
{
    DEBUG("C_SignInit START");
    (void)pMechanism; // TODO: Do something with this?

    if(!SfModule)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    // Session ID == Slot Number
    PKCS11_SfSlot* sSlotPtr = SfModule->getSlot(hSession);
    if(!sSlotPtr)
    {
        return CKR_ARGUMENTS_BAD;
    }

    PKCS11_SfToken& sToken = sSlotPtr->getToken();

    PKCS11_SfSession& sSession = sToken.getSession();

    // TODO: handle null ptr
    const SfKey* sKeyPtr = sSession.getKey(hKey);
    if(!sKeyPtr)
    {
        DEBUG("BAD ARGUMENT: hObject " << std::dec << hKey);
        return CKR_ARGUMENTS_BAD;
    }

    sSession.initSigning(hKey);

    return CKR_OK;
}

/* C_Sign signs (encrypts with private key) data in a single
 * part, where the signature is (will be) an appendix to the
 * data, and plaintext cannot be recovered from the signature.
 */
CK_DECLARE_FUNCTION(CK_RV, C_Sign)

(CK_SESSION_HANDLE hSession,       /* the session's handle */
 CK_BYTE_PTR       pData,          /* the data to sign */
 CK_ULONG          ulDataLen,      /* count of bytes to sign */
 CK_BYTE_PTR       pSignature,     /* gets the signature */
 CK_ULONG_PTR      pulSignatureLen /* gets signature length */
)
{
    DEBUG("C_Sign");

    if(!SfModule)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }

    // Session ID == Slot Number
    PKCS11_SfSlot* sSlotPtr = SfModule->getSlot(hSession);
    if(!sSlotPtr)
    {
        return CKR_ARGUMENTS_BAD;
    }

    PKCS11_SfToken& sToken = sSlotPtr->getToken();

    PKCS11_SfSession& sSession = sToken.getSession();
    bool sIsSuccess            = sSession.doSigning(pData, ulDataLen, pSignature, *pulSignatureLen);

    return sIsSuccess ? CKR_OK : CKR_GENERAL_ERROR;
}

/* C_SignUpdate continues a multiple-part signature operation,
 * where the signature is (will be) an appendix to the data,
 * and plaintext cannot be recovered from the signature.
 */
CK_DECLARE_FUNCTION(CK_RV, C_SignUpdate)

(CK_SESSION_HANDLE hSession, /* the session's handle */
 CK_BYTE_PTR       pPart,    /* the data to sign */
 CK_ULONG          ulPartLen /* count of bytes to sign */
)
{
    DEBUG("C_SignUpdate");
    (void)hSession;
    (void)pPart;
    (void)ulPartLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_SignFinal finishes a multiple-part signature operation,
 * returning the signature.
 */
CK_DECLARE_FUNCTION(CK_RV, C_SignFinal)

(CK_SESSION_HANDLE hSession,       /* the session's handle */
 CK_BYTE_PTR       pSignature,     /* gets the signature */
 CK_ULONG_PTR      pulSignatureLen /* gets signature length */
)
{
    (void)hSession;
    (void)pSignature;
    (void)pulSignatureLen;

    return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_SignRecoverInit initializes a signature operation, where
 * the data can be recovered from the signature.
 */
CK_DECLARE_FUNCTION(CK_RV, C_SignRecoverInit)

(CK_SESSION_HANDLE hSession,   /* the session's handle */
 CK_MECHANISM_PTR  pMechanism, /* the signature mechanism */
 CK_OBJECT_HANDLE  hKey        /* handle of the signature key */
)
{
    (void)hSession;
    (void)pMechanism;
    (void)hKey;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_SignRecover signs data in a single operation, where the
 * data can be recovered from the signature.
 */
CK_DECLARE_FUNCTION(CK_RV, C_SignRecover)

(CK_SESSION_HANDLE hSession,       /* the session's handle */
 CK_BYTE_PTR       pData,          /* the data to sign */
 CK_ULONG          ulDataLen,      /* count of bytes to sign */
 CK_BYTE_PTR       pSignature,     /* gets the signature */
 CK_ULONG_PTR      pulSignatureLen /* gets signature length */
)
{
    (void)hSession;
    (void)pData;
    (void)ulDataLen;
    (void)pSignature;
    (void)pulSignatureLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/* Verifying signatures and MACs */

/* C_VerifyInit initializes a verification operation, where the
 * signature is an appendix to the data, and plaintext cannot
 * cannot be recovered from the signature (e.g. DSA).
 */
CK_DECLARE_FUNCTION(CK_RV, C_VerifyInit)

(CK_SESSION_HANDLE hSession,   /* the session's handle */
 CK_MECHANISM_PTR  pMechanism, /* the verification mechanism */
 CK_OBJECT_HANDLE  hKey        /* verification key */
)
{
    (void)hSession;
    (void)pMechanism;
    (void)hKey;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_Verify verifies a signature in a single-part operation,
 * where the signature is an appendix to the data, and plaintext
 * cannot be recovered from the signature.
 */
CK_DECLARE_FUNCTION(CK_RV, C_Verify)

(CK_SESSION_HANDLE hSession,      /* the session's handle */
 CK_BYTE_PTR       pData,         /* signed data */
 CK_ULONG          ulDataLen,     /* length of signed data */
 CK_BYTE_PTR       pSignature,    /* signature */
 CK_ULONG          ulSignatureLen /* signature length*/
)
{
    (void)hSession;
    (void)pData;
    (void)ulDataLen;
    (void)pSignature;
    (void)ulSignatureLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_VerifyUpdate continues a multiple-part verification
 * operation, where the signature is an appendix to the data,
 * and plaintext cannot be recovered from the signature.
 */
CK_DECLARE_FUNCTION(CK_RV, C_VerifyUpdate)

(CK_SESSION_HANDLE hSession, /* the session's handle */
 CK_BYTE_PTR       pPart,    /* signed data */
 CK_ULONG          ulPartLen /* length of signed data */
)
{
    (void)hSession;
    (void)pPart;
    (void)ulPartLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_VerifyFinal finishes a multiple-part verification
 * operation, checking the signature.
 */
CK_DECLARE_FUNCTION(CK_RV, C_VerifyFinal)

(CK_SESSION_HANDLE hSession,      /* the session's handle */
 CK_BYTE_PTR       pSignature,    /* signature to verify */
 CK_ULONG          ulSignatureLen /* signature length */
)
{
    (void)hSession;
    (void)pSignature;
    (void)ulSignatureLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_VerifyRecoverInit initializes a signature verification
 * operation, where the data is recovered from the signature.
 */
CK_DECLARE_FUNCTION(CK_RV, C_VerifyRecoverInit)

(CK_SESSION_HANDLE hSession,   /* the session's handle */
 CK_MECHANISM_PTR  pMechanism, /* the verification mechanism */
 CK_OBJECT_HANDLE  hKey        /* verification key */
)
{
    (void)hSession;
    (void)pMechanism;
    (void)hKey;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_VerifyRecover verifies a signature in a single-part
 * operation, where the data is recovered from the signature.
 */
CK_DECLARE_FUNCTION(CK_RV, C_VerifyRecover)

(CK_SESSION_HANDLE hSession,       /* the session's handle */
 CK_BYTE_PTR       pSignature,     /* signature to verify */
 CK_ULONG          ulSignatureLen, /* signature length */
 CK_BYTE_PTR       pData,          /* gets signed data */
 CK_ULONG_PTR      pulDataLen      /* gets signed data len */
)
{
    (void)hSession;
    (void)pSignature;
    (void)ulSignatureLen;
    (void)pData;
    (void)pulDataLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/* Dual-function cryptographic operations */

/* C_DigestEncryptUpdate continues a multiple-part digesting
 * and encryption operation.
 */
CK_DECLARE_FUNCTION(CK_RV, C_DigestEncryptUpdate)

(CK_SESSION_HANDLE hSession,           /* session's handle */
 CK_BYTE_PTR       pPart,              /* the plaintext data */
 CK_ULONG          ulPartLen,          /* plaintext length */
 CK_BYTE_PTR       pEncryptedPart,     /* gets ciphertext */
 CK_ULONG_PTR      pulEncryptedPartLen /* gets c-text length */
)
{
    (void)hSession;
    (void)pPart;
    (void)ulPartLen;
    (void)pEncryptedPart;
    (void)pulEncryptedPartLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_DecryptDigestUpdate continues a multiple-part decryption and
 * digesting operation.
 */
CK_DECLARE_FUNCTION(CK_RV, C_DecryptDigestUpdate)

(CK_SESSION_HANDLE hSession,           /* session's handle */
 CK_BYTE_PTR       pEncryptedPart,     /* ciphertext */
 CK_ULONG          ulEncryptedPartLen, /* ciphertext length */
 CK_BYTE_PTR       pPart,              /* gets plaintext */
 CK_ULONG_PTR      pulPartLen          /* gets plaintext len */
)
{
    (void)hSession;
    (void)pEncryptedPart;
    (void)ulEncryptedPartLen;
    (void)pPart;
    (void)pulPartLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_SignEncryptUpdate continues a multiple-part signing and
 * encryption operation.
 */
CK_DECLARE_FUNCTION(CK_RV, C_SignEncryptUpdate)

(CK_SESSION_HANDLE hSession,           /* session's handle */
 CK_BYTE_PTR       pPart,              /* the plaintext data */
 CK_ULONG          ulPartLen,          /* plaintext length */
 CK_BYTE_PTR       pEncryptedPart,     /* gets ciphertext */
 CK_ULONG_PTR      pulEncryptedPartLen /* gets c-text length */
)
{
    (void)hSession;
    (void)pPart;
    (void)ulPartLen;
    (void)pEncryptedPart;
    (void)pulEncryptedPartLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_DecryptVerifyUpdate continues a multiple-part decryption and
 * verify operation.
 */
CK_DECLARE_FUNCTION(CK_RV, C_DecryptVerifyUpdate)

(CK_SESSION_HANDLE hSession,           /* session's handle */
 CK_BYTE_PTR       pEncryptedPart,     /* ciphertext */
 CK_ULONG          ulEncryptedPartLen, /* ciphertext length */
 CK_BYTE_PTR       pPart,              /* gets plaintext */
 CK_ULONG_PTR      pulPartLen          /* gets p-text length */
)
{
    (void)hSession;
    (void)pEncryptedPart;
    (void)ulEncryptedPartLen;
    (void)pPart;
    (void)pulPartLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/* Key management */

/* C_GenerateKey generates a secret key, creating a new key
 * object.
 */
CK_DECLARE_FUNCTION(CK_RV, C_GenerateKey)

(CK_SESSION_HANDLE    hSession,   /* the session's handle */
 CK_MECHANISM_PTR     pMechanism, /* key generation mech. */
 CK_ATTRIBUTE_PTR     pTemplate,  /* template for new key */
 CK_ULONG             ulCount,    /* # of attrs in template */
 CK_OBJECT_HANDLE_PTR phKey       /* gets handle of new key */
)
{
    (void)hSession;
    (void)pMechanism;
    (void)pTemplate;
    (void)ulCount;
    (void)phKey;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_GenerateKeyPair generates a public-key/private-key pair,
 * creating new key objects.
 */
CK_DECLARE_FUNCTION(CK_RV, C_GenerateKeyPair)

(CK_SESSION_HANDLE    hSession,                   /* session handle */
 CK_MECHANISM_PTR     pMechanism,                 /* key-gen mech. */
 CK_ATTRIBUTE_PTR     pPublicKeyTemplate,         /* template for pub. key */
 CK_ULONG             ulPublicKeyAttributeCount,  /* # pub. attrs. */
 CK_ATTRIBUTE_PTR     pPrivateKeyTemplate,        /* template for priv. key */
 CK_ULONG             ulPrivateKeyAttributeCount, /* # priv.  attrs. */
 CK_OBJECT_HANDLE_PTR phPublicKey,                /* gets pub. key handle */
 CK_OBJECT_HANDLE_PTR phPrivateKey                /* gets priv. key handle */
)
{
    (void)hSession;
    (void)pMechanism;
    (void)pPublicKeyTemplate;
    (void)ulPublicKeyAttributeCount;
    (void)pPrivateKeyTemplate;
    (void)ulPrivateKeyAttributeCount;
    (void)phPublicKey;
    (void)phPrivateKey;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_WrapKey wraps (i.e., encrypts) a key. */
CK_DECLARE_FUNCTION(CK_RV, C_WrapKey)

(CK_SESSION_HANDLE hSession,        /* the session's handle */
 CK_MECHANISM_PTR  pMechanism,      /* the wrapping mechanism */
 CK_OBJECT_HANDLE  hWrappingKey,    /* wrapping key */
 CK_OBJECT_HANDLE  hKey,            /* key to be wrapped */
 CK_BYTE_PTR       pWrappedKey,     /* gets wrapped key */
 CK_ULONG_PTR      pulWrappedKeyLen /* gets wrapped key size */
)
{
    (void)hSession;
    (void)pMechanism;
    (void)hWrappingKey;
    (void)hKey;
    (void)pWrappedKey;
    (void)pulWrappedKeyLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_UnwrapKey unwraps (decrypts) a wrapped key, creating a new
 * key object.
 */
CK_DECLARE_FUNCTION(CK_RV, C_UnwrapKey)

(CK_SESSION_HANDLE    hSession,         /* session's handle */
 CK_MECHANISM_PTR     pMechanism,       /* unwrapping mech. */
 CK_OBJECT_HANDLE     hUnwrappingKey,   /* unwrapping key */
 CK_BYTE_PTR          pWrappedKey,      /* the wrapped key */
 CK_ULONG             ulWrappedKeyLen,  /* wrapped key len */
 CK_ATTRIBUTE_PTR     pTemplate,        /* new key template */
 CK_ULONG             ulAttributeCount, /* template length */
 CK_OBJECT_HANDLE_PTR phKey             /* gets new handle */
)
{
    (void)hSession;
    (void)pMechanism;
    (void)hUnwrappingKey;
    (void)pWrappedKey;
    (void)ulWrappedKeyLen;
    (void)pTemplate;
    (void)ulAttributeCount;
    (void)phKey;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_DeriveKey derives a key from a base key, creating a new key
 * object.
 */
CK_DECLARE_FUNCTION(CK_RV, C_DeriveKey)

(CK_SESSION_HANDLE    hSession,         /* session's handle */
 CK_MECHANISM_PTR     pMechanism,       /* key deriv. mech. */
 CK_OBJECT_HANDLE     hBaseKey,         /* base key */
 CK_ATTRIBUTE_PTR     pTemplate,        /* new key template */
 CK_ULONG             ulAttributeCount, /* template length */
 CK_OBJECT_HANDLE_PTR phKey             /* gets new handle */
)
{
    (void)hSession;
    (void)pMechanism;
    (void)hBaseKey;
    (void)pTemplate;
    (void)ulAttributeCount;
    (void)phKey;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/* Random number generation */

/* C_SeedRandom mixes additional seed material into the token's
 * random number generator.
 */
CK_DECLARE_FUNCTION(CK_RV, C_SeedRandom)

(CK_SESSION_HANDLE hSession, /* the session's handle */
 CK_BYTE_PTR       pSeed,    /* the seed material */
 CK_ULONG          ulSeedLen /* length of seed material */
)
{
    (void)hSession;
    (void)pSeed;
    (void)ulSeedLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_GenerateRandom generates random data. */
CK_DECLARE_FUNCTION(CK_RV, C_GenerateRandom)

(CK_SESSION_HANDLE hSession,   /* the session's handle */
 CK_BYTE_PTR       RandomData, /* receives the random data */
 CK_ULONG          ulRandomLen /* # of bytes to generate */
)
{
    (void)hSession;
    (void)RandomData;
    (void)ulRandomLen;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/* Parallel function management */

/* C_GetFunctionStatus is a legacy function{} it obtains an
 * updated status of a function running in parallel with an
 * application.
 */
CK_DECLARE_FUNCTION(CK_RV, C_GetFunctionStatus)

(CK_SESSION_HANDLE hSession /* the session's handle */
)
{
    (void)hSession;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_CancelFunction is a legacy function{} it cancels a function
 * running in parallel.
 */
CK_DECLARE_FUNCTION(CK_RV, C_CancelFunction)

(CK_SESSION_HANDLE hSession /* the session's handle */
)
{
    (void)hSession;
    return CKR_FUNCTION_NOT_SUPPORTED;
}

/* C_WaitForSlotEvent waits for a slot event (token insertion,
 * removal, etc.) to occur.
 */
CK_DECLARE_FUNCTION(CK_RV, C_WaitForSlotEvent)

(CK_FLAGS       flags,   /* blocking/nonblocking flag */
 CK_SLOT_ID_PTR pSlot,   /* location that receives the slot ID */
 CK_VOID_PTR    pRserved /* reserved.  Should be NULL_PTR */
)
{
    (void)flags;
    (void)pSlot;
    (void)pRserved;
    return CKR_FUNCTION_NOT_SUPPORTED;
}
