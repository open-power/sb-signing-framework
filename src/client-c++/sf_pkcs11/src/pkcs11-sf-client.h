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

#include <bitset>
#include <iostream>
#include <openssl/crypto.h>
#include <sstream>
#include <string>
#include <vector>

#ifndef _PKCS11_SF_CLIENT_H
#define _PKCS11_SF_CLIENT_H

// Required definitions for PKCS11 files
#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType(*name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType(*name)

#ifndef NULL_PTR
#define NULL_PTR 0
#endif

#include "pkcs11/pkcs11.h"

enum
{
    CryptokiVersionMajor       = 2,
    CryptokiVersionMinor       = 40,
    Pkcs11SfClientVersionMajor = 0,
    Pkcs11SfClientVersionMinor = 1,
};

// Slots:
// Only expose a single slot to the application
enum
{
    TotalNumberOfSlots     = 1,
    MaxPasswordLength      = 1024,
    PasswordAllocationSize = MaxPasswordLength + 1, // null termination
};


#endif