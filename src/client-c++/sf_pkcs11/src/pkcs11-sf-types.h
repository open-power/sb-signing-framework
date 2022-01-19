/* Copyright 2021 IBM Corp.
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
#ifndef _PKCS11_SF_TYPES_H
#define _PKCS11_SF_TYPES_H

extern const char* SfTokenLabel;
extern const char* SfTokenManufacturer;
extern const char* SfTokenModel;
extern const char* SfTokenSerialNumber;

extern const char* SfModuleManufacturer;
extern const char* SfModuleDescription;

extern const char* SfSlotManufacturer;
extern const char* SfSlotDescription;

extern const char* SfJsonKey_Url;
extern const char* SfJsonKey_Epwd;
extern const char* SfJsonKey_PrivateKeyPath;
extern const char* SfJsonKey_ProjectArray;
extern const char* SfJsonKey_ProjectName;
extern const char* SfJsonKey_ProjectType;
extern const char* SfJsonKey_HashAlgorithm;

enum
{
    TokenHardwareVersionMajor = 0,
    TokenHardwareVersionMinor = 0,
    TokenFirmwareVersionMajor = 0,
    TokenFirmwareVersionMinor = 0,
};

enum
{
    ModuleCryptokiVersionMajor = 0,
    ModuleCryptokiVersionMinor = 0,
    ModuleLibraryVersionMajor  = 0,
    ModuleLibraryVersionMinor  = 0,
};

enum
{
    SlotHardwareVersionMajor = 1,
    SlotHardwareVersionMinor = 0,
    SlotFirmwareVersionMajor = 1,
    SlotFirmwareVersionMinor = 0,
};

#endif
