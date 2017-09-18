/* Copyright 2017 IBM Corp.
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

#include "hw_utils.h"
#include "sha512.h"
#include "ecdsa521.h"


#define CONTAINER_VERSION   1
#define HEADER_VERSION      1
#define HASH_ALG_SHA512     1
#define SIG_ALG_ECDSA521    1

#define HBI_BASE_SIGNING_KEY 0x80000000

#define ROM_MAGIC_NUMBER     0x17082011


typedef struct {
    uint32_t  m_magicNumber;                    // (17082011)
    uint16_t  m_version;                        // (1: see versions above)
    uint8_t   m_containerSize[8];               // filled by caller
    uint8_t   m_targetHrmor[8];                 // filled by caller
    uint8_t   m_stackPointer[8];                // filled by caller
    uint8_t   m_hwPkeyA[ECDSA521_KEY_SIZE];
    uint8_t   m_hwPkeyB[ECDSA521_KEY_SIZE];
    uint8_t   m_hwPkeyC[ECDSA521_KEY_SIZE];
} ContainerHdr;


typedef struct {
    uint16_t  m_version;                         // (1: see versions above)
    uint8_t   m_hashAlg;                         // (1: SHA-512)
    uint8_t   m_sigAlg;                          // (1: SHA-512/ECDSA-521)
    uint8_t   m_codeStartOffset[8];
    uint8_t   m_reserved[8];
    uint32_t  m_flags;
    uint8_t   m_swKeyCount;
    uint8_t   m_payloadSize[8];
    uint8_t   m_payloadHash[SHA512_DIGEST_SIZE];
    uint8_t   m_ecidCount;
    uint8_t   m_ecid[ECID_SIZE];                 // optional ecid place 
                                                 // holder ecid_count * szeof(ecids)
} PrefixHdr;


typedef struct {
    uint8_t   m_hwSigA[ECDSA521_SIG_SIZE];
    uint8_t   m_hwSigB[ECDSA521_SIG_SIZE];
    uint8_t   m_hwSigC[ECDSA521_SIG_SIZE];
    uint8_t   m_swPkeyP[ECDSA521_KEY_SIZE];
    uint8_t   m_swPkeyQ[ECDSA521_KEY_SIZE];
    uint8_t   m_swPkeyR[ECDSA521_KEY_SIZE];
} PrefixData;


typedef struct {
    uint16_t  m_version;                         // (1: see versions above)
    uint8_t   m_hashAlg;                         // (1: SHA-512)
    uint8_t   m_unused;
    uint8_t   m_codeStartOffset[8];
    uint8_t   m_reserved[8];
    uint32_t  m_flags;
    uint8_t   m_reserved0;
    uint8_t   m_payloadSize[8];
    uint8_t   m_payloadHash[SHA512_DIGEST_SIZE];
    uint8_t   m_ecidCount;
    uint8_t   m_ecid[ECID_SIZE];                 // optional ecid place 
                                                 // holder ecid_count * szeof(ecids)
} SoftwareHdr;


typedef struct {
    uint8_t   m_swSigP[ECDSA521_SIG_SIZE];
    uint8_t   m_swSigQ[ECDSA521_SIG_SIZE];
    uint8_t   m_swSigR[ECDSA521_SIG_SIZE];
} SoftwareSig;




/* The Container Layout consists of the following 5 blocks 
 *   ContainerHdr
 *   PrefixHdr
 *   PrefixData
 *   SoftwareHdr
 *   SoftwareSig
 */
typedef struct {
    ContainerHdr m_containerHdr;
    PrefixHdr    m_prefixHdr;
    PrefixData   m_prefixData;
    SoftwareHdr  m_softwareHdr;
    SoftwareSig  m_softwareSig;
} Container;


// Print out all the fields of the container
void PrintContainer( const Container *p_container );

// Validate the container
int  ValidateContainer( const Container *p_container );

// Given a stream of bytes, parse the data and constuct the container
Container* ParseContainer( uint8_t *p_rawData, int p_endianess );
