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

#ifndef CCA_ECC_STRUCTURES_H
#define CCA_ECC_STRUCTURES_H

#include <stdint.h>

/* tokenID */
#define PKA_EXTERNAL_TOKEN		0x1E
#define PKA_INTERNAL_TOKEN		0x1F

/* sectionID */
#define ECC_PRIVATE_SECTION          	0x20
#define ECC_PUBLIC_SECTION           	0x21

#define ECC_WRAP_METH_CLEAR         	0x00
#define ECC_WRAP_METH_AESKW         	0x01
#define ECC_WRAP_METH_CBC           	0x02

#define ECC_HASH_NONE              	0x00
#define ECC_HASH_SHA224            	0x01
#define ECC_HASH_SHA256            	0x02
#define ECC_HASH_SHA384            	0x04
#define ECC_HASH_SHA512            	0x08

#define ECC_KEY_MGMT_ONLY               0xC0
#define ECC_KEY_DIST_AND_SIGN           0x80
#define ECC_SIGNATURE_USE_ONLY          0x00
#define ECC_TRANSLATE                   0x02

#define ECC_PRIME      			0x00
#define ECC_BRAINPOOL  			0x01

#define ECC_INTERNAL_ENCRYPTED          0x08
#define ECC_EXTERNAL                    0x40
#define ECC_EXTERNAL_ENCRYPTED          0x42

#define ECC_PRIV_VERSION_00          	0x00


#define ECC_PRIME_521     		0x0209
#define MKVP_LENGTH             	8

#define ECC_OBJ_PROTECTION_LEN       	48
#define MAX_Q_LEN_BYTES     133     /* size of pub key for max p-Len (521)    */


/* PKA96 ECC token header */

typedef struct tdEccKeyTokenHeader
{
    unsigned char    	tokenId;                    /* Token identifier.          */
    unsigned char    	version;
    uint16_t  		tokenLength;
    uint32_t 		reserved;
} EccKeyTokenHeader;

typedef struct tdEccKeyTokenPublic
{
    unsigned char   	sectionId;
    unsigned char    	version;
    uint16_t         	sectionLength;           /* Length of the RSA public key section  */
    uint32_t 		reserved;
    unsigned char    	curveType;               /* curve type:  Prime or Brainpool       */
    unsigned char    	reserved2;
    uint16_t   		pLength;                 /* length of p in bits                   */
    uint16_t   		qLen;                    /* length of public key Q in bytes       */
    unsigned char    	publicKey[MAX_Q_LEN_BYTES]; /* beginning of the public key Q         */
} EccKeyTokenPublic;

typedef struct tdEccKeyTokenPrivate
{
    unsigned char    	sectionId;
    unsigned char    	version;
    uint16_t   		sectionLength;         /* Length of the ECC private key section   */
    unsigned char    	wrappingMethod;        /* Wrapping method: 0 - clear        @f3a  */
    /*                  1 - AESKW        @f3a  */
    /*                  2 - CBC wrap     @f3a  */
    unsigned char    	hashType;              /* Hash used in wrapping: 1 - SHA224 @f3a  */
    /*                        2 - SHA256 @f3a  */
    /*                        4 - SHA384 @f3a  */
    /*                        8 - SHA512 @f3a  */
    uint16_t   		reserved;
    unsigned char    	keyUsage;              /* key usage byte                          */
    unsigned char    	curveType;             /* curve type:  Prime or Brainpool         */
    unsigned char    	keyFormatSecurity;     /* key format and security flags           */
    unsigned char    	reserved2;
    uint16_t   		pLength;               /* length of p in bits                     */
    uint16_t   		IBMAssocDataLen;       /* length of IBM Assoc. data in bytes  @f1c*/
    unsigned char    	mkvp[MKVP_LENGTH];     /* master key verification pattern         */
    unsigned char    	objProtection[ECC_OBJ_PROTECTION_LEN]; /* object protection key   */
    uint16_t   		aDataLen;              /* associated data length                  */
    uint16_t   		formattedDataLen;      /* formatted data length                   */
} EccKeyTokenPrivate;



long getPKA96EccPublicKey(EccKeyTokenPublic *eccKeyTokenPublic,
                          long keyTokenLength,
                          unsigned char *keyToken);
long parsePKA96EccKeyTokenHeader(EccKeyTokenHeader *eccKeyTokenHeader,
                                 long *keyTokenLength,
                                 unsigned char **keyToken);
long parsePKA96EccKeyTokenPublicKey(EccKeyTokenPublic *eccKeyTokenPublic,
                                    long *pubKeyTokenLength,
                                    unsigned char **pubKeyToken);
long parsePKA96EccKeyTokenPrivateKey(EccKeyTokenPrivate *eccKeyTokenPrivate,
                                     long *keyTokenLength,
                                     unsigned char **keyToken);

/*
  Debug Print Functions
*/

void printPKA96EccKeyTokenHeader(EccKeyTokenHeader *eccKeyTokenHeader);
void printPKA96EccKeyTokenPublicKey(EccKeyTokenPublic *eccKeyTokenPublic);
void printPKA96EccKeyTokenPrivateKey(EccKeyTokenPrivate *eccKeyTokenPrivate);

void printEccSectionID(unsigned char sectionId);
void printWrappingMethod(unsigned char wrappingMethod);
void printHashType(unsigned char hashType);
void printKeyUsage(unsigned char keyUsage);
void printCurveType(unsigned char curveType);
void printKeyFormatSecurity(unsigned char keyFormatSecurity);

#endif
