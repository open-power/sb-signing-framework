/* Copyright 2019 IBM Corp.
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

#ifndef CCA_STRUCTURES_H
#define CCA_STRUCTURES_H

/* tokenID */
#define PKA_EXTERNAL_TOKEN		0x1E
#define PKA_INTERNAL_TOKEN		0x1F

/* sectionID */
#define RSA_PRIVATE_KEY_1024_EXTERNAL	0x02
#define RSA_PUBLIC_SECTION		0x04
#define RSA_PRIVATE_KEY_2048_CRT_DEP	0x05	/* deprecated */
#define RSA_PRIVATE_KEY_1024_INTERNAL	0x06
#define RSA_PRIVATE_KEY_CRT		0x08

/* keyFormat */
#define RSA_EXTERNAL_UNENCRYPTED	0x40
#define RSA_EXTERNAL_ENCRYPTED		0x42
#define RSA_INTERNAL_ENCRYPTED		0x08

/* tokenType */
#define RSA_TOKEN_EXTERNAL			0x00
#define RSA_TOKEN_INTERNAL_IMPORT_CLEARTEXT	0x21
#define RSA_TOKEN_INTERNAL_IMPORT_CIPHERTEXT	0x22
#define RSA_TOKEN_INTERNAL_GEN_REGEN		0x23
#define RSA_TOKEN_INTERNAL_GEN_RANDOM		0x24

/* keyUsageFlag */
#define SIG_ONLY			0x00
#define KM_ONLY				0xc0
#define KEY_MGMT			0x80

/* Application hard coded sizes

 */

#define E_SIZE		4		/* bytes, exponent maximum, typically 010001 */
#define N_SIZE		256		/* bytes, public modulus for 2048 bit key */
#define N_SIZE_MAX	512		/* bytes, public modulus for 4096 bit key */
#define N_BIT_SIZE	2048		/* bits, public modulus for 2048 bit key */
#define N_BIT_SIZE_MAX	4096		/* bits, public modulus for 4096 bit key */
#define SHA1_SIZE	20
#define SHA256_SIZE	32
#define SHA384_SIZE	48
#define SHA512_SIZE	64

/* PKA96 RSA token header */

typedef struct tdRsaKeyTokenHeader
{
    unsigned char	tokenId;
    unsigned char	version;
    unsigned short 	tokenLength;
    unsigned long	reserved;
} RsaKeyTokenHeader;

typedef struct tdRsaKeyTokenPublic {
    unsigned char 	sectionId;
    unsigned char 	version;
    unsigned short 	sectionLength;	/* Length of the RSA public key section */
    unsigned char 	reserved[2];
    unsigned short 	eLength;
    unsigned short 	nBitLength;
    unsigned short 	nByteLength;	/* Prime divisor length in bytes */
    unsigned char 	e[E_SIZE];
    unsigned char 	n[N_SIZE_MAX];
} RsaKeyTokenPublic ;

typedef struct tdRsaKeyTokenPrivate {
    unsigned char	sectionId;
    unsigned char	version;
    unsigned short	sectionLength;
    unsigned char 	sha1HashPrivKey[SHA1_SIZE];
    unsigned long	reserved0;
    unsigned char	keyFormat;
    unsigned char	tokenType;
    unsigned char	sha1HashOptional[SHA1_SIZE];
    unsigned char	keyUsageFlag;
    unsigned char	reserved1[3];
    unsigned short	pLength;
    unsigned short	qLength;
    unsigned short	dpLength;
    unsigned short	dqLength;
    unsigned short	uLength;
    unsigned short	nLength;
    unsigned short	reserved2;
    unsigned short	reserved3;
    unsigned short	padLength;
    unsigned long	reserved4;
    unsigned char	reserved5[16];
    unsigned char	reserved6[32];
    unsigned char	confounder[8];
    /* p */
    /* q */
    /* dp */
    /* dq */
    /* u */
    /* pad */
    /* n */
} RsaKeyTokenPrivate;


long getPKA96PublicKey(RsaKeyTokenPublic *rsaKeyTokenPublic,
                       long keyTokenLength,
                       unsigned char *keyToken,
                       unsigned int bitSize);
long parsePKA96KeyTokenHeader(RsaKeyTokenHeader *rsaKeyTokenHeader,
                              long *keyTokenLength,
                              unsigned char **keyToken);
long parsePKA96KeyTokenPublicKey(RsaKeyTokenPublic *rsaKeyTokenPublic,
                                 long *pubKeyTokenLength,
                                 unsigned char **pubKeyToken,
                                 int hasPrivKey);
long parsePKA96KeyTokenPrivateKey(RsaKeyTokenPublic *rsaKeyTokenPublic,
                                  RsaKeyTokenPrivate *rsaKeyTokenPrivate,
                                  long *keyTokenLength,
                                  unsigned char **keyToken,
                                  unsigned int bitSize);

/*
  Debug Print Functions
*/

void printPKA96KeyTokenHeader(RsaKeyTokenHeader *rsaKeyTokenHeader);
void printPKA96KeyTokenPublicKey(RsaKeyTokenPublic *rsaKeyTokenPublic);
void printPKA96KeyTokenPrivateKey(RsaKeyTokenPrivate *rsaKeyTokenPrivate);

void printSectionID(unsigned char sectionId);
void printKeyFormat(unsigned char keyFormat);
void printTokenType (unsigned char tokenType);
void printKeyUsageFlag(unsigned char keyUsageFlag);

#endif
