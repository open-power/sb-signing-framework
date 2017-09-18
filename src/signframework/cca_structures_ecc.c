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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Linux specific */
#include <sys/types.h>
#include <netinet/in.h>

/* local */
#include "cca_structures_ecc.h"
#include "utils.h"
#include "debug.h"

extern FILE* messageFile;
extern int verbose;

/* local functions */

long validatePKA96EccKeyToken(EccKeyTokenPrivate *eccKeyTokenPrivate,
			      EccKeyTokenPublic *eccKeyTokenPublic);

/* getPKA96EccPublicKey() returns a CCA EccKeyTokenPublic structure with the members filled in from the
   binary PKA96 key token.

*/

long getPKA96EccPublicKey(EccKeyTokenPublic *eccKeyTokenPublic,
			  long keyTokenLength,
			  unsigned char *keyToken)
{
    long		rc = 0;
    EccKeyTokenHeader	eccKeyTokenHeader;
    EccKeyTokenPrivate	eccKeyTokenPrivate;
    int			foundPrivateSection = FALSE;
    
    /* parse the PKA96 key token header */
    if (rc == 0) {
	rc = parsePKA96EccKeyTokenHeader(&eccKeyTokenHeader,
					 &keyTokenLength,
					 &keyToken);
    }
    /* if there's a private key section, parse it just to bypass it */
    if (rc == 0) {
	if ((keyTokenLength > 0) && (*keyToken == ECC_PRIVATE_SECTION)) {
	    foundPrivateSection = TRUE;
	    rc = parsePKA96EccKeyTokenPrivateKey(&eccKeyTokenPrivate,
						 &keyTokenLength,
						 &keyToken);
	}
    }
    /* parse the public key */
    if (rc == 0) {
	rc = parsePKA96EccKeyTokenPublicKey(eccKeyTokenPublic,
					    &keyTokenLength,
					    &keyToken);
    }
    if ((rc == 0) && foundPrivateSection) {
	rc = validatePKA96EccKeyToken(&eccKeyTokenPrivate,
				      eccKeyTokenPublic);
    }
    if (rc == 0) {
	if (verbose) PrintAll(messageFile,
			      "getPKA96EccEccPublicKey: public key",
			      eccKeyTokenPublic->qLen, eccKeyTokenPublic->publicKey);
    }
    return rc;
}

/* parsePKA96EccKeyTokenHeader() returns a CCA EccKeyTokenHeader structure with the members filled in
   from the binary PKA96 key token.

   keyTokenLength is decremented and keyToken is incremented as binary data is consumed.
*/

long parsePKA96EccKeyTokenHeader(EccKeyTokenHeader *eccKeyTokenHeader,
				 long *keyTokenLength,
				 unsigned char **keyToken)
{
    /* tokenId */
    if (*keyTokenLength < 1) {
	fprintf(messageFile,
		"parsePKA96EccKeyTokenHeader: Error parsing tokenId \n");
	return -1;
    }
    eccKeyTokenHeader->tokenId = **keyToken;
    *keyToken += 1;
    *keyTokenLength -= 1;
    if (eccKeyTokenHeader->tokenId != PKA_INTERNAL_TOKEN) {
	fprintf(messageFile,
		"parsePKA96EccKeyTokenHeader: Error, unknown tokenId %02x\n",
		eccKeyTokenHeader->tokenId);
	return -1;
    }
    /* version */
    if (*keyTokenLength < 1) {
	fprintf(messageFile,
		"parsePKA96EccKeyTokenHeader: Error parsing version\n");
	return -1;
    }
    eccKeyTokenHeader->version = **keyToken;
    *keyToken += 1;
    *keyTokenLength -= 1;
    if (eccKeyTokenHeader->version != 0) {
	fprintf(messageFile,
		"parsePKA96EccKeyTokenHeader: Error, unknown version %02x\n",
		eccKeyTokenHeader->version);
	return -1;
    }
    /* tokenLength */
    if (*keyTokenLength < 2) {
	fprintf(messageFile,
		"parsePKA96EccKeyTokenHeader: Error parsing tokenLength \n");
	return -1;
    }
    eccKeyTokenHeader->tokenLength = ntohs(*(unsigned short *)*keyToken);
    *keyToken += 2;
    *keyTokenLength -= 2;
    /* reserved */
    if (*keyTokenLength < 4) {
	fprintf(messageFile,
		"parsePKA96EccKeyTokenHeader: Error parsing reserved\n");
	return -1;
    }
    eccKeyTokenHeader->reserved = ntohl(*(unsigned long *)*keyToken);
    *keyToken += 4;
    *keyTokenLength -= 4;
    if (eccKeyTokenHeader->reserved != 0) {
	fprintf(messageFile,
		"parsePKA96EccKeyTokenHeader: Error, reserved %08x\n",
		eccKeyTokenHeader->reserved);
	return -1;
    }
    if (verbose) printPKA96EccKeyTokenHeader(eccKeyTokenHeader);
    return 0;
}

/* parsePKA96EccKeyTokenPublicKey() returns a CCA EccKeyTokenPublic structure
   with the members filled in from the binary PKA96 public key token.

   keyTokenLength is decremented and keyToken is incremented as binary data is consumed.
*/

long parsePKA96EccKeyTokenPublicKey(EccKeyTokenPublic *eccKeyTokenPublic,
				    long *pubKeyTokenLength,
				    unsigned char **pubKeyToken)
{
    /* sectionId */
    if (*pubKeyTokenLength < 1) {
	fprintf(messageFile,
		"parsePKA96EccKeyTokenPublicKey: Error parsing sectionId\n");
	return -1;
    }
    eccKeyTokenPublic->sectionId = **pubKeyToken;
    *pubKeyToken += 1;
    *pubKeyTokenLength -= 1;
    if (eccKeyTokenPublic->sectionId != ECC_PUBLIC_SECTION) {
	fprintf(messageFile,
		"parsePKA96EccKeyTokenPublicKey: Error, unknown sectionId %02x\n",
		eccKeyTokenPublic->sectionId);
	return -1;
    }
    /* version */
    if (*pubKeyTokenLength < 1) {
	fprintf(messageFile,
		"parsePKA96EccKeyTokenPublicKey: Error parsing version\n");
	return -1;
    }
    eccKeyTokenPublic->version = **pubKeyToken;
    *pubKeyToken += 1;
    *pubKeyTokenLength -= 1;
    if (eccKeyTokenPublic->version != 0) {
	fprintf(messageFile,
		"parsePKA96EccKeyTokenPublicKey: Error, unknown version %02x\n",
		eccKeyTokenPublic->version);
	return -1;
    }
    /* sectionLength */
    if (*pubKeyTokenLength < 2) {
	fprintf(messageFile,
		"parsePKA96EccKeyTokenPublicKey: Error parsing sectionLength\n");
	return -1;
    }
    eccKeyTokenPublic->sectionLength = ntohs(*(unsigned short *)*pubKeyToken);
    *pubKeyToken += 2;
    *pubKeyTokenLength -= 2;
    /* reserved */
    if (*pubKeyTokenLength < 4) {
	fprintf(messageFile,
		"parsePKA96EccKeyTokenPublicKey: Error parsing reserved\n");
	return -1;
    }
    eccKeyTokenPublic->reserved = ntohl(*(unsigned long *)*pubKeyToken);
    *pubKeyToken += 4;
    *pubKeyTokenLength -= 4;
    if (eccKeyTokenPublic->reserved != 0) {
	fprintf(messageFile,
		"parsePKA96EccKeyTokenPublicKey: Error, reserved %08x\n",
		eccKeyTokenPublic->reserved);
	return -1;
    }
    /* curveType */
    if (*pubKeyTokenLength < 1) {
	fprintf(messageFile,
		"parsePKA96EccKeyTokenPublicKey: Error parsing curveType\n");
	return -1;
    }
    eccKeyTokenPublic->curveType = **pubKeyToken;
    *pubKeyToken += 1;
    *pubKeyTokenLength -= 1;
    if (eccKeyTokenPublic->curveType != ECC_PRIME) {
	fprintf(messageFile,
		"parsePKA96EccKeyTokenPublicKey: Error, curveType unknown %02x\n",
		eccKeyTokenPublic->curveType);
	return -1;	
    }
    /* reserved2 */
    if (*pubKeyTokenLength < 1) {
	fprintf(messageFile,
		"parsePKA96EccKeyTokenPublicKey: Error parsing reserved2\n");
	return -1;
    }
    eccKeyTokenPublic->reserved2 = **pubKeyToken;
    *pubKeyToken += 1;
    *pubKeyTokenLength -= 1;
    if (eccKeyTokenPublic->reserved2 != 0) {
	fprintf(messageFile,
		"parsePKA96EccKeyTokenPublicKey: Error, reserved2 unknown %02x\n",
		eccKeyTokenPublic->curveType);
	return -1;	
    }
    /* pLength */
    if (*pubKeyTokenLength < 2) {
	fprintf(messageFile,
		"parsePKA96EccKeyTokenPublicKey: Error parsing pLength\n");
	return -1;
    }
    eccKeyTokenPublic->pLength = ntohs(*(unsigned short *)*pubKeyToken);
    *pubKeyToken += 2;
    *pubKeyTokenLength -= 2;
    if (eccKeyTokenPublic->pLength != ECC_PRIME_521) {
	fprintf(messageFile,
		"parsePKA96EccKeyTokenPublicKey: Error, pLength %04x\n",
		eccKeyTokenPublic->pLength);
	return -1;
    }
    /* qLen */
    if (*pubKeyTokenLength < 2) {
	fprintf(messageFile,
		"parsePKA96EccKeyTokenPublicKey: Error parsing qLen\n");
	return -1;
    }
    eccKeyTokenPublic->qLen = ntohs(*(unsigned short *)*pubKeyToken);
    *pubKeyToken += 2;
    *pubKeyTokenLength -= 2;
    if (eccKeyTokenPublic->qLen != MAX_Q_LEN_BYTES) {
	fprintf(messageFile,
		"parsePKA96EccKeyTokenPublicKey: Error, qLen %04x\n",
		eccKeyTokenPublic->qLen);
	return -1;
    }
    /* publicKey */
    if (*pubKeyTokenLength < MAX_Q_LEN_BYTES) {
	fprintf(messageFile,
		"parsePKA96EccKeyTokenPublicKey: Error parsing publicKey\n");
	return -1;
    }
    memcpy(eccKeyTokenPublic->publicKey, *pubKeyToken, MAX_Q_LEN_BYTES);
    *pubKeyToken += MAX_Q_LEN_BYTES;
    *pubKeyTokenLength -= MAX_Q_LEN_BYTES;
    if (verbose) printPKA96EccKeyTokenPublicKey(eccKeyTokenPublic);
    return 0;
}

/* parsePKA96EccKeyTokenPrivateKey() returns CCA the EccKeyTokenPrivate structure
   with the members filled in from the binary PKA96 key token.

   keyTokenLength is decremented and keyToken is incremented as binary data is consumed.
*/

long parsePKA96EccKeyTokenPrivateKey(EccKeyTokenPrivate *eccKeyTokenPrivate,
				     long *keyTokenLength,
				     unsigned char **keyToken)
{
    /* sectionId */
    if (*keyTokenLength < 1) {
	fprintf(messageFile,
		"parsePKA96EccKeyTokenPrivateKey: Error parsing sectionId\n");
	return -1;
    }
    eccKeyTokenPrivate->sectionId = **keyToken;
    *keyToken += 1;
    *keyTokenLength -= 1;
    if (eccKeyTokenPrivate->sectionId != ECC_PRIVATE_SECTION) {
	fprintf(messageFile,
		"parsePKA96EccKeyTokenPrivateKey: Error, unknown sectionId %02x\n",
		eccKeyTokenPrivate->sectionId);
	return -1;
    }
    /* version */
    if (*keyTokenLength < 1) {
	fprintf(messageFile,
		"parsePKA96EccKeyTokenPrivateKey: Error parsing version\n");
	return -1;
    }
    eccKeyTokenPrivate->version = **keyToken;
    *keyToken += 1;
    *keyTokenLength -= 1;
    if (eccKeyTokenPrivate->version != ECC_PRIV_VERSION_00) {
	fprintf(messageFile,
		"parsePKA96EccKeyTokenPrivateKey: Error, unknown version %02x\n",
		eccKeyTokenPrivate->version);
	return -1;
    }
    /* sectionLength */
    if (*keyTokenLength < 2) {
	fprintf(messageFile,
		"parsePKA96EccKeyTokenPrivateKey: Error parsing sectionLength\n");
	return -1;
    }
    eccKeyTokenPrivate->sectionLength = ntohs(*(unsigned short *)*keyToken);
    *keyToken += 2;
    *keyTokenLength -= 2;
    if (eccKeyTokenPrivate->sectionLength > (*keyTokenLength + 4)) {	/* char, char, short */
	fprintf(messageFile,
		"parsePKA96EccKeyTokenPrivateKey: Error, sectionLength %04x too large\n",
		eccKeyTokenPrivate->sectionLength );
	return -1;
    }
    /* wrappingMethod */
    if (*keyTokenLength < 1) {
	fprintf(messageFile,
		"parsePKA96EccKeyTokenPrivateKey: Error parsing wrappingMethod\n");
	return -1;
    }
    eccKeyTokenPrivate->wrappingMethod = **keyToken;
    *keyToken += 1;
    *keyTokenLength -= 1;
    if (eccKeyTokenPrivate->wrappingMethod != ECC_WRAP_METH_AESKW) {
	fprintf(messageFile,
		"parsePKA96EccKeyTokenPrivateKey: Error, unknown wrappingMethod %02x\n",
		eccKeyTokenPrivate->wrappingMethod);
	return -1;
    }
    /* hashType */
    if (*keyTokenLength < 1) {
	fprintf(messageFile,
		"parsePKA96EccKeyTokenPrivateKey: Error parsing hashType\n");
	return -1;
    }
    eccKeyTokenPrivate->hashType = **keyToken;
    *keyToken += 1;
    *keyTokenLength -= 1;
    if ((eccKeyTokenPrivate->hashType != ECC_HASH_SHA224) &&
	(eccKeyTokenPrivate->hashType != ECC_HASH_SHA256) &&
	(eccKeyTokenPrivate->hashType != ECC_HASH_SHA384) &&
	(eccKeyTokenPrivate->hashType != ECC_HASH_SHA512)) {
	fprintf(messageFile,
		"parsePKA96EccKeyTokenPrivateKey: Error, unknown hashType %02x\n",
		eccKeyTokenPrivate->hashType);
	return -1;
    }
    /* reserved */
    if (*keyTokenLength < 2) {
	fprintf(messageFile,
		"parsePKA96EccKeyTokenPrivateKey: Error parsing reserved\n");
	return -1;
    }
    eccKeyTokenPrivate->reserved = ntohs(*(unsigned short *)*keyToken);
    *keyToken += 2;
    *keyTokenLength -= 2;
    if (eccKeyTokenPrivate->reserved != 0x0000) {
	fprintf(messageFile,
		"parsePKA96EccKeyTokenPrivateKey: Error, reserved %04x\n",
		eccKeyTokenPrivate->reserved);
	return -1;
    }
    /* keyUsage */
    if (*keyTokenLength < 1) {
	fprintf(messageFile,
		"parsePKA96EccKeyTokenPrivateKey: Error parsing keyUsage\n");
	return -1;
    }
    eccKeyTokenPrivate->keyUsage = **keyToken;
    *keyToken += 1;
    *keyTokenLength -= 1;
    if (eccKeyTokenPrivate->keyUsage != ECC_SIGNATURE_USE_ONLY) {
	fprintf(messageFile,
		"parsePKA96EccKeyTokenPrivateKey: Error, unknown keyUsage %02x\n",
		eccKeyTokenPrivate->keyUsage);
	return -1;
    }
    /* curveType */
    if (*keyTokenLength < 1) {
	fprintf(messageFile,
		"parsePKA96EccKeyTokenPrivateKey: Error parsing curveType\n");
	return -1;
    }
    eccKeyTokenPrivate->curveType = **keyToken;
    *keyToken += 1;
    *keyTokenLength -= 1;
    if (eccKeyTokenPrivate->curveType != ECC_PRIME) {
	fprintf(messageFile,
		"parsePKA96EccKeyTokenPrivateKey: Error, curveType unknown %02x\n",
		eccKeyTokenPrivate->curveType);
	return -1;	
    }
    /* keyFormatSecurity */
    if (*keyTokenLength < 1) {
	fprintf(messageFile,
		"parsePKA96EccKeyTokenPrivateKey: Error parsing keyFormatSecurity\n");
	return -1;
    }
    eccKeyTokenPrivate->keyFormatSecurity = **keyToken;
    *keyToken += 1;
    *keyTokenLength -= 1;
    if (eccKeyTokenPrivate->keyFormatSecurity != ECC_INTERNAL_ENCRYPTED) {
	fprintf(messageFile,
		"parsePKA96EccKeyTokenPrivateKey: Error, tokenType unknown %02x\n",
		eccKeyTokenPrivate->keyFormatSecurity);
	return -1;	
    }
    /* reserved2 */
    if (*keyTokenLength < 1) {
	fprintf(messageFile,
		"parsePKA96EccKeyTokenPrivateKey: Error parsing reserved2\n");
	return -1;
    }
    eccKeyTokenPrivate->reserved2 = **keyToken;
    *keyToken += 1;
    *keyTokenLength -= 1;
    if (eccKeyTokenPrivate->reserved2 != 0x00) {
	fprintf(messageFile,
		"parsePKA96EccKeyTokenPrivateKey: Error, tokenType unknown %02x\n",
		eccKeyTokenPrivate->reserved2);
	return -1;	
    }
    /* pLength */
    if (*keyTokenLength < 2) {
	fprintf(messageFile,
		"parsePKA96EccKeyTokenPrivateKey: Error parsing pLength\n");
	return -1;
    }
    eccKeyTokenPrivate->pLength = ntohs(*(unsigned short *)*keyToken);
    *keyToken += 2;
    *keyTokenLength -= 2;
    if (eccKeyTokenPrivate->pLength != ECC_PRIME_521) {
	fprintf(messageFile,
		"parsePKA96EccKeyTokenPrivateKey: Error, pLength %04x\n",
		eccKeyTokenPrivate->pLength);
	return -1;
    }
    /* IBMAssocDataLen */
    if (*keyTokenLength < 2) {
	fprintf(messageFile,
		"parsePKA96EccKeyTokenPrivateKey: Error parsing IBMAssocDataLen\n");
	return -1;
    }
    eccKeyTokenPrivate->IBMAssocDataLen = ntohs(*(unsigned short *)*keyToken);
    *keyToken += 2;
    *keyTokenLength -= 2;
    if (eccKeyTokenPrivate->IBMAssocDataLen < 16) {
	fprintf(messageFile,
		"parsePKA96EccKeyTokenPrivateKey: Error, IBMAssocDataLen %04x\n",
		eccKeyTokenPrivate->IBMAssocDataLen );
	return -1;
    }
    /* mkvp */
    if (*keyTokenLength < MKVP_LENGTH) {
	fprintf(messageFile,
		"parsePKA96EccKeyTokenPrivateKey: Error parsing mkvp\n");
	return -1;
    }
    memcpy(eccKeyTokenPrivate->mkvp, *keyToken, MKVP_LENGTH);
    *keyToken += MKVP_LENGTH;
    *keyTokenLength -= MKVP_LENGTH;
    /* objProtection */
    if (*keyTokenLength < ECC_OBJ_PROTECTION_LEN) {
	fprintf(messageFile,
		"parsePKA96EccKeyTokenPrivateKey: Error parsing \n");
	return -1;
    }
    memcpy(eccKeyTokenPrivate->objProtection, *keyToken, ECC_OBJ_PROTECTION_LEN);
    *keyToken += ECC_OBJ_PROTECTION_LEN;
    *keyTokenLength -= ECC_OBJ_PROTECTION_LEN;
    /* aDataLen */
    if (*keyTokenLength < 2) {
	fprintf(messageFile,
		"parsePKA96EccKeyTokenPrivateKey: Error parsing aDataLen\n");
	return -1;
    }
    eccKeyTokenPrivate->aDataLen = ntohs(*(unsigned short *)*keyToken);
    *keyToken += 2;
    *keyTokenLength -= 2;
    if (eccKeyTokenPrivate->aDataLen > eccKeyTokenPrivate->IBMAssocDataLen) {
	fprintf(messageFile,
		"parsePKA96EccKeyTokenPrivateKey: Error, aDataLen %04x > IBMAssocDataLen %04x\n",
		eccKeyTokenPrivate->aDataLen, eccKeyTokenPrivate->IBMAssocDataLen );
	return -1;
    }
    /* formattedDataLen */
    if (*keyTokenLength < 2) {
	fprintf(messageFile,
		"parsePKA96EccKeyTokenPrivateKey: Error parsing formattedDataLen\n");
	return -1;
    }
    eccKeyTokenPrivate->formattedDataLen = ntohs(*(unsigned short *)*keyToken);
    *keyToken += 2;
    *keyTokenLength -= 2;
    /* skip the aData part */
    if (*keyTokenLength < eccKeyTokenPrivate->aDataLen) {
	fprintf(messageFile,
		"parsePKA96EccKeyTokenPrivateKey: Error parsing aData\n");
	return -1;
    }
    *keyToken += eccKeyTokenPrivate->aDataLen;
    *keyTokenLength -= eccKeyTokenPrivate->aDataLen;
    /* skip the encrypted part */
    if (*keyTokenLength < eccKeyTokenPrivate->formattedDataLen) {
	fprintf(messageFile,
		"parsePKA96EccKeyTokenPrivateKey: Error parsing formattedDataLen\n");
	return -1;
    }
    *keyToken += eccKeyTokenPrivate->formattedDataLen;
    *keyTokenLength -= eccKeyTokenPrivate->formattedDataLen;
    if (verbose) printPKA96EccKeyTokenPrivateKey(eccKeyTokenPrivate);
    return 0;
}

/* validatePKA96EccKeyToken() validates the public section against the private section
 */

long validatePKA96EccKeyToken(EccKeyTokenPrivate *eccKeyTokenPrivate,
			      EccKeyTokenPublic *eccKeyTokenPublic)
{
    long		rc = 0;

    if (rc == 0) {
	if (eccKeyTokenPrivate->curveType != eccKeyTokenPublic->curveType) {
	    fprintf(messageFile,
		    "validatePKA96EccKeyToken: Error, curveType inconsistent %02x %02x\n",
		    eccKeyTokenPrivate->curveType, eccKeyTokenPublic->curveType);
	    rc = -1;
	}
    }
    if (rc == 0) {
	if (eccKeyTokenPrivate->pLength != eccKeyTokenPublic->pLength) {
	    fprintf(messageFile,
		    "validatePKA96EccKeyToken: Error, pLength inconsistent %02x %02x\n",
		    eccKeyTokenPrivate->pLength, eccKeyTokenPublic->pLength);
	    rc = -1;
	}
    }
    return rc;
}

/*
  Debug Print Functions
*/

/* printPKA96EccKeyTokenHeader() prints the EccKeyTokenHeader structure in human readable form

 */

void printPKA96EccKeyTokenHeader(EccKeyTokenHeader *eccKeyTokenHeader)
{
    if (verbose) fprintf(messageFile,
			 "\tToken Header:\n");
    /* tokenId */
    switch (eccKeyTokenHeader->tokenId) {
      case PKA_EXTERNAL_TOKEN:
	if (verbose) fprintf(messageFile,
			     "\t\ttokenId: External token\n");
	break;
      case PKA_INTERNAL_TOKEN:
	if (verbose) fprintf(messageFile,
			     "\t\ttokenId: Internal token\n");
	break;
      default:
	if (verbose) fprintf(messageFile,
			     "\t\ttokenId: Unknown %02x\n",
			     eccKeyTokenHeader->tokenId);
    }
    /* version */
    if (verbose) fprintf(messageFile,
			 "\t\tversion: %02x\n", eccKeyTokenHeader->version);
    /* tokenLength */
    if (verbose) fprintf(messageFile,
			 "\t\ttokenLength: %04hx %hu\n",
			 eccKeyTokenHeader->tokenLength, eccKeyTokenHeader->tokenLength);
    /* reserved */
    if (verbose) fprintf(messageFile,
			 "\t\treserved: %08x\n", eccKeyTokenHeader->reserved);
    return;
}

/* printPKA96EccKeyTokenPublicKey() prints the EccKeyTokenPublic structure in human readable form

 */

void printPKA96EccKeyTokenPublicKey(EccKeyTokenPublic *eccKeyTokenPublic)
{
    if (verbose) fprintf(messageFile,
			 "\tToken Public Key:\n");
    /* sectionId */
    printEccSectionID(eccKeyTokenPublic->sectionId);
    /* version */
    if (verbose) fprintf(messageFile,
			 "\t\tversion: %02x\n", eccKeyTokenPublic->version);
    /* sectionLength */
    if (verbose) fprintf(messageFile,
			 "\t\tsectionLength: %04hx %hu\n",
			 eccKeyTokenPublic->sectionLength, eccKeyTokenPublic->sectionLength);
    /* reserved */
    if (verbose) fprintf(messageFile,
			 "\t\treserved: %08x\n",
			 eccKeyTokenPublic->reserved);
    /* curveType */
    printCurveType(eccKeyTokenPublic->curveType);
    /* reserved2 */
    if (verbose) fprintf(messageFile,
			 "\t\treserved: %02x\n",
			 eccKeyTokenPublic->reserved2);
    /* pLength */
    if (verbose) fprintf(messageFile,
			 "\t\tpLength: %04hx %hu\n",
			 eccKeyTokenPublic->pLength, eccKeyTokenPublic->pLength);
    /* publicKey */
    if (verbose) {
	PrintAll(messageFile,
		 "\t\tpublicKey\n", eccKeyTokenPublic->qLen, eccKeyTokenPublic->publicKey);
    }
    return;
}

/* printPKA96EccKeyTokenPrivateKey() prints the EccKeyTokenPrivate structure in human readable form

 */

void printPKA96EccKeyTokenPrivateKey(EccKeyTokenPrivate *eccKeyTokenPrivate)
{
    if (verbose) fprintf(messageFile,
			 "\tECC Token Private Key:\n");
    
    /* sectionId */
    printEccSectionID(eccKeyTokenPrivate->sectionId);
    /* version */
    if (verbose) fprintf(messageFile,
			 "\t\tversion: %02x\n", eccKeyTokenPrivate->version);
    /* sectionLength */
    if (verbose) fprintf(messageFile,
			 "\t\tsectionLength: %04hx %hu\n",
			 eccKeyTokenPrivate->sectionLength, eccKeyTokenPrivate->sectionLength);
    /* wrappingMethod */
    printWrappingMethod(eccKeyTokenPrivate->wrappingMethod);
    /* hashType */
    printHashType(eccKeyTokenPrivate->hashType);
    /* reserved */
    if (verbose) fprintf(messageFile,
			 "\t\treserved: %04hx %hu\n",
			 eccKeyTokenPrivate->reserved, eccKeyTokenPrivate->reserved);
    /* keyUsage */
    printKeyUsage(eccKeyTokenPrivate->keyUsage);
    /* curveType */
    printCurveType(eccKeyTokenPrivate->curveType);
    /* keyFormatSecurity */
    printKeyFormatSecurity(eccKeyTokenPrivate->keyFormatSecurity);
    /* reserved2 */
    if (verbose) fprintf(messageFile,
			 "\t\treserved2: %04hx %hu\n",
			 eccKeyTokenPrivate->reserved2, eccKeyTokenPrivate->reserved2);
    /* pLength */
    if (verbose) fprintf(messageFile,
			 "\t\tpLength: %04hx %hu\n",
			 eccKeyTokenPrivate->pLength, eccKeyTokenPrivate->pLength);
    /* IBMAssocDataLen */
    if (verbose) fprintf(messageFile,
			 "\t\tIBMAssocDataLength: %04hx %hu\n",
			 eccKeyTokenPrivate->IBMAssocDataLen, eccKeyTokenPrivate->IBMAssocDataLen);
    /* mkvp */
    if (verbose) fprintf(messageFile,
			 "\t\tmkvp: %02x %02x %02x %02x ... \n",
			 eccKeyTokenPrivate->mkvp[0],
			 eccKeyTokenPrivate->mkvp[1],
			 eccKeyTokenPrivate->mkvp[2],
			 eccKeyTokenPrivate->mkvp[3]);
    /* objProtection */
    if (verbose) fprintf(messageFile,
			 "\t\tobjProtection: %02x %02x %02x %02x ... \n",
			 eccKeyTokenPrivate->objProtection[0],
			 eccKeyTokenPrivate->objProtection[1],
			 eccKeyTokenPrivate->objProtection[2],
			 eccKeyTokenPrivate->objProtection[3]);
    /* aDataLen */
    if (verbose) fprintf(messageFile,
			 "\t\taDataLen: %04hx %hu\n",
			 eccKeyTokenPrivate->aDataLen, eccKeyTokenPrivate->aDataLen);
    /* formattedDataLen */
    if (verbose) fprintf(messageFile,
			 "\t\tformattedDataLen: %04hx %hu\n",
			 eccKeyTokenPrivate->formattedDataLen, eccKeyTokenPrivate->formattedDataLen);
    return;
}
    
void printEccSectionID(unsigned char sectionId)
{
    if (verbose) fprintf(messageFile,
			 "\t\tsectionId: ");
    switch (sectionId) {
      case ECC_PRIVATE_SECTION:
	if (verbose) fprintf(messageFile,
			     "ECC_PRIVATE_SECTION\n");
	break;
      case ECC_PUBLIC_SECTION:
	if (verbose) fprintf(messageFile,
			     "ECC_PUBLIC_SECTION\n");
	break;
      default:
	if (verbose) fprintf(messageFile,
			     "Unknown %02x\n", sectionId);
    }
    return;
}

void printWrappingMethod(unsigned char wrappingMethod)
{
    if (verbose) fprintf(messageFile,
			 "\t\twrappingMethod: ");
    switch (wrappingMethod) {
      case ECC_WRAP_METH_CLEAR:
	if (verbose) fprintf(messageFile,
			     "ECC_WRAP_METH_CLEAR\n");
	break;
      case ECC_WRAP_METH_AESKW:
	if (verbose) fprintf(messageFile,
			     "ECC_WRAP_METH_AESKW\n");
	break;
      case ECC_WRAP_METH_CBC:
	if (verbose) fprintf(messageFile,
			     "ECC_WRAP_METH_CBC\n");
	break;
      default:
	if (verbose) fprintf(messageFile,
			     "Unknown %02x\n", wrappingMethod);
    }
    return;
}

void printHashType(unsigned char hashType)
{
    if (verbose) fprintf(messageFile,
			 "\t\thashType: ");
    switch (hashType) {
      case ECC_HASH_NONE:
	if (verbose) fprintf(messageFile,
			     "ECC_HASH_NONE\n");
	break;
      case ECC_HASH_SHA224:
	if (verbose) fprintf(messageFile,
			     "ECC_HASH_SHA224\n");
	break;
      case ECC_HASH_SHA256:
	if (verbose) fprintf(messageFile,
			     "ECC_HASH_SHA256\n");
	break;
      case ECC_HASH_SHA384:
	if (verbose) fprintf(messageFile,
			     "ECC_HASH_SHA384\n");
	break;
      case ECC_HASH_SHA512:
	if (verbose) fprintf(messageFile,
			     "ECC_HASH_SHA512\n");
	break;
      default:
	if (verbose) fprintf(messageFile,
			     "Unknown %02x\n", hashType);
    }
    return;
}

void printKeyUsage(unsigned char keyUsage)
{
    if (verbose) fprintf(messageFile,
			 "\t\tkeyUsage: ");
    switch (keyUsage) {
      case ECC_KEY_MGMT_ONLY:
	if (verbose) fprintf(messageFile,
			     "ECC_KEY_MGMT_ONLY\n");
       break;
      case ECC_KEY_DIST_AND_SIGN:
	if (verbose) fprintf(messageFile,
			     "ECC_KEY_DIST_AND_SIGN\n");
	break;
      case ECC_SIGNATURE_USE_ONLY:
	if (verbose) fprintf(messageFile,
			     "ECC_SIGNATURE_USE_ONLY\n");
	break;
      case ECC_TRANSLATE:
	if (verbose) fprintf(messageFile,
			     "ECC_TRANSLATE\n");
	break;
      default:
	if (verbose) fprintf(messageFile,
			     "Unknown %02x\n", keyUsage);
    }
    return;
}

void printCurveType(unsigned char curveType)
{
    if (verbose) fprintf(messageFile,
			 "\t\tcurveType: ");
    switch (curveType) {
      case ECC_PRIME:
	if (verbose) fprintf(messageFile,
			     "ECC_PRIME\n");
	break;
      case ECC_BRAINPOOL:
	if (verbose) fprintf(messageFile,
			     "ECC_BRAINPOOL\n");
	break;
     default:
	if (verbose) fprintf(messageFile,
			     "Unknown %02x\n", curveType);
    }
    return;
}

void printKeyFormatSecurity(unsigned char keyFormatSecurity)
{
    if (verbose) fprintf(messageFile,
			 "\t\tkeyFormatSecurity: ");
    switch (keyFormatSecurity) {
      case ECC_INTERNAL_ENCRYPTED:
	if (verbose) fprintf(messageFile,
			     "ECC_INTERNAL_ENCRYPTED\n");
	break;
      case ECC_EXTERNAL:
	if (verbose) fprintf(messageFile,
			     "ECC_EXTERNAL\n");
	break;
      case ECC_EXTERNAL_ENCRYPTED:
	if (verbose) fprintf(messageFile,
			     "ECC_EXTERNAL_ENCRYPTED\n");
	break;
      default:
	if (verbose) fprintf(messageFile,
			     "Unknown %02x\n", keyFormatSecurity);
    }
    return;
}
