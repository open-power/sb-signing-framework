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

/* AIX specific */
#include <sys/types.h>
#include <netinet/in.h>

/* local */
#include "cca_structures.h"
#include "utils.h"
#include "debug.h"

extern FILE* messageFile;
extern int verbose;

/* getPKA96PublicKey() returns a CCA RsaKeyTokenPublic structure with the members filled in from the
   binary PKA96 key token.

*/

long getPKA96PublicKey(RsaKeyTokenPublic *rsaKeyTokenPublic,
                       long keyTokenLength,
                       unsigned char *keyToken,
                       unsigned int bitSize)
{
    long		rc = 0;
    int			hasPrivKey;		/* boolean */
    RsaKeyTokenHeader	rsaKeyTokenHeader;
    RsaKeyTokenPrivate	rsaKeyTokenPrivate;

    /* parse the PKA96 key token header */
    if (rc == 0) {
        rc = parsePKA96KeyTokenHeader(&rsaKeyTokenHeader,
                                      &keyTokenLength,
                                      &keyToken);
    }
    /* if there's a private key section, parse it to get the public modulus n */
    if (rc == 0) {
        if ((keyTokenLength > 0) && (*keyToken == RSA_PRIVATE_KEY_CRT)) {
            rc = parsePKA96KeyTokenPrivateKey(rsaKeyTokenPublic,
                                              &rsaKeyTokenPrivate,
                                              &keyTokenLength,
                                              &keyToken,
                                              bitSize);
            hasPrivKey = TRUE;	/* flag to remember that the modulus n came from the private key */
        } else if ((keyTokenLength > 0) && (*keyToken == RSA_PRIVATE_KEY_CRT_AES_OPK)) {
            rc = parsePKA96KeyTokenPrivateKeyAesOPK(rsaKeyTokenPublic,
                                                    &rsaKeyTokenPrivate,
                                                    &keyTokenLength,
                                                    &keyToken,
                                                    bitSize);
            hasPrivKey = TRUE;	/* flag to remember that the modulus n came from the private key */

        } else {
            hasPrivKey = FALSE;
        }
    }
    /* check that the next section is a public key token */
    if (rc == 0) {
        if (keyTokenLength == 0) {
            if (verbose) fprintf(messageFile,
                                 "getPKA96PublicKey: Error, no public key section\n");
            return -1;
        }
    }
    /* parse the public key to get e and possibly n

       If the key token is a public key, the public modulus n and exponent are parsed here.

       If the key token is a private key, the public part has the exponent but not the modulus.
       parsePKA96KeyTokenPrivateKey() put the modulus n and its length in the structure.  It should
       not be overwritten by the zero length here.
    */
    if (rc == 0) {
        rc = parsePKA96KeyTokenPublicKey(rsaKeyTokenPublic,
                                         &keyTokenLength,
                                         &keyToken,
                                         hasPrivKey);
    }
    if (rc == 0) {
        if (verbose) PrintAll(messageFile,
                              "getPKA96PublicKey: public key",
                              rsaKeyTokenPublic->nByteLength, rsaKeyTokenPublic->n);
    }
    return rc;
}

/* parsePKA96KeyTokenHeader() returns a CCA RsaKeyTokenHeader structure with the members filled in
   from the binary PKA96 key token.

   keyTokenLength is decremented and keyToken is incremented as binary data is consumed.
*/

long parsePKA96KeyTokenHeader(RsaKeyTokenHeader *rsaKeyTokenHeader,
                              long *keyTokenLength,
                              unsigned char **keyToken)
{
    /* tokenId */
    if (*keyTokenLength < 1) {
        if (verbose) fprintf(messageFile,
                             "parsePKA96KeyTokenHeader: Error parsing tokenId \n");
        return -1;
    }
    rsaKeyTokenHeader->tokenId = **keyToken;
    *keyToken += 1;
    *keyTokenLength -= 1;
    if ((rsaKeyTokenHeader->tokenId != PKA_EXTERNAL_TOKEN) &&
        (rsaKeyTokenHeader->tokenId != PKA_INTERNAL_TOKEN)) {
        if (verbose) fprintf(messageFile,
                             "parsePKA96KeyTokenHeader: Error, unknown tokenId %02x\n",
                             rsaKeyTokenHeader->tokenId);
        return -1;
    }
    /* version */
    if (*keyTokenLength < 1) {
        if (verbose) fprintf(messageFile,
                             "parsePKA96KeyTokenHeader: Error parsing version\n");
        return -1;
    }
    rsaKeyTokenHeader->version = **keyToken;
    *keyToken += 1;
    *keyTokenLength -= 1;
    if (rsaKeyTokenHeader->version != 0) {
        if (verbose) fprintf(messageFile,
                             "parsePKA96KeyTokenHeader: Error, unknown version %02x\n",
                             rsaKeyTokenHeader->version);
        return -1;
    }
    /* tokenLength */
    if (*keyTokenLength < 2) {
        if (verbose) fprintf(messageFile,
                             "parsePKA96KeyTokenHeader: Error parsing tokenLength \n");
        return -1;
    }
    rsaKeyTokenHeader->tokenLength = ntohs(*(unsigned short *)*keyToken);
    *keyToken += 2;
    *keyTokenLength -= 2;
    /* reserved */
    if (*keyTokenLength < 4) {
        if (verbose) fprintf(messageFile,
                             "parsePKA96KeyTokenHeader: Error parsing reserved\n");
        return -1;
    }
    rsaKeyTokenHeader->reserved = ntohl(*(unsigned long *)*keyToken);
    *keyToken += 4;
    *keyTokenLength -= 4;
    if (rsaKeyTokenHeader->reserved != 0) {
        if (verbose) fprintf(messageFile,
                             "parsePKA96KeyTokenHeader: Error, reserved %08lx\n",
                             rsaKeyTokenHeader->reserved);
        return -1;
    }
    if (verbose) printPKA96KeyTokenHeader(rsaKeyTokenHeader);
    return 0;
}

/* parsePKA96KeyTokenPublicKey() returns a CCA RsaKeyTokenPublic  structure
   with the members filled in from the binary PKA96 public key token.

   If 'hasPrivKey' is FALSE, the modulus n and its length are extracted here.

   If 'hasPrivKey' is TRUE, the stream is part of a private/public key token, and the modulus n has
   already been extracted from the private key part.  Here, the modulus n length should be zero,
   and is not used.

   keyTokenLength is decremented and keyToken is incremented as binary data is consumed.
*/

long parsePKA96KeyTokenPublicKey(RsaKeyTokenPublic *rsaKeyTokenPublic,
                                 long *pubKeyTokenLength,
                                 unsigned char **pubKeyToken,
                                 int hasPrivKey)
{
    unsigned short nByteLengthPub;		/* parsed here */

    /* sectionId */
    if (*pubKeyTokenLength < 1) {
        if (verbose) fprintf(messageFile,
                             "parsePKA96KeyTokenPublicKey: Error parsing sectionId\n");
        return -1;
    }
    rsaKeyTokenPublic->sectionId = **pubKeyToken;
    *pubKeyToken += 1;
    *pubKeyTokenLength -= 1;
    if (rsaKeyTokenPublic->sectionId != RSA_PUBLIC_SECTION) {
        if (verbose) fprintf(messageFile,
                             "parsePKA96KeyTokenPublicKey: Error, unknown sectionId %02x\n",
                             rsaKeyTokenPublic->sectionId);
        return -1;
    }
    /* version */
    if (*pubKeyTokenLength < 1) {
        if (verbose) fprintf(messageFile,
                             "parsePKA96KeyTokenPublicKey: Error parsing version\n");
        return -1;
    }
    rsaKeyTokenPublic->version = **pubKeyToken;
    *pubKeyToken += 1;
    *pubKeyTokenLength -= 1;
    if (rsaKeyTokenPublic->version != 0) {
        if (verbose) fprintf(messageFile,
                             "parsePKA96KeyTokenPublicKey: Error, unknown version %02x\n",
                             rsaKeyTokenPublic->version);
        return -1;
    }
    /* sectionLength */
    if (*pubKeyTokenLength < 2) {
        if (verbose) fprintf(messageFile,
                             "parsePKA96KeyTokenPublicKey: Error parsing sectionLength\n");
        return -1;
    }
    rsaKeyTokenPublic->sectionLength = ntohs(*(unsigned short *)*pubKeyToken);
    *pubKeyToken += 2;
    *pubKeyTokenLength -= 2;
    /* reserved[2] */
    if (*pubKeyTokenLength < 2) {
        if (verbose) fprintf(messageFile,
                             "parsePKA96KeyTokenPublicKey: Error parsing reserved\n");
        return -1;
    }
    rsaKeyTokenPublic->reserved[0] = **pubKeyToken;
    *pubKeyToken += 1;
    rsaKeyTokenPublic->reserved[1] = **pubKeyToken;
    *pubKeyToken += 1;
    *pubKeyTokenLength -= 2;
    /* eLength */
    if (*pubKeyTokenLength < 2) {
        if (verbose) fprintf(messageFile,
                             "parsePKA96KeyTokenPublicKey: Error parsing eLength\n");
        return -1;
    }
    rsaKeyTokenPublic->eLength = ntohs(*(unsigned short *)*pubKeyToken);
    *pubKeyToken += 2;
    *pubKeyTokenLength -= 2;
    if (rsaKeyTokenPublic->eLength > E_SIZE) {
        if (verbose) fprintf(messageFile,
                             "parsePKA96KeyTokenPublicKey: Error eLength %04hx too large\n",
                             rsaKeyTokenPublic->eLength);
        return -1;
    }
    /* nBitLength */
    if (*pubKeyTokenLength < 2) {
        if (verbose) fprintf(messageFile,
                             "parsePKA96KeyTokenPublicKey: Error parsing nBitLength\n");
        return -1;
    }
    rsaKeyTokenPublic->nBitLength = ntohs(*(unsigned short *)*pubKeyToken);
    *pubKeyToken += 2;
    *pubKeyTokenLength -= 2;
    /* nByteLength */
    if (*pubKeyTokenLength < 2) {
        if (verbose) fprintf(messageFile,
                             "parsePKA96KeyTokenPublicKey: Error parsing nByteLength\n");
        return -1;
    }
    nByteLengthPub = ntohs(*(unsigned short *)*pubKeyToken);	/* parsed here */
    *pubKeyToken += 2;
    *pubKeyTokenLength -= 2;
    if (nByteLengthPub > N_SIZE_MAX) {
        if (verbose) fprintf(messageFile,
                             "parsePKA96KeyTokenPublicKey: Error, nByteLength %04hx too large\n",
                             rsaKeyTokenPublic->nByteLength);
        return -1;
    }
    /* if the token does not have a private key, use this value */
    if (!hasPrivKey) {
        rsaKeyTokenPublic->nByteLength = nByteLengthPub;
    }
    /* if the token has a private key, its nByteLength is already in the structure.  This value
       should be 0 */
    else {
        if (nByteLengthPub != 0) {
            if (verbose) fprintf(messageFile,
                                 "parsePKA96KeyTokenPublicKey: "
                                 "Error nByteLength %04hx should be 0 for private key token\n",
                                 rsaKeyTokenPublic->nByteLength);
            return -1;
        }
    }
    /* e */
    if (*pubKeyTokenLength < rsaKeyTokenPublic->eLength) {
        if (verbose) fprintf(messageFile,
                             "parsePKA96KeyTokenPublicKey: Error parsing e\n");
        return -1;
    }
    memcpy(rsaKeyTokenPublic->e, *pubKeyToken, rsaKeyTokenPublic->eLength);
    *pubKeyToken += rsaKeyTokenPublic->eLength;
    *pubKeyTokenLength -= rsaKeyTokenPublic->eLength;
    /* n */
    if (!hasPrivKey) {
        if (*pubKeyTokenLength < rsaKeyTokenPublic->nByteLength) {
            if (verbose) fprintf(messageFile,
                                 "parsePKA96KeyTokenPublicKey: Error parsing n\n");
            return -1;
        }
        memcpy(rsaKeyTokenPublic->n, *pubKeyToken, rsaKeyTokenPublic->nByteLength);
        *pubKeyToken += rsaKeyTokenPublic->nByteLength;
        *pubKeyTokenLength -= rsaKeyTokenPublic->nByteLength;
    }
    if (verbose) printPKA96KeyTokenPublicKey(rsaKeyTokenPublic);
    return 0;
}

/* parsePKA96KeyTokenPrivateKey() returns CCA RsaKeyTokenPublic and RsaKeyTokenPrivate structures
   with the members filled in from the binary PKA96 key token.

   It puts the public key modulus n into the RsaKeyTokenPublic, which is where upper layers of the
   code expect it.

   keyTokenLength is decremented and keyToken is incremented as binary data is consumed.

   If bitSize is not 0, does sanity check against key token.
*/

long parsePKA96KeyTokenPrivateKey(RsaKeyTokenPublic *rsaKeyTokenPublic,
                                  RsaKeyTokenPrivate *rsaKeyTokenPrivate,
                                  long *keyTokenLength,
                                  unsigned char **keyToken,
                                  unsigned int bitSize)		/* expected RSA modulus size */
{
    long encLength;	/* length of encrypted private area */

    /* sectionId */
    if (*keyTokenLength < 1) {
        if (verbose) fprintf(messageFile,
                             "parsePKA96KeyTokenPrivateKey: Error parsing sectionId\n");
        return -1;
    }
    rsaKeyTokenPrivate->sectionId = **keyToken;
    *keyToken += 1;
    *keyTokenLength -= 1;
    if (rsaKeyTokenPrivate->sectionId != RSA_PRIVATE_KEY_CRT) {
        if (verbose) fprintf(messageFile,
                             "parsePKA96KeyTokenPrivateKey: Error, unknown sectionId %02x\n",
                             rsaKeyTokenPrivate->sectionId);
        return -1;
    }
    /* version */
    if (*keyTokenLength < 1) {
        if (verbose) fprintf(messageFile,
                             "parsePKA96KeyTokenPrivateKey: Error parsing version\n");
        return -1;
    }
    rsaKeyTokenPrivate->version = **keyToken;
    *keyToken += 1;
    *keyTokenLength -= 1;
    if (rsaKeyTokenPrivate->version != 0) {
        if (verbose) fprintf(messageFile,
                             "parsePKA96KeyTokenPrivateKey: Error, unknown version %02x\n",
                             rsaKeyTokenPrivate->version);
        return -1;
    }
    /* sectionLength */
    if (*keyTokenLength < 2) {
        if (verbose) fprintf(messageFile,
                             "parsePKA96KeyTokenPrivateKey: Error parsing sectionLength\n");
        return -1;
    }
    rsaKeyTokenPrivate->sectionLength = ntohs(*(unsigned short *)*keyToken);
    *keyToken += 2;
    *keyTokenLength -= 2;
    /* sha1HashPrivKey[SHA1_SIZE] */
    if (*keyTokenLength < SHA1_SIZE) {
        if (verbose) fprintf(messageFile,
                             "parsePKA96KeyTokenPrivateKey: Error parsing sha1HashPrivKey\n");
        return -1;
    }
    memcpy(rsaKeyTokenPrivate->sha1HashPrivKey, keyToken, SHA1_SIZE);
    *keyToken += SHA1_SIZE;
    *keyTokenLength -= SHA1_SIZE;
    /* reserved0 */
    if (*keyTokenLength < 4) {
        if (verbose) fprintf(messageFile,
                             "parsePKA96KeyTokenPrivateKey: Error parsing reserved0\n");
        return -1;
    }
    rsaKeyTokenPrivate->reserved0 = ntohl(*(unsigned long *)*keyToken);
    *keyToken += 4;
    *keyTokenLength -= 4;
    if (rsaKeyTokenPrivate->reserved0 != 0) {
        if (verbose) fprintf(messageFile,
                             "parsePKA96KeyTokenPrivateKey: Error, reserved %08lx\n",
                             rsaKeyTokenPrivate->reserved0);
        return -1;
    }
    /* keyFormat */
    if (*keyTokenLength < 1) {
        if (verbose) fprintf(messageFile,
                             "parsePKA96KeyTokenPrivateKey: Error parsing keyFormat\n");
        return -1;
    }
    rsaKeyTokenPrivate->keyFormat = **keyToken;
    *keyToken += 1;
    *keyTokenLength -= 1;
    if (rsaKeyTokenPrivate->keyFormat != RSA_INTERNAL_ENCRYPTED) {
        if (verbose) fprintf(messageFile,
                             "parsePKA96KeyTokenPrivateKey: Error, unknown keyFormat %02x\n",
                             rsaKeyTokenPrivate->keyFormat);
        return -1;
    }
    /* tokenType */
    if (*keyTokenLength < 1) {
        if (verbose) fprintf(messageFile,
                             "parsePKA96KeyTokenPrivateKey: Error parsing tokenType\n");
        return -1;
    }
    rsaKeyTokenPrivate->tokenType = **keyToken;
    *keyToken += 1;
    *keyTokenLength -= 1;
    if (rsaKeyTokenPrivate->tokenType != RSA_TOKEN_INTERNAL_GEN_RANDOM) {
        if (verbose) fprintf(messageFile,
                             "parsePKA96KeyTokenPrivateKey: Error, tokenType unknown %02x\n",
                             rsaKeyTokenPrivate->tokenType);
        return -1;
    }
    /* sha1HashOptional[SHA1_SIZE] */
    if (*keyTokenLength < SHA1_SIZE) {
        if (verbose) fprintf(messageFile,
                             "parsePKA96KeyTokenPrivateKey: Error parsing sha1HashOptional\n");
        return -1;
    }
    memcpy(rsaKeyTokenPrivate->sha1HashOptional, keyToken, SHA1_SIZE);
    *keyToken += SHA1_SIZE;
    *keyTokenLength -= SHA1_SIZE;
    /* keyUsageFlag */
    if (*keyTokenLength < 1) {
        if (verbose) fprintf(messageFile,
                             "parsePKA96KeyTokenPrivateKey: Error parsing keyUsageFlag\n");
        return -1;
    }
    rsaKeyTokenPrivate->keyUsageFlag = **keyToken;
    *keyToken += 1;
    *keyTokenLength -= 1;
    if ((rsaKeyTokenPrivate->keyUsageFlag != SIG_ONLY) &&
        (rsaKeyTokenPrivate->keyUsageFlag != KEY_MGMT)) {
        if (verbose) fprintf(messageFile,
                             "parsePKA96KeyTokenPrivateKey: Error, unknown keyUsageFlag %02x\n",
                             rsaKeyTokenPrivate->keyUsageFlag);
        return -1;
    }
    /* reserved1[3] */
    if (*keyTokenLength < 3) {
        if (verbose) fprintf(messageFile,
                             "parsePKA96KeyTokenPrivateKey: Error parsing reserved1\n");
        return -1;
    }
    memcpy(rsaKeyTokenPrivate->reserved1, keyToken, 3);
    *keyToken += 3;
    *keyTokenLength -= 3;
#if 0	/* the documentation says this should be 0, but it's not */
    if ((rsaKeyTokenPrivate->reserved1[0] != 0) ||
        (rsaKeyTokenPrivate->reserved1[1] != 0) ||
        (rsaKeyTokenPrivate->reserved1[2] != 0)) {
        if (verbose) fprintf(messageFile,
                             "parsePKA96KeyTokenPrivateKey: Error, illegal reserved1 %02x %02x %02x\n",
                             rsaKeyTokenPrivate->reserved1[0],
                             rsaKeyTokenPrivate->reserved1[1],
                             rsaKeyTokenPrivate->reserved1[2]);
        return -1;
    }
#endif
    /* pLength */
    if (*keyTokenLength < 2) {
        if (verbose) fprintf(messageFile,
                             "parsePKA96KeyTokenPrivateKey: Error parsing pLength\n");
        return -1;
    }
    rsaKeyTokenPrivate->pLength = ntohs(*(unsigned short *)*keyToken);
    *keyToken += 2;
    *keyTokenLength -= 2;
    if (bitSize != 0) {
        if (rsaKeyTokenPrivate->pLength != (bitSize/(2 * 8))) {
            if (verbose) fprintf(messageFile,
                                 "parsePKA96KeyTokenPrivateKey: Error, illegal pLength %hu for bit size %u\n",
                                 rsaKeyTokenPrivate->pLength, bitSize);
            return -1;
        }
    }
    /* qLength */
    if (*keyTokenLength < 2) {
        if (verbose) fprintf(messageFile,
                             "parsePKA96KeyTokenPrivateKey: Error parsing qLength\n");
        return -1;
    }
    rsaKeyTokenPrivate->qLength = ntohs(*(unsigned short *)*keyToken);
    *keyToken += 2;
    *keyTokenLength -= 2;
    if (bitSize != 0) {
        if (rsaKeyTokenPrivate->qLength != (bitSize/(2 * 8))) {
            if (verbose) fprintf(messageFile,
                                 "parsePKA96KeyTokenPrivateKey: Error, illegal qLength %hu for bit size %u\n",
                                 rsaKeyTokenPrivate->qLength, bitSize);
            return -1;
        }
    }
    /* dpLength */
    if (*keyTokenLength < 2) {
        if (verbose) fprintf(messageFile,
                             "parsePKA96KeyTokenPrivateKey: Error parsing dpLength\n");
        return -1;
    }
    rsaKeyTokenPrivate->dpLength = ntohs(*(unsigned short *)*keyToken);
    *keyToken += 2;
    *keyTokenLength -= 2;
    if (bitSize != 0) {
        if (rsaKeyTokenPrivate->dpLength != (bitSize/(2 * 8))) {
            if (verbose) fprintf(messageFile,
                                 "parsePKA96KeyTokenPrivateKey: Error, illegal dpLength %hu for bit size %u\n",
                                 rsaKeyTokenPrivate->dpLength, bitSize);
            return -1;
        }
    }
    /* dqLength */
    if (*keyTokenLength < 2) {
        if (verbose) fprintf(messageFile,
                             "parsePKA96KeyTokenPrivateKey: Error parsing dqLength\n");
        return -1;
    }
    rsaKeyTokenPrivate->dqLength = ntohs(*(unsigned short *)*keyToken);
    *keyToken += 2;
    *keyTokenLength -= 2;
    if (bitSize != 0) {
        if (rsaKeyTokenPrivate->dqLength != (bitSize/(2 * 8))) {
            if (verbose) fprintf(messageFile,
                                 "parsePKA96KeyTokenPrivateKey: Error, illegal dqLength %hu for bit size %u\n",
                                 rsaKeyTokenPrivate->dqLength, bitSize);
            return -1;
        }
    }
    /* uLength */
    if (*keyTokenLength < 2) {
        if (verbose) fprintf(messageFile,
                             "parsePKA96KeyTokenPrivateKey: Error parsing uLength\n");
        return -1;
    }
    rsaKeyTokenPrivate->uLength = ntohs(*(unsigned short *)*keyToken);
    *keyToken += 2;
    *keyTokenLength -= 2;
    if (bitSize != 0) {
        if (rsaKeyTokenPrivate->uLength != (bitSize/(2 * 8))) {
            if (verbose) fprintf(messageFile,
                                 "parsePKA96KeyTokenPrivateKey: Error, illegal uLength %hu for bit size %u\n",
                                 rsaKeyTokenPrivate->uLength, bitSize);
            return -1;
        }
    }
    /* nLength */
    if (*keyTokenLength < 2) {
        if (verbose) fprintf(messageFile,
                             "parsePKA96KeyTokenPrivateKey: Error parsing nLength\n");
        return -1;
    }
    rsaKeyTokenPrivate->nLength = ntohs(*(unsigned short *)*keyToken);
    /* copy to public key area as a service, since nByteLength in the public token will be 0 */
    rsaKeyTokenPublic->nByteLength = rsaKeyTokenPrivate->nLength;
    *keyToken += 2;
    *keyTokenLength -= 2;
    if (bitSize != 0) {
        if (rsaKeyTokenPrivate->nLength != (bitSize/8)) {
            if (verbose) fprintf(messageFile,
                                 "parsePKA96KeyTokenPrivateKey: Error illegal nLength %04hx for bit size %u\n",
                                 rsaKeyTokenPrivate->nLength, bitSize);
            return -1;
        }
    }
    /* reserved2 */
    if (*keyTokenLength < 2) {
        if (verbose) fprintf(messageFile,
                             "parsePKA96KeyTokenPrivateKey: Error parsing reserved2\n");
        return -1;
    }
    rsaKeyTokenPrivate->reserved2 = ntohs(*(unsigned short *)*keyToken);
    *keyToken += 2;
    *keyTokenLength -= 2;
    if (rsaKeyTokenPrivate->reserved2 != 0) {
        if (verbose) fprintf(messageFile,
                             "parsePKA96KeyTokenPrivateKey: Error, illegal reserved2 %04hx\n",
                             rsaKeyTokenPrivate->reserved2);
        return -1;
    }
    /* reserved3 */
    if (*keyTokenLength < 2) {
        if (verbose) fprintf(messageFile,
                             "parsePKA96KeyTokenPrivateKey: Error parsing reserved3\n");
        return -1;
    }
    rsaKeyTokenPrivate->reserved3 = ntohs(*(unsigned short *)*keyToken);
    *keyToken += 2;
    *keyTokenLength -= 2;
    if (rsaKeyTokenPrivate->reserved3 != 0) {
        if (verbose) fprintf(messageFile,
                             "parsePKA96KeyTokenPrivateKey: Error, illegal reserved3 %04hx\n",
                             rsaKeyTokenPrivate->reserved3);
        return -1;
    }
    /* padLength */
    if (*keyTokenLength < 2) {
        if (verbose) fprintf(messageFile,
                             "parsePKA96KeyTokenPrivateKey: Error parsing padLength\n");
        return -1;
    }
    rsaKeyTokenPrivate->padLength = ntohs(*(unsigned short *)*keyToken);
    *keyToken += 2;
    *keyTokenLength -= 2;
    /* reserved4 */
    if (*keyTokenLength < 4) {
        if (verbose) fprintf(messageFile,
                             "parsePKA96KeyTokenPrivateKey: Error parsing reserved4\n");
        return -1;
    }
    rsaKeyTokenPrivate->reserved4 = ntohl(*(unsigned long *)*keyToken);
    *keyToken += 4;
    *keyTokenLength -= 4;
    if (rsaKeyTokenPrivate->reserved4 != 0) {
        if (verbose) fprintf(messageFile,
                             "parsePKA96KeyTokenPrivateKey: Error, illegal reserved4 %08lx\n",
                             rsaKeyTokenPrivate->reserved4);
        return -1;
    }
    /* reserved5[16] */
    if (*keyTokenLength < 16) {
        if (verbose) fprintf(messageFile,
                             "parsePKA96KeyTokenPrivateKey: Error parsing reserved5\n");
        return -1;
    }
    memcpy(rsaKeyTokenPrivate->reserved5, keyToken, 16);
    *keyToken += 16;
    *keyTokenLength -= 16;
    /* reserved6[32] */
    if (*keyTokenLength < 32) {
        if (verbose) fprintf(messageFile,
                             "parsePKA96KeyTokenPrivateKey: Error parsing reserved6\n");
        return -1;
    }
    memcpy(rsaKeyTokenPrivate->reserved6, keyToken, 32);
    *keyToken += 32;
    *keyTokenLength -= 32;
    /* confounder[8] */
    if (*keyTokenLength < 8) {
        if (verbose) fprintf(messageFile,
                             "parsePKA96KeyTokenPrivateKey: Error parsing confounder\n");
        return -1;
    }
    memcpy(rsaKeyTokenPrivate->confounder, keyToken, 8);
    *keyToken += 8;
    *keyTokenLength -= 8;
    /* p */
    /* q */
    /* dp */
    /* dq */
    /* u */
    /* pad */
    /* skip the encrypted part */
    encLength = rsaKeyTokenPrivate->pLength +
		rsaKeyTokenPrivate->qLength +
		rsaKeyTokenPrivate->dpLength +
		rsaKeyTokenPrivate->dqLength +
		rsaKeyTokenPrivate->uLength +
		rsaKeyTokenPrivate->padLength;
    if (*keyTokenLength < encLength) {
        if (verbose) fprintf(messageFile,
                             "parsePKA96KeyTokenPrivateKey: Error parsing encrypted area\n");
        return -1;
    }
    *keyToken += encLength;
    *keyTokenLength -= encLength;
    /* n */
    if (*keyTokenLength < rsaKeyTokenPrivate->nLength) {
        if (verbose) fprintf(messageFile,
                             "parsePKA96KeyTokenPrivateKey: Error parsing n\n");
        return -1;
    }
    memcpy(rsaKeyTokenPublic->n, *keyToken, rsaKeyTokenPrivate->nLength);
    *keyToken += rsaKeyTokenPrivate->nLength;
    *keyTokenLength -= rsaKeyTokenPrivate->nLength;

    if (verbose) printPKA96KeyTokenPrivateKey(rsaKeyTokenPrivate);
    return 0;
}

/* parsePKA96KeyTokenPrivateKeyAesOPK() returns CCA RsaKeyTokenPublic and RsaKeyTokenPrivate structures
   with the members filled in from the binary PKA96 key token.

   It puts the public key modulus n into the RsaKeyTokenPublic, which is where upper layers of the
   code expect it.

   keyTokenLength is decremented and keyToken is incremented as binary data is consumed.

   If bitSize is not 0, does sanity check against key token.
*/

long parsePKA96KeyTokenPrivateKeyAesOPK(RsaKeyTokenPublic *rsaKeyTokenPublic,
                                        RsaKeyTokenPrivate *rsaKeyTokenPrivate,
                                        long *keyTokenLength,
                                        unsigned char **keyToken,
                                        unsigned int bitSize)		/* expected RSA modulus size */
{
    unsigned short payloadLength; /* length of payload */

    /* sectionId */
    if (*keyTokenLength < 1) {
        if (verbose) fprintf(messageFile,
                             "parsePKA96KeyTokenPrivateKeyAesOPK: Error parsing sectionId\n");
        return -1;
    }
    rsaKeyTokenPrivate->sectionId = **keyToken;
    *keyToken += 1;
    *keyTokenLength -= 1;
    if (rsaKeyTokenPrivate->sectionId != RSA_PRIVATE_KEY_CRT_AES_OPK) {
        if (verbose) fprintf(messageFile,
                             "parsePKA96KeyTokenPrivateKeyAesOPK: Error, unknown sectionId %02x\n",
                             rsaKeyTokenPrivate->sectionId);
        return -1;
    }
    /* version */
    if (*keyTokenLength < 1) {
        if (verbose) fprintf(messageFile,
                             "parsePKA96KeyTokenPrivateKeyAesOPK: Error parsing version\n");
        return -1;
    }
    rsaKeyTokenPrivate->version = **keyToken;
    *keyToken += 1;
    *keyTokenLength -= 1;
    if (rsaKeyTokenPrivate->version != 0) {
        if (verbose) fprintf(messageFile,
                             "parsePKA96KeyTokenPrivateKeyAesOPK: Error, unknown version %02x\n",
                             rsaKeyTokenPrivate->version);
        return -1;
    }
    /* sectionLength */
    if (*keyTokenLength < 2) {
        if (verbose) fprintf(messageFile,
                             "parsePKA96KeyTokenPrivateKeyAesOPK: Error parsing sectionLength\n");
        return -1;
    }
    rsaKeyTokenPrivate->sectionLength = ntohs(*(unsigned short *)*keyToken);
    *keyToken += 2;
    *keyTokenLength -= 2;
    if (rsaKeyTokenPrivate->sectionLength < 134) {
        if (verbose) fprintf(messageFile,
                             "parsePKA96KeyTokenPrivateKeyAesOPK: Invalid sectionLength\n");
        return -1;
    }

    /* Length of assoc data section */
    *keyToken += 2;
    *keyTokenLength -= 2;

    /* Length of payload data */
    payloadLength = ntohs(*(unsigned short *)*keyToken);
    *keyToken += 2;
    *keyTokenLength -= 2;

    /* Reserved */
    *keyToken += 2;
    *keyTokenLength -= 2;

    /* Assoc data section version */
    if (**keyToken != 0x03) {
        if (verbose) fprintf(messageFile,
                             "parsePKA96KeyTokenPrivateKeyAesOPK: Invalid associated data section version : %X\n", **keyToken);
        return -1;
    }
    *keyToken += 1;
    *keyTokenLength -= 1;

    /* key format */
    rsaKeyTokenPrivate->keyFormat = **keyToken;
    if (rsaKeyTokenPrivate->keyFormat != RSA_INTERNAL_ENCRYPTED) {
        if (verbose) fprintf(messageFile,
                             "parsePKA96KeyTokenPrivateKeyAesOPK: Error, unknown keyFormat %02x\n",
                             rsaKeyTokenPrivate->keyFormat);
        return -1;
    }
    *keyToken += 1;
    *keyTokenLength -= 1;

    /* key source */
    rsaKeyTokenPrivate->tokenType = **keyToken;
    *keyToken += 1;
    *keyTokenLength -= 1;
    if (rsaKeyTokenPrivate->tokenType != RSA_TOKEN_INTERNAL_GEN_RANDOM) {
        if (verbose) fprintf(messageFile,
                             "parsePKA96KeyTokenPrivateKeyAesOPK: Error, tokenType unknown %02x\n",
                             rsaKeyTokenPrivate->tokenType);
        return -1;
    }

    /* reserved */
    *keyToken += 1;
    *keyTokenLength -= 1;

    /* hash type */
    *keyToken += 1;
    *keyTokenLength -= 1;

    /* sha-256 hash of optional sections */
    *keyToken += 32;
    *keyTokenLength -= 32;

    /* reserved */
    *keyToken += 3;
    *keyTokenLength -= 3;

    /* key usage */
    /* keyUsageFlag */
    if (*keyTokenLength < 1) {
        if (verbose) fprintf(messageFile,
                             "parsePKA96KeyTokenPrivateKeyAesOPK: Error parsing keyUsageFlag\n");
        return -1;
    }
    rsaKeyTokenPrivate->keyUsageFlag = **keyToken;
    *keyToken += 1;
    *keyTokenLength -= 1;
    if ((rsaKeyTokenPrivate->keyUsageFlag != SIG_ONLY) &&
        (rsaKeyTokenPrivate->keyUsageFlag != KEY_MGMT)) {
        if (verbose) fprintf(messageFile,
                             "parsePKA96KeyTokenPrivateKeyAesOPK: Error, unknown keyUsageFlag %02x\n",
                             rsaKeyTokenPrivate->keyUsageFlag);
        return -1;
    }

    /* Format restriction */
    *keyToken += 1;
    *keyTokenLength -= 1;

    /* pLength */
    if (*keyTokenLength < 2) {
        if (verbose) fprintf(messageFile,
                             "parsePKA96KeyTokenPrivateKeyAesOPK: Error parsing pLength\n");
        return -1;
    }
    rsaKeyTokenPrivate->pLength = ntohs(*(unsigned short *)*keyToken);
    *keyToken += 2;
    *keyTokenLength -= 2;
    if (bitSize != 0) {
        if (rsaKeyTokenPrivate->pLength != (bitSize/(2 * 8))) {
            if (verbose) fprintf(messageFile,
                                 "parsePKA96KeyTokenPrivateKeyAesOPK: Error, illegal pLength %hu for bit size %u\n",
                                 rsaKeyTokenPrivate->pLength, bitSize);
            return -1;
        }
    }
    /* qLength */
    if (*keyTokenLength < 2) {
        if (verbose) fprintf(messageFile,
                             "parsePKA96KeyTokenPrivateKeyAesOPK: Error parsing qLength\n");
        return -1;
    }
    rsaKeyTokenPrivate->qLength = ntohs(*(unsigned short *)*keyToken);
    *keyToken += 2;
    *keyTokenLength -= 2;
    if (bitSize != 0) {
        if (rsaKeyTokenPrivate->qLength != (bitSize/(2 * 8))) {
            if (verbose) fprintf(messageFile,
                                 "parsePKA96KeyTokenPrivateKeyAesOPK: Error, illegal qLength %hu for bit size %u\n",
                                 rsaKeyTokenPrivate->qLength, bitSize);
            return -1;
        }
    }
    /* dpLength */
    if (*keyTokenLength < 2) {
        if (verbose) fprintf(messageFile,
                             "parsePKA96KeyTokenPrivateKeyAesOPK: Error parsing dpLength\n");
        return -1;
    }
    rsaKeyTokenPrivate->dpLength = ntohs(*(unsigned short *)*keyToken);
    *keyToken += 2;
    *keyTokenLength -= 2;
    if (bitSize != 0) {
        if (rsaKeyTokenPrivate->dpLength != (bitSize/(2 * 8))) {
            if (verbose) fprintf(messageFile,
                                 "parsePKA96KeyTokenPrivateKeyAesOPK: Error, illegal dpLength %hu for bit size %u\n",
                                 rsaKeyTokenPrivate->dpLength, bitSize);
            return -1;
        }
    }
    /* dqLength */
    if (*keyTokenLength < 2) {
        if (verbose) fprintf(messageFile,
                             "parsePKA96KeyTokenPrivateKeyAesOPK: Error parsing dqLength\n");
        return -1;
    }
    rsaKeyTokenPrivate->dqLength = ntohs(*(unsigned short *)*keyToken);
    *keyToken += 2;
    *keyTokenLength -= 2;
    if (bitSize != 0) {
        if (rsaKeyTokenPrivate->dqLength != (bitSize/(2 * 8))) {
            if (verbose) fprintf(messageFile,
                                 "parsePKA96KeyTokenPrivateKeyAesOPK: Error, illegal dqLength %hu for bit size %u\n",
                                 rsaKeyTokenPrivate->dqLength, bitSize);
            return -1;
        }
    }
    /* uLength */
    if (*keyTokenLength < 2) {
        if (verbose) fprintf(messageFile,
                             "parsePKA96KeyTokenPrivateKeyAesOPK: Error parsing uLength\n");
        return -1;
    }
    rsaKeyTokenPrivate->uLength = ntohs(*(unsigned short *)*keyToken);
    *keyToken += 2;
    *keyTokenLength -= 2;
    if (bitSize != 0) {
        if (rsaKeyTokenPrivate->uLength != (bitSize/(2 * 8))) {
            if (verbose) fprintf(messageFile,
                                 "parsePKA96KeyTokenPrivateKeyAesOPK: Error, illegal uLength %hu for bit size %u\n",
                                 rsaKeyTokenPrivate->uLength, bitSize);
            return -1;
        }
    }
    /* nLength */
    if (*keyTokenLength < 2) {
        if (verbose) fprintf(messageFile,
                             "parsePKA96KeyTokenPrivateKeyAesOPK: Error parsing nLength\n");
        return -1;
    }
    rsaKeyTokenPrivate->nLength = ntohs(*(unsigned short *)*keyToken);
    /* copy to public key area as a service, since nByteLength in the public token will be 0 */
    rsaKeyTokenPublic->nByteLength = rsaKeyTokenPrivate->nLength;
    *keyToken += 2;
    *keyTokenLength -= 2;
    if (bitSize != 0) {
        if (rsaKeyTokenPrivate->nLength != (bitSize/8)) {
            if (verbose) fprintf(messageFile,
                                 "parsePKA96KeyTokenPrivateKeyAesOPK: Error illegal nLength %04hx for bit size %u\n",
                                 rsaKeyTokenPrivate->nLength, bitSize);
            return -1;
        }
    }

    /* reserved */
    *keyToken += 4;
    *keyTokenLength -= 4;

    /* OPK data */
    if (*keyTokenLength < 48) {
        if (verbose) fprintf(messageFile,
                             "parsePKA96KeyTokenPrivateKeyAesOPK: Error parsing OPK data\n");
        return -1;
    }
    *keyToken += 48;
    *keyTokenLength -= 48;

    /* Key verif pattern */
    if (*keyTokenLength < 16) {
        if (verbose) fprintf(messageFile,
                             "parsePKA96KeyTokenPrivateKeyAesOPK: Error parsing key verif pattern\n");
        return -1;
    }
    *keyToken += 16;
    *keyTokenLength -= 16;

    /* reserved */
    *keyToken += 2;
    *keyTokenLength -= 2;

    /* n */
    if (*keyTokenLength < rsaKeyTokenPrivate->nLength) {
        if (verbose) fprintf(messageFile,
                             "parsePKA96KeyTokenPrivateKeyAesOPK: Error parsing n\n");
        return -1;
    }
    memcpy(rsaKeyTokenPublic->n, *keyToken, rsaKeyTokenPrivate->nLength);
    *keyToken += rsaKeyTokenPrivate->nLength;
    *keyTokenLength -= rsaKeyTokenPrivate->nLength;

    if (*keyTokenLength < payloadLength) {
        if (verbose) fprintf(messageFile,
                             "parsePKA96KeyTokenPrivateKeyAesOPK: Error parsing invalid payload length\n");
        return -1;
    }
    *keyToken += payloadLength;
    *keyTokenLength -= payloadLength;

    if (verbose) printPKA96KeyTokenPrivateKey(rsaKeyTokenPrivate);

    return 0;

}

/*
  Debug Print Functions
*/

/* printPKA96KeyTokenHeader() prints the RsaKeyTokenHeader structure in human readable form

 */

void printPKA96KeyTokenHeader(RsaKeyTokenHeader *rsaKeyTokenHeader)
{
    if (verbose) fprintf(messageFile,
                         "\tToken Header:\n");
    /* tokenId */
    switch (rsaKeyTokenHeader->tokenId) {
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
                             rsaKeyTokenHeader->tokenId);
    }
    /* version */
    if (verbose) fprintf(messageFile,
                         "\t\tversion: %02x\n", rsaKeyTokenHeader->version);
    /* tokenLength */
    if (verbose) fprintf(messageFile,
                         "\t\ttokenLength: %04hx %hu\n",
                         rsaKeyTokenHeader->tokenLength, rsaKeyTokenHeader->tokenLength);
    /* reserved */
    if (verbose) fprintf(messageFile,
                         "\t\treserved: %08lx\n", rsaKeyTokenHeader->reserved);
    return;
}

/* printPKA96KeyTokenPublicKey() prints the RsaKeyTokenPublic structure in human readable form

 */

void printPKA96KeyTokenPublicKey(RsaKeyTokenPublic *rsaKeyTokenPublic)
{
    if (verbose) fprintf(messageFile,
                         "\tToken Public Key:\n");

    /* sectionId */
    printSectionID(rsaKeyTokenPublic->sectionId);
    /* version */
    if (verbose) fprintf(messageFile,
                         "\t\tversion: %02x\n", rsaKeyTokenPublic->version);
    /* section_length */
    if (verbose) fprintf(messageFile,
                         "\t\tsectionLength: %04hx %hu\n",
                         rsaKeyTokenPublic->sectionLength, rsaKeyTokenPublic->sectionLength);
    /* reserved[2] */
    if (verbose) fprintf(messageFile,
                         "\t\treserved: %02x %02x\n",
                         rsaKeyTokenPublic->reserved[0],
                         rsaKeyTokenPublic->reserved[1]);
    /* eLength */
    if (verbose) fprintf(messageFile,
                         "\t\teLength : %04hx %hu\n",
                         rsaKeyTokenPublic->eLength, rsaKeyTokenPublic->eLength);
    /* nBitLength */
    if (verbose) fprintf(messageFile,
                         "\t\tnBitLength: %04hx %hu\n",
                         rsaKeyTokenPublic->nBitLength, rsaKeyTokenPublic->nBitLength);
    /* nByteLength */
    if (verbose) fprintf(messageFile,
                         "\t\tnByteLength: %04hx %hu\n",
                         rsaKeyTokenPublic->nByteLength, rsaKeyTokenPublic->nByteLength);
    if (verbose) {
        /* e */
        PrintAll(messageFile,
                 "\t\te", rsaKeyTokenPublic->eLength, rsaKeyTokenPublic->e);
        /* n */
        PrintAll(messageFile,
                 "\t\tn", rsaKeyTokenPublic->nByteLength, rsaKeyTokenPublic->n);
    }
    return;
}

/* printPKA96KeyTokenPrivateKey() prints the RsaKeyTokenPrivate structure in human readable form

 */

void printPKA96KeyTokenPrivateKey(RsaKeyTokenPrivate *rsaKeyTokenPrivate)
{
    if (verbose) fprintf(messageFile,
                         "\tToken Private Key:\n");

    /* sectionId */
    printSectionID(rsaKeyTokenPrivate->sectionId);
    /* version */
    if (verbose) fprintf(messageFile,
                         "\t\tversion: %02x\n", rsaKeyTokenPrivate->version);
    /* sectionLength */
    if (verbose) fprintf(messageFile,
                         "\t\tsectionLength: %04hx %hu\n",
                         rsaKeyTokenPrivate->sectionLength, rsaKeyTokenPrivate->sectionLength);
    /* sha1HashPrivKey[SHA1_SIZE] */
    if (verbose) fprintf(messageFile,
                         "\t\tsha1HashPrivKey: ");
    if (verbose) {
        PrintAll(messageFile,
                 "", SHA1_SIZE, rsaKeyTokenPrivate->sha1HashPrivKey);
    }
    /* reserved0 */
    if (verbose) fprintf(messageFile,
                         "\t\treserved0 %08lx\n", rsaKeyTokenPrivate->reserved0);
    /* keyFormat */
    printKeyFormat(rsaKeyTokenPrivate->keyFormat);
    /* tokenType */
    printTokenType(rsaKeyTokenPrivate->tokenType);
    /* sha1HashOptional[SHA1_SIZE] */
    if (verbose) fprintf(messageFile,
                         "\t\tsha1HashOptional: ");
    if (verbose) {
        PrintAll(messageFile,
                 "", SHA1_SIZE, rsaKeyTokenPrivate->sha1HashOptional);
    }
    /* keyUsageFlag */
    printKeyUsageFlag(rsaKeyTokenPrivate->keyUsageFlag);
    /* reserved1[3] */
    if (verbose) fprintf(messageFile,
                         "\t\treserved1 %02x %02x %02x \n",
                         rsaKeyTokenPrivate->reserved1[0],
                         rsaKeyTokenPrivate->reserved1[1],
                         rsaKeyTokenPrivate->reserved1[2]);
    /* pLength */
    if (verbose) fprintf(messageFile,
                         "\t\tpLength : %04hx %hu\n",
                         rsaKeyTokenPrivate->pLength, rsaKeyTokenPrivate->pLength);
    /* qLength */
    if (verbose) fprintf(messageFile,
                         "\t\tqLength: %04hx %hu\n",
                         rsaKeyTokenPrivate->qLength, rsaKeyTokenPrivate->qLength);
    /* dpLength */
    if (verbose) fprintf(messageFile,
                         "\t\tdpLength: %04hx %hu\n",
                         rsaKeyTokenPrivate->dpLength, rsaKeyTokenPrivate->dpLength);
    /* dqLength */
    if (verbose) fprintf(messageFile,
                         "\t\tdqLength: %04hx %hu\n",
                         rsaKeyTokenPrivate->dqLength, rsaKeyTokenPrivate->dqLength);
    /* uLength */
    if (verbose) fprintf(messageFile,
                         "\t\tuLength: %04hx %hu\n",
                         rsaKeyTokenPrivate->uLength, rsaKeyTokenPrivate->uLength);
    /* nLength */
    if (verbose) fprintf(messageFile,
                         "\t\tnLength: %04hx %hu\n",
                         rsaKeyTokenPrivate->nLength, rsaKeyTokenPrivate->nLength);
    /* reserved2 */
    if (verbose) fprintf(messageFile,
                         "\t\treserved2: %04hx\n", rsaKeyTokenPrivate->reserved2);
    /* reserved3 */
    if (verbose) fprintf(messageFile,
                         "\t\treserved3: %04hx\n", rsaKeyTokenPrivate->reserved3);
    /* padLength */
    if (verbose) fprintf(messageFile,
                         "\t\tpadLength: %04hx %hu\n",
                         rsaKeyTokenPrivate->padLength, rsaKeyTokenPrivate->padLength);
    /* reserved4 */
    if (verbose) fprintf(messageFile,
                         "\t\treserved4: %08lx\n", rsaKeyTokenPrivate->reserved4);
    /* reserved5[16] */
    if (verbose) fprintf(messageFile,
                         "\t\treserved5: ");
    if (verbose) {
        PrintAll(messageFile,
                 "", 16, rsaKeyTokenPrivate->reserved5);
    }
    /* reserved6[32] */
    if (verbose) fprintf(messageFile,
                         "\t\treserved6: ");
    if (verbose) {
        PrintAll(messageFile,
                 "", 32, rsaKeyTokenPrivate->reserved6);
    }
    /* confounder[8] */
    if (verbose) fprintf(messageFile,
                         "\t\tconfounder: %02x%02x%02x%02x %02x%02x%02x%02x\n",
                         rsaKeyTokenPrivate->confounder[0], rsaKeyTokenPrivate->confounder[1],
                         rsaKeyTokenPrivate->confounder[2], rsaKeyTokenPrivate->confounder[3],
                         rsaKeyTokenPrivate->confounder[4], rsaKeyTokenPrivate->confounder[5],
                         rsaKeyTokenPrivate->confounder[6], rsaKeyTokenPrivate->confounder[7]);
    return;
}

void printSectionID(unsigned char sectionId)
{
    if (verbose) fprintf(messageFile,
                         "\t\tsectionId: ");
    switch (sectionId) {
    case RSA_PRIVATE_KEY_1024_EXTERNAL:
        if (verbose) fprintf(messageFile,
                             "RSA_PRIVATE_KEY_1024_EXTERNAL\n");
        break;
    case RSA_PUBLIC_SECTION:
        if (verbose) fprintf(messageFile,
                             "RSA_PUBLIC_SECTION\n");
        break;
    case RSA_PRIVATE_KEY_2048_CRT_DEP:
        if (verbose) fprintf(messageFile,
                             "RSA_PRIVATE_KEY_2048_CRT_DEP\n");
        break;
    case RSA_PRIVATE_KEY_1024_INTERNAL:
        if (verbose) fprintf(messageFile,
                             "RSA_PRIVATE_KEY_1024_INTERNAL\n");
        break;
    case RSA_PRIVATE_KEY_CRT:
        if (verbose) fprintf(messageFile,
                             "RSA_PRIVATE_KEY_CRT\n");
        break;
    default:
        if (verbose) fprintf(messageFile,
                             "Unknown %02x\n", sectionId);
    }
    return;
}

void printKeyFormat(unsigned char keyFormat)
{
    if (verbose) fprintf(messageFile,
                         "\t\tkeyFormat: ");
    switch (keyFormat) {
    case RSA_EXTERNAL_UNENCRYPTED:
        if (verbose) fprintf(messageFile,
                             "RSA_EXTERNAL_UNENCRYPTED\n");
        break;
    case RSA_EXTERNAL_ENCRYPTED:
        if (verbose) fprintf(messageFile,
                             "RSA_EXTERNAL_ENCRYPTED\n");
        break;
    case RSA_INTERNAL_ENCRYPTED:
        if (verbose) fprintf(messageFile,
                             "RSA_INTERNAL_ENCRYPTED\n");
        break;
    default:
        if (verbose) fprintf(messageFile,
                             "Unknown %02x\n", keyFormat);
    }
    return;
}

void printTokenType (unsigned char tokenType)
{
    if (verbose) fprintf(messageFile,
                         "\t\ttokenType: ");
    switch (tokenType) {
    case RSA_TOKEN_EXTERNAL:
        if (verbose) fprintf(messageFile,
                             "RSA_TOKEN_EXTERNAL\n");
        break;
    case RSA_TOKEN_INTERNAL_IMPORT_CLEARTEXT:
        if (verbose) fprintf(messageFile,
                             "RSA_TOKEN_INTERNAL_IMPORT_CLEARTEXT\n");
        break;
    case RSA_TOKEN_INTERNAL_IMPORT_CIPHERTEXT:
        if (verbose) fprintf(messageFile,
                             "RSA_TOKEN_INTERNAL_IMPORT_CIPHERTEXT\n");
        break;
    case RSA_TOKEN_INTERNAL_GEN_REGEN:
        if (verbose) fprintf(messageFile,
                             "RSA_TOKEN_INTERNAL_GEN_REGEN\n");
        break;
    case RSA_TOKEN_INTERNAL_GEN_RANDOM:
        if (verbose) fprintf(messageFile,
                             "RSA_TOKEN_INTERNAL_GEN_RANDOM\n");
        break;
    default:
        if (verbose) fprintf(messageFile,
                             "Unknown %02x\n", tokenType);
    }
    return;
}

void printKeyUsageFlag(unsigned char keyUsageFlag)
{
    if (verbose) fprintf(messageFile,
                         "\t\tkeyUsageFlag: ");
    switch (keyUsageFlag) {
    case SIG_ONLY:
        if (verbose) fprintf(messageFile,
                             "SIG_ONLY\n");
        break;
    case KM_ONLY:
        if (verbose) fprintf(messageFile,
                             "KM_ONLY\n");
        break;
    case KEY_MGMT:
        if (verbose) fprintf(messageFile,
                             "KEY_MGMT\n");
        break;
    default:
        if (verbose) fprintf(messageFile,
                             "Unknown %02x\n", keyUsageFlag);
    }
    return;
}
