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

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <openssl/crypto.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/objects.h>

#include "debug.h"
#include "utils.h"
#include "ossl_functions_ecc.h"

/* messages are traced here

   All messages, even error messages, are traced only if verbose is set.  There messages are
   'techie' and should not be returned unless the user asks for them.
*/

extern FILE* messageFile;
extern int verbose;

long Ossl_VerifyECC(int *valid,			/* output boolean */
		    const unsigned char *digest,
		    size_t digestLength,
		    const unsigned char *publicKey,
		    size_t publicKeyLength,
		    const unsigned char *signature,
		    unsigned long signatureLength)
{
    long 		rc = 0;			/* function return code */
    int			irc;
    EC_KEY 		*ecPubKey = NULL;	/* freed @1 */

    if (verbose) fprintf(messageFile, "Ossl_VerifyECC: Verifying using OpenSSL\n");
    if (verbose) PrintAll(messageFile, "Ossl_VerifyECC: public key", publicKeyLength, publicKey);
    if (verbose) PrintAll(messageFile, "Ossl_VerifyECC: digest", digestLength, digest);
    if (verbose) PrintAll(messageFile, "Ossl_VerifyECC: signature", signatureLength, signature);
    /* create an EC public key token */
    if (rc == 0) {
	rc = Ossl_SetPubKey_ECC(&ecPubKey,	/* freed @1 */
				publicKey,
				publicKeyLength);
    }
    /* verify signature */
    if (rc == 0) {
	if (verbose) fprintf(messageFile, "Ossl_VerifyECC: signature length out %lu\n",
			     signatureLength);
	irc = ECDSA_verify(0,			/* type ignored */
			   digest, 		/* digest to be verified*/
			   digestLength,
			   signature, 		/* DER encoded signature */
			   signatureLength, 	/* length of signature */
			   ecPubKey);		/* public key */
	if (irc == 0)  {
	    if (verbose) fprintf(messageFile,
				 "Ossl_VerifyECC: ECDSA_verify failed\n");
	    *valid = FALSE;
	}
	else {
	    if (verbose) fprintf(messageFile,
				 "Ossl_VerifyECC: ECDSA_verify success\n");
	    *valid = TRUE;
	}
    }
    /* cleanup */
    if (ecPubKey != NULL) {	/* @1 */
	EC_KEY_free(ecPubKey);
    }
    return rc;
}

long Ossl_SetPubKey_ECC(EC_KEY **ecPubKey,		/* freed by caller */
			const unsigned char *publicKey,
			size_t publicKeyLength)
{
    long 		rc = 0;
    int			irc;
    int			nid;
    EC_GROUP		*group = NULL;		/* freed @1 */
    EC_POINT 		*ec_point = NULL;	/* freed @2 */

    if (verbose) fprintf(messageFile, "Ossl_SetPubKey_ECC: Creating public key token\n");
    /* create an EC_KEY */
    if (rc == 0) {
	*ecPubKey = EC_KEY_new();	/* freed @5 */
	if (*ecPubKey == NULL) {
	    fprintf(messageFile, "Ossl_SetPubKey_ECC: unable to EC_KEY_new\n");
	    rc = ERROR_CODE;
	}
    }
    /* Creates a EC_GROUP object with a curve specified by a NID */
    if (rc == 0) {
	nid = NID_secp521r1;	/* P-521 */
	if (verbose) fprintf(messageFile, "Ossl_SetPubKey_ECC: nid %d %s\n", nid, OBJ_nid2sn(nid));
	group = EC_GROUP_new_by_curve_name(nid);	/* freed @1 */
	if (group == NULL) {
	    fprintf(messageFile, "Ossl_SetPubKey_ECC: unable to EC_GROUP_new_by_curve_name\n");
	    rc = ERROR_CODE;
	}
    }
    /* create a new EC_POINT */
    if (rc == 0) {
	ec_point = EC_POINT_new(group);		/* freed @2 */
	if (ec_point == NULL) {
	    fprintf(messageFile, "Ossl_SetPubKey_ECC: unable to EC_POINT_new\n");
	    rc = ERROR_CODE;
	}
    }
    /* Sets the EC_GROUP P-521 of an EC_KEY object */
    if (rc == 0) {
	irc = EC_KEY_set_group(*ecPubKey, group);
	if (irc == 0)  {
	    fprintf(messageFile, "Ossl_SetPubKey_ECC: unable to EC_KEY_set_group\n");
	    rc = ERROR_CODE;
	}
    }
    /* assign the public key to the EC_POINT */
    if (rc == 0) {
	/** Decodes a EC_POINT from a octet string
	 *  \param  group  underlying EC_GROUP object
	 *  \param  p      EC_POINT object
	 *  \param  buf    memory buffer with the encoded ec point
	 *  \param  len    length of the encoded ec point
	 *  \param  ctx    BN_CTX object (optional)
	 *  \return 1 on success and 0 if an error occured
	 */
	irc = EC_POINT_oct2point(group,
				 ec_point,
				 publicKey,
				 publicKeyLength,
				 NULL);
	if (irc == 0) {
	    fprintf(messageFile, "Ossl_SetPubKey_ECC: unable to EC_POINT_oct2point\n");
	    rc = ERROR_CODE;
	}
    }
    if (rc == 0) {
	/** Sets the public key of a EC_KEY object.
	 *  \param  key  EC_KEY object
	 *  \param  pub  EC_POINT object with the public key (note: the EC_KEY object
	 *               will use an own copy of the EC_POINT object).
	 *  \return 1 on success and 0 if an error occurred.
	 */
	irc = EC_KEY_set_public_key(*ecPubKey, ec_point);
	if (irc == 0) {
	    fprintf(messageFile, "Ossl_SetPubKey_ECC: unable to EC_KEY_set_public_key\n");
	    rc = ERROR_CODE;
	}
    }
    /* sanity check */
    if (rc == 0) {
	/** Verifies that a private and/or public key is valid.
	 *  \param  key  the EC_KEY object
	 *  \return 1 on success and 0 otherwise.
	 */
	irc = EC_KEY_check_key(*ecPubKey);
	if (irc == 0) {
	    fprintf(messageFile, "Ossl_SetPubKey_ECC: unable to EC_KEY_check_key\n");
	    rc = ERROR_CODE;
	}
    }
    /* cleanup */
    if (group != NULL) {
	EC_GROUP_free(group);		/* @1 */
    }
    if (ec_point != NULL) {
	EC_POINT_free(ec_point);	/* @2 */
    }
    return rc;
}
