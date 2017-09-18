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

#include <csulincl.h>

#include "cca_functions.h"
#include "cca_functions_ecc.h"
#include "debug.h"
#include "utils.h"

extern FILE* messageFile;
extern int verbose;

/* key_values_structure for skeleton key token */
static const char eccP521Struct[] = {0x00,		/* prime curve */
				     0x00,		/* reserved */
				     0x02, 0x09,	/* P-521 */
				     0x00, 0x00,	/* length of the private key d */
				     0x00, 0x00,	/* length of the public key */
};

/* PKA_Key_Token_Build_ECC() builds a skeleton RSA 2048-bit key token

 */

int PKA_Key_Token_Build_ECCP521(long *token_length,	/* i/o: skeleton key token length */
				unsigned char *token)	/* output: skeleton key token */
{
    int			rc = 0;
    long		return_code = 0;
    long		reason_code = 0;
    long		exit_data_length = 0;
    long        	rule_array_count = 0;
    unsigned char 	rule_array[16];	/* rule array can be either 1 or 2 8-byte values */
    long          	key_values_structure_length;	/* key parameter values */
    unsigned char 	key_values_structure[2500];	/* maximum length */
    long		key_name_length;
    long          	reserved_1_length;
    long          	reserved_2_length;
    long          	reserved_3_length;
    long          	reserved_4_length;
    long          	reserved_5_length;

    if (verbose) fprintf(messageFile, "PKA_Key_Token_Build_ECCP521: create a skeleton key token\n");

    rule_array_count = 2;
    memcpy(rule_array, "ECC-PAIR", 8);	/* ECC public and private key pair */
    memcpy(rule_array + 8, "SIG-ONLY", 8);	/* signing key */
    
    key_values_structure_length = 8;
    memcpy(key_values_structure, eccP521Struct,
	   sizeof(eccP521Struct));	/* ECC P-521 */
    
    key_name_length = 0;
    
    reserved_1_length = 0;
    reserved_2_length = 0;
    reserved_3_length = 0;
    reserved_4_length = 0;
    reserved_5_length = 0;

    /* create skeleton */
    CSNDPKB(&return_code,
	    &reason_code,
	    &exit_data_length,
	    NULL,
	    &rule_array_count,
	    rule_array,
	    &key_values_structure_length,
	    key_values_structure,
	    &key_name_length,
	    rule_array,	 			/* key_name, even though the length is 0, the API
						   does not accept a NULL pointer here */
	    &reserved_1_length,
	    NULL,				/* reserved_1 */
	    &reserved_2_length,
	    NULL,				/* reserved_2 */
	    &reserved_3_length,
	    NULL,				/* reserved_3 */
	    &reserved_4_length,
	    NULL,				/* reserved_4 */
	    &reserved_5_length,
	    NULL,				/* reserved_5 */
	    token_length,
	    token);				/* output skeleton key token */
    if (verbose || (return_code != 0)) {
	fprintf(messageFile,
		" PKA_Key_Token_Build_ECCP521: CSNDPKB return_code %08lx reason_code %08lx\n",
		return_code, reason_code);
    }
    if (return_code != 0) {
	CCA_PrintError(return_code, reason_code);
	rc = ERROR_CODE;
    }
    return rc;
}

/* Digital_Signature_Generate_ECC() generates a digital signature

   'signature_field' is the output signature.
   'hash' is the hash of the data to be signed.
   'PKA_private_key' is a PKA96 key pair, the CCA key token
*/

int Digital_Signature_Generate_ECC(unsigned long *signature_field_length,	/* i/o */
				   unsigned long *signature_bit_length,		/* output */
				   unsigned char *signature_field,		/* output */
				   unsigned long PKA_private_key_length,	/* input */
				   unsigned char *PKA_private_key,		/* input */
				   unsigned long hash_length,			/* input */
				   unsigned char *hash)				/* input */
{
    int			rc = 0;
    long		return_code = 0;
    long		reason_code = 0;
    long		exit_data_length = 0;
    long        	rule_array_count = 0;
    unsigned char 	rule_array[8];	/* rule array */

    if (verbose) fprintf(messageFile,
			 "Digital_Signature_Generate_ECC: generate the digital signature\n");
    if (verbose) PrintAll(messageFile,
			  "  Digital_Signature_Generate_ECC: message hash", hash_length, hash);
    
    exit_data_length = 0;		/* must be 0 */

    rule_array_count = 1;
    memcpy(rule_array,"ECDSA   ", 8);

    CSNDDSG(&return_code,
	    &reason_code,
	    &exit_data_length,
	    NULL,
	    &rule_array_count,
	    rule_array,
	    (long *)&PKA_private_key_length,
	    PKA_private_key,
	    (long *)&hash_length,
	    hash,
	    (long *)signature_field_length,
	    (long *)signature_bit_length,
	    signature_field);
    if (verbose || (return_code != 0)) {
	fprintf(messageFile,
		"  Digital_Signature_Generate_ECC: CSNDDSG return_code %08lx reason_code %08lx\n",
		return_code, reason_code);
    }
    if (return_code != 0) {
	CCA_PrintError(return_code, reason_code);
	rc = ERROR_CODE;
    }
    if (return_code == 0) {
	if (verbose) PrintAll(messageFile,
			      "  Digital_Signature_Generate_ECC: signature",
			      *signature_field_length, signature_field);
    }
    return rc;
}
   
/* Digital_Signature_Verify_ECC() verifies the signature using the coprocessor.

   'key_token' can be either the public/private key pair or the public key.
   'hash' is a hash of the data to be verified.
   'signature_field' is the signature to be verified.
*/

int Digital_Signature_Verify_ECC(unsigned long signature_field_length,	/* input */
			     unsigned char *signature_field,		/* input */
			     unsigned long key_token_length,		/* input */
			     unsigned char *key_token,			/* input */
			     unsigned long hash_length,			/* input */
			     unsigned char *hash)			/* input */
{
    int			rc = 0;
    long		return_code = 0;
    long		reason_code = 0;
    long		exit_data_length = 0;
    long        	rule_array_count = 0;
    unsigned char 	rule_array[8];	/* rule array */

    if (verbose) fprintf(messageFile,
			 "Digital_Signature_Verify_ECC: "
			 "verify the digital signature using the coprocessor\n");

    exit_data_length = 0;			/* must be 0 */
    
    rule_array_count = 1;
    memcpy(rule_array,"ECDSA   ", 8);
	
    CSNDDSV(&return_code,
	    &reason_code,
	    &exit_data_length,
	    NULL,
	    &rule_array_count,
	    rule_array,
	    (long *)&key_token_length,
	    key_token,
	    (long *)&hash_length,
	    hash,
	    (long *)&signature_field_length,
	    signature_field);

    if (verbose || (return_code != 0)) {
	fprintf(messageFile,
		"  Digital_Signature_Verify_ECC: CSNDDSV return_code %08lx reason_code %08lx\n",
		return_code, reason_code);
    }
    if (return_code != 0) {
	CCA_PrintError(return_code, reason_code);
	rc = ERROR_CODE;
    }
    return rc;
}

