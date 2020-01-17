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
#include <time.h>

/* CCA library */
#if defined AIX
#include <csufincl.h>
#elif defined Linux
#include <csulincl.h>
#else
#error "Must define either AIX or Linux"
#endif

/* local */
#include "cca_functions.h"
#include "cca_structures.h"
#include "ossl_functions.h"
#include "debug.h"
#include "utils.h"

extern FILE* messageFile;
extern int verbose;

/* local prototypes */

int PadCCAString(unsigned char *out, const char *in, size_t length);


/* PadCCAString() pads the input string with trailing spaces.  This pattern is used by the CCA
   profile ID.

   The array 'in' must be of size 'length'.

   'out' is not a C string, in that it does not have a NUL terminator.
*/

int PadCCAString(unsigned char *out, const char *in, size_t length)
{
    int		rc = 0;
    size_t 	inLength;

    if (rc == 0) {
        inLength = strlen(in);
        if (inLength > length) {
            fprintf(messageFile, "Error, Illegal CCA profile ID %s\n", in);
            rc = ERROR_CODE;
        }
    }
    if (rc == 0) {
        memset(out, ' ', length);
        memcpy(out, in, inLength);
    }
    return rc;
}

/* Login_Control() logs in or out a user profile

   logIn TRUE: log in
   logIn FALSE: log out
*/

int Login_Control(int logIn,
                  const char *userName,
                  const char *password)

{
    int			rc = 0;
    long		return_code = 0;
    long		reason_code = 0;
    long		exit_data_length = 0;
    long        	rule_array_count = 0;
    unsigned char 	rule_array[16];		/* rule array can be either 1 or 2 8-byte values */
    unsigned char	user_id[8];
    unsigned char	auth_params[1];
    long 		auth_params_length;
    unsigned char	dummy[1];		/* dummy data for logout */
    long 		auth_data_length;
    unsigned char 	*auth_data;

    /* pad with trailing spaces */
    if (rc == 0) {
        rc = PadCCAString(user_id, userName, sizeof(user_id));
    }
    if (rc == 0) {
        auth_params_length = 0;
        auth_params[0] ='\0';

        if (logIn) {
            if (verbose) fprintf(messageFile, "Login_Control: Log in the user profile\n");
            rule_array_count = 2;
            memcpy(rule_array,"LOGON   ", 8);
            memcpy(rule_array + 8,"PPHRASE ", 8);
            auth_data_length = strlen(password);
            auth_data = (unsigned char *)password;
        }
        else {
            if (verbose) fprintf(messageFile, "Login_Control: Log out the user profile\n");
            rule_array_count = 1;
            memcpy(rule_array,"LOGOFF  ", 8);
            auth_data_length = 0;	/* must be 0 even though password not used */
            auth_data = dummy;
        }
        CSUALCT(&return_code,
                &reason_code,
                &exit_data_length,
                NULL,
                &rule_array_count,
                rule_array,
                user_id,		/* profile user ID */
                &auth_params_length,	/* auth_params_length */
                auth_params,		/* auth_params, cannot be NULL */
                &auth_data_length,	/* auth_data_length */
                auth_data);		/* auth_data, cannot be NULL */

        if (verbose || (return_code != 0)) {
            fprintf(messageFile, "  Login_Control: CSUALCT return_code %08lx reason_code %08lx\n",
                    return_code, reason_code);
            fprintf(messageFile, "  Login_Control: CSUALCT CCA profile (user name): %s\n", userName);
        }
        if (return_code != 0) {
            CCA_PrintError(return_code, reason_code);
            rc = ERROR_CODE;
        }
    }
    return rc;
}

/* Password_ToMechanism() constructs a CCA mechanism in the format required by the
   Access_Control_Initialization verb verb_data_2.

   'password' is a cleartext C string

   ThE format is:

   length (2) length of the following fields, 32 bytes 0x0020
   mechanism ID (2) passphrase is 0x0001
   mechanism strength (2) 0x0180
   expiration date (4) 0x07da (2010) 0x06 June 0x01 1st
   attributes (4) - renewable 0x80 00 00 00
   mechanism data (20) - SHA1 hash of password
*/

int Password_ToMechanism(unsigned char 	**mechanism,
                         size_t 	*mechanismLength,
                         unsigned int 	passwordExpire,
                         const char 	*password)
{
    int 	rc = 0;
    time_t	currentTime;	/* right now */
    struct tm 	*timeTm;
    time_t	newTime;	/* passwordExpire months from now */

    if (rc == 0) {
        *mechanismLength = 34;
        rc = Malloc_Safe(mechanism, *mechanismLength, *mechanismLength);
    }
    /* get the current time as a time_t */
    if (rc == 0) {
        currentTime = time(NULL);
        if (currentTime == (time_t)-1) {
            fprintf(messageFile, "Error, Server cannot get current time\n");
            rc = ERROR_CODE;
        }
    }
    /* convert to a tm structure */
    if (rc == 0) {
        timeTm = localtime(&currentTime);
        if (timeTm == NULL) {
            fprintf(messageFile, "Error, Server cannot convert current time\n");
            rc = ERROR_CODE;
        }
    }
    /* add the number of months until the password expires */
    if (rc == 0) {
        timeTm->tm_mon += passwordExpire;
        /* convert the structure, adjusting to legal values */
        newTime = mktime(timeTm);
        if (newTime == (time_t)-1) {
            fprintf(messageFile, "Error, Server cannot calculate password expiration date\n");
            rc = ERROR_CODE;
        }
    }
    if (rc == 0) {
        /* length */
        (*mechanism)[0] = 0x00;
        (*mechanism)[1] = 0x20;
        /* mechanism is passphrase */
        (*mechanism)[2] = 0x00;
        (*mechanism)[3] = 0x01;
        /* strength, the maximum allowed is 255 decimal */
        (*mechanism)[4] = 0x00;
        (*mechanism)[5] = 0xff;
        /* expiration date */
        /* year, C is 1900 based, CCA is 0 based */
        (*mechanism)[6] = (char)(((timeTm->tm_year + 1900) & 0xff00) >> 8);
        (*mechanism)[7] = (char)(( timeTm->tm_year + 1900) & 0x00ff);
        /* month, because C is 0 based and CCA is 1 based */
        (*mechanism)[8] = (char)((timeTm->tm_mon + 1) & 0x00ff);	/* month */
        (*mechanism)[9] = (char)(timeTm->tm_mday & 0xff);		/* day */
        /* attributes */
        (*mechanism)[10] = 0x80;
        (*mechanism)[11] = 0x00;
        (*mechanism)[12] = 0x00;
        (*mechanism)[13] = 0x00;
        /* SHA-1 hash of password */
        Ossl_SHA1(&((*mechanism)[14]),
                  strlen(password), password,
                  0, NULL);
    }
    return rc;
}

/* Access_Control_Initialization() changes the password for the specified CCA profile (user)

   passwordExpire gives the expiration period in months.
*/

int Access_Control_Initialization(const char *profileID,
                                  unsigned int passwordExpire,
                                  const char *password)
{
    int			rc = 0;
    long		return_code = 0;
    long		reason_code = 0;
    long		exit_data_length = 0;
    long        	rule_array_count = 2;
    unsigned char 	rule_array[16];
    unsigned char	user_id[8];
    long		userIDLength;
    unsigned char 	*mechanism = NULL;
    size_t 		mechanismLength;


    /* pad with trailing spaces */
    if (rc == 0) {
        userIDLength = sizeof(user_id);
        rc = PadCCAString(user_id, profileID, sizeof(user_id));
    }
    /* construct the CCA mechanism */
    if (rc == 0) {
        rc = Password_ToMechanism(&mechanism,
                                  &mechanismLength,
                                  passwordExpire,
                                  password);
    }
    if (rc == 0) {
        if (verbose) fprintf(messageFile,
                             "Access_Control_Initialization: Changing password for profile %s\n",
                             profileID);
        memcpy(rule_array,    "CHG-AD  ", 8);	/* change a user password */
        memcpy(rule_array + 8,"PROTECTD", 8);	/* proof that the user has authenticated */

        CSUAACI(&return_code,
                &reason_code,
                &exit_data_length,
                NULL,			/* exit data */
                &rule_array_count,
                rule_array,
                &userIDLength,
                user_id,		/* 8 chacter profile ID */
                (long *)&mechanismLength,
                mechanism);
        if (verbose || (return_code != 0)) {
            fprintf(messageFile,
                    "  Access_Control_Initialization: CSUAACI return_code %08lx reason_code %08lx\n",
                    return_code, reason_code);
        }
        if (return_code != 0) {
            CCA_PrintError(return_code, reason_code);
            rc = ERROR_CODE;
        }

    }
    free(mechanism);
    return rc;
}

/* Crypto_Facility_SetClock() sets the card clock to the current time.

   This should never be used.  It's here only because my (Ken Goldman) 4764 has a broken clock that
   drifts excessively.  I hacked a repair by setting the clock every hour using a cron job.
*/

int Crypto_Facility_SetClock()
{
    int			rc = 0;
    long		return_code = 0;
    long		reason_code = 0;
    long		exit_data_length = 0;
    long        	rule_array_count = 1;
    unsigned char 	rule_array[8];
    unsigned char	verb_data[17];		/* YYYYMMDDHHmmSSWW + nul */
    long 		verb_data_length = sizeof(verb_data) - 1;
    time_t		gmt;
    long		len;	/* length of string */

    if (rc == 0) {
        gmt = time(NULL);
        len = strftime((char *)verb_data, verb_data_length + 1, "%Y%m%d%H%M%S0%w", gmtime(&gmt));
        verb_data[15] += 1;	/* C is 0 based, CCA is 1 based */
        if (verbose) fprintf(messageFile, "Crypto_Facility_SetClock: Time is %s\n", verb_data);
        if (len != verb_data_length) {
            fprintf(messageFile, "Error, TIme string length %ld is not %ld\n",
                    len, verb_data_length);
            rc = ERROR_CODE;
        }
    }
    if (rc == 0) {
        if (verbose) fprintf(messageFile,
                             "Crypto_Facility_SetClock: Resetting clock time\n");
        memcpy(rule_array, "SETCLOCK", 8);

        CSUACFC(&return_code,
                &reason_code,
                &exit_data_length,
                NULL,			/* exit data */
                &rule_array_count,
                rule_array,
                &verb_data_length,
                verb_data);
        if (verbose || (return_code != 0)) {
            fprintf(messageFile,
                    "  Crypto_Facility_SetClock: CSUACFC return_code %08lx reason_code %08lx\n",
                    return_code, reason_code);
        }
        if (return_code != 0) {
            CCA_PrintError(return_code, reason_code);
            rc = ERROR_CODE;
        }
    }
    return rc;
}

/* Random_Number_Generate_Long() gets a random number from the card.

 */

int Random_Number_Generate_Long(unsigned char *random_number,
                                size_t random_number_length_in)
{
    int			rc = 0;
    long		return_code = 0;
    long		reason_code = 0;
    long		exit_data_length = 0;
    long        	rule_array_count = 1;
    unsigned char 	rule_array[8];

    long seed_length = 0;
    long random_number_length = random_number_length_in;

    if (rc == 0) {
        memcpy(rule_array,"RANDOM  ", 8);
#if 0
        if (verbose) fprintf(messageFile, "Random_Number_Generate_Long: \n");
#endif
        /* get random numbers */
        CSNBRNGL(&return_code,
                 &reason_code,
                 &exit_data_length,
                 NULL,			/* exit data */
                 &rule_array_count,
                 rule_array,
                 &seed_length,
                 NULL,			/* seed */
                 &random_number_length,
                 random_number);
#if 0
        if (return_code == 0) {
            if (verbose) PrintAll(messageFile,
                                  "  Random_Number_Generate_Long: ",
                                  random_number_length ,
                                  random_number);
        }
#endif
        if (verbose || (return_code != 0)) {
            fprintf(messageFile,
                    "  Random_Number_Generate_Long: CSNBRNGL return_code %08lx reason_code %08lx\n",
                    return_code, reason_code);
        }
        if (return_code != 0) {
            CCA_PrintError(return_code, reason_code);
            rc = ERROR_CODE;
        }
    }
    if (rc == 0) {
        if (random_number_length_in != (unsigned long)random_number_length) {
            rc = ERROR_CODE;
        }
    }
    return rc;
}

/* Key_Generate() generates an AES key

   generated_key_identifier_1 must be a 64-byte array
*/

int Key_Generate(unsigned char *generated_key_identifier_1)	/* output: key token */
{
    int		rc = 0;
    long	return_code = 0;
    long	reason_code = 0;
    long	exit_data_length = 0;

    unsigned char key_form[8];
    unsigned char key_length[8];
    unsigned char key_type_1[8];
    unsigned char key_type_2[8];
    unsigned char KEK_key_identifier_1[64];
    unsigned char KEK_key_identifier_2[64];
    unsigned char generated_key_identifier_2[64];

    memcpy(key_form,   "OP      ", 8);
    memcpy(key_length, "KEYLN16 ", 8);
    memcpy(key_type_1, "AESDATA ", 8);
    memcpy(key_type_2, "        ", 8);
    memset(KEK_key_identifier_1, 0x00, 64);
    memset(KEK_key_identifier_2, 0x00, 64);
    memset(generated_key_identifier_1, 0x00, 64);
    memset(generated_key_identifier_2, 0x00, 64);

    if (verbose) fprintf(messageFile, "Key_Generate: generate an AES key\n");

    /* generate an AES key */
    CSNBKGN(&return_code,
            &reason_code,
            &exit_data_length,
            NULL,			/* exit data */
            key_form,
            key_length,
            key_type_1,
            key_type_2,
            KEK_key_identifier_1,
            KEK_key_identifier_2,
            generated_key_identifier_1,
            generated_key_identifier_2);

#if 0
    if (return_code == 0) {
        if (verbose) PrintAll(messageFile,
                              "  Key_Generate: key token",
                              64,
                              generated_key_identifier_1);
    }
#endif
    if (verbose || (return_code != 0)) {
        fprintf(messageFile, "  Key_Generate: CSNBKGN return_code %08lx reason_code %08lx\n",
                return_code, reason_code);
    }
    if (return_code != 0) {
        CCA_PrintError(return_code, reason_code);
        rc = ERROR_CODE;
    }
    return rc;
}

/* PKA_Key_Token_Build() builds a skeleton RSA 2048-bit key token

 */

/* key_values_structure for skeleton key token */
static const char rsaCrtStruct[] = {0x08, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00,
                                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                    0x00, 0x00, 0x01, 0x00, 0x01}; 	/* RSA 2048 65537 */
static const char rsaCrtStruct4096[] = {0x10, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00,
                                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                        0x00, 0x00, 0x01, 0x00, 0x01}; 	/* RSA 4096 65537 */

/* PKA_Key_Token_Build() builds a skeleton for an RSA bitSize key.  If encrypt is FALSE, restricts
   to a signing key.
*/

int PKA_Key_Token_Build(long *token_length,	/* i/o: skeleton key token length */
                        unsigned char *token,	/* output: skeleton key token */
                        unsigned int bitSize,
                        int encrypt,
                        int useRsaAesc)
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

    if (verbose) fprintf(messageFile, "PKA_Key_Token_Build: create a skeleton key token\n");

    if (rc == 0) {
        exit_data_length = 0;			/* must be 0 */
        rule_array_count = 2;

        if (!useRsaAesc) {
            memcpy(rule_array, "RSA-CRT", 8);	/* store in CRT */
        } else {
            memcpy(rule_array, "RSA-AESC", 8);	/* store in CRT with an AES encrypted OPK */
        }
        if (!encrypt) {			/* if encrypt disallowed */
            if (verbose) fprintf(messageFile, "PKA_Key_Token_Build: sign only\n");
            memcpy(rule_array + 8, "SIG-ONLY", 8);	/* signing key */
        }
        else {
            if (verbose) fprintf(messageFile, "PKA_Key_Token_Build: sign and encrypt\n");
            memcpy(rule_array + 8, "KEY-MGMT", 8);	/* signing key */
        }
        switch (bitSize) {
        case 2048:
            memcpy(key_values_structure, rsaCrtStruct,
                   sizeof(rsaCrtStruct));			/* RSA 2048 65537 CRT */
            key_values_structure_length = sizeof(rsaCrtStruct);
            break;
        case 4096:
            memcpy(key_values_structure, rsaCrtStruct4096,
                   sizeof(rsaCrtStruct4096));		/* RSA 4096 65537 CRT */
            key_values_structure_length = sizeof(rsaCrtStruct4096);
            break;
        default:
            if (verbose) {
                fprintf(messageFile, "  PKA_Key_Token_Build: Illegal bitSize %u\n", bitSize);
            }
            rc = ERROR_CODE;
            break;
        }
    }

    if (rc == 0) {

        key_name_length = 0;

        reserved_1_length = 0;
        reserved_2_length = 0;
        reserved_3_length = 0;
        reserved_4_length = 0;
        reserved_5_length = 0;

        if (verbose) fprintf(messageFile, "PKA_Key_Token_Build: rule array count %lu\n",
                             rule_array_count);
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
            fprintf(messageFile, "  PKA_Key_Token_Build: CSNDPKB return_code %08lx reason_code %08lx\n",
                    return_code, reason_code);
        }
        if (return_code != 0) {
            CCA_PrintError(return_code, reason_code);
            rc = ERROR_CODE;
        }
    }
    return rc;
}

/* PKA_Key_Generate() generates an RSA key pair using the skeleton key token

 */

int PKA_Key_Generate(long *generated_key_identifier_length,	/* i/o: key token */
                     unsigned char *generated_key_identifier,	/* output */
                     long skeleton_key_token_length,		/* input */
                     unsigned char *skeleton_key_token)	/* input */
{
    int			rc = 0;
    long		return_code = 0;
    long		reason_code = 0;
    long		exit_data_length = 0;
    long        	rule_array_count = 0;
    unsigned char 	rule_array[16];	/* rule array can be either 1 or 2 8-byte values */
    long        	regeneration_data_length;
    unsigned char 	transport_key_identifier[64];

    if (verbose) fprintf(messageFile, "PKA_Key_Generate: generate a key pair\n");

    exit_data_length = 0;		/* must be 0 */

    rule_array_count = 1;
    memcpy(rule_array, "MASTER  ", 8);	/* encipher with the master key */

    regeneration_data_length = 0;	/* base key on random seed */

    memset(transport_key_identifier, 0,
           sizeof(transport_key_identifier));	/* not used with MASTER */

    generated_key_identifier[0] = 0;	/* put output key token here */

    /* generate a key based on skeleton token */
    CSNDPKG(&return_code,
            &reason_code,
            &exit_data_length,
            NULL,			/* exit data */
            &rule_array_count,
            rule_array,
            &regeneration_data_length,
            NULL,			/* regeneration_data */
            &skeleton_key_token_length,
            skeleton_key_token,
            transport_key_identifier,
            generated_key_identifier_length,
            generated_key_identifier);
    if (verbose || (return_code != 0)) {
        fprintf(messageFile, "  PKA_Key_Generate: CSNDPKG return_code %08lx reason_code %08lx\n",
                return_code, reason_code);
    }
    if (return_code != 0) {
        CCA_PrintError(return_code, reason_code);
        rc = ERROR_CODE;
    }
    if (return_code == 0) {
        if (verbose) PrintAll(messageFile,
                              "  PKA_Key_Generate: key token",
                              *generated_key_identifier_length, generated_key_identifier);
    }
    return rc;
}

/* Digital_Signature_Generate() generates a digital signature

   'signature_field' is the output signature.
   'hash' is the hash of the data to be signed.
   'PKA_private_key' is a PKA96 key pair, the CCA key token
*/

int Digital_Signature_Generate(unsigned long *signature_field_length,	/* i/o */
                               unsigned long *signature_bit_length,	/* output */
                               unsigned char *signature_field,		/* output */
                               unsigned long PKA_private_key_length,	/* input */
                               unsigned char *PKA_private_key,		/* input */
                               unsigned long hash_length,		/* input */
                               unsigned char *hash,             /* input */
                               enum SignMode signmode)          /* input */
{
    int			rc = 0;
    long		return_code = 0;
    long		reason_code = 0;
    long		exit_data_length = 0;
    long        	rule_array_count = 0;
    unsigned char 	rule_array[16];	/* rule array can be either 1 or 2 8-byte values */

    if (verbose) fprintf(messageFile,
                         "Digital_Signature_Generate: generate the digital signature\n");
    if (verbose) PrintAll(messageFile,
                          "  Digital_Signature_Generate: message hash", hash_length, hash);

    exit_data_length = 0;		/* must be 0 */

    if (SIGN_PKCS_PSS == signmode) {
        rule_array_count = 2;
        memcpy(rule_array,"PKCS-PSS", 8);	/* RSASSA-PSS Signature Scheme */
        if ((SHA512_SIZE + 4) != hash_length) {
            fprintf(messageFile,
                    "  Digital_Signature_Generate: Unsupported hash length for PKCS-PSS sign mode\n");
            rc = ERROR_CODE;
        }
        memcpy(rule_array+8,"SHA-512 ", 8);  /* SHA-512 hash */
    } else {
        rule_array_count = 1;
        memcpy(rule_array,"PKCS-1.1", 8);	/* PKCS#1 padding */
    }

    if (0 == rc) {
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
                    "  Digital_Signature_Generate: CSNDDSG return_code %08lx reason_code %08lx\n",
                    return_code, reason_code);
        }
        if (return_code != 0) {
            CCA_PrintError(return_code, reason_code);
            rc = ERROR_CODE;
        }
    }
    if (0 == rc) {
        if (verbose) PrintAll(messageFile,
                              "  Digital_Signature_Generate: signature",
                              *signature_field_length, signature_field);
    }
    return rc;
}

/* Digital_Signature_Generate_Zero_Padding() generates a digital signature using a zero-padding scheme

   'signature_field' is the output signature.
   'hash' is the hash of the data to be signed.
   'PKA_private_key' is a PKA96 key pair, the CCA key token
*/

int Digital_Signature_Generate_Zero_Padding(unsigned long *signature_field_length,	/* i/o */
                               unsigned long *signature_bit_length,	/* output */
                               unsigned char *signature_field,		/* output */
                               unsigned long PKA_private_key_length,	/* input */
                               unsigned char *PKA_private_key,		/* input */
                               unsigned long rawPayloadLength,		/* input */
                               unsigned char *rawPayload)			/* input */
{
    int			rc = 0;
    long		return_code = 0;
    long		reason_code = 0;
    long		exit_data_length = 0;
    long        	rule_array_count = 0;
    unsigned char 	rule_array[16];	/* rule array can be either 1 or 2 8-byte values */

    if (verbose) fprintf(messageFile,
                         "Digital_Signature_Generate: generate the digital signature\n");
    // Commenting this out to reduce verbose output file size
    //if (verbose) PrintAll(messageFile,
    //                      "  Digital_Signature_Generate: message raw payload", rawPayloadLength, rawPayload);

    exit_data_length = 0;		/* must be 0 */

    rule_array_count = 1;
    memcpy(rule_array,"ZERO-PAD", 8);	/* Pad with zeros (although we always pass the full modulus) */

    CSNDDSG(&return_code,
            &reason_code,
            &exit_data_length,
            NULL,
            &rule_array_count,
            rule_array,
            (long *)&PKA_private_key_length,
            PKA_private_key,
            (long *)&rawPayloadLength,
            rawPayload,
            (long *)signature_field_length,
            (long *)signature_bit_length,
            signature_field);
    if (verbose || (return_code != 0)) {
        fprintf(messageFile,
                "  Digital_Signature_Generate: CSNDDSG return_code %08lx reason_code %08lx\n",
                return_code, reason_code);
    }
    if (return_code != 0) {
        CCA_PrintError(return_code, reason_code);
        rc = ERROR_CODE;
    }
    if (return_code == 0) {
        if (verbose) PrintAll(messageFile,
                              "  Digital_Signature_Generate: signature",
                              *signature_field_length, signature_field);
    }
    return rc;
}

/* Digital_Signature_Verify() verifies the signature using the coprocessor.

   'key_token' can be either the public/private key pair or the public key.
   'hash' is a hash of the data to be verified.
   'signature_field' is the signature to be verified.
*/

int Digital_Signature_Verify(unsigned long signature_field_length,	/* input */
                             unsigned char *signature_field,		/* input */
                             unsigned long key_token_length,		/* input */
                             unsigned char *key_token,			/* input */
                             unsigned long hash_length,			/* input */
                             unsigned char *hash,			/* input */
                             enum SignMode signmode)        /* input */
{
    int			rc = 0;
    long		return_code = 0;
    long		reason_code = 0;
    long		exit_data_length = 0;
    long        	rule_array_count = 0;
    unsigned char 	rule_array[16];	/* rule array can be either 1 or 2 8-byte values */

    if (verbose) fprintf(messageFile,
                         "Digital_Signature_Verify: "
                         "verify the digital signature using the coprocessor\n");

    exit_data_length = 0;			/* must be 0 */

    if (SIGN_PKCS_PSS == signmode) {
        rule_array_count = 2;
        memcpy(rule_array,"PKCS-PSS", 8);		/* PKCS#1 with RSASSA-PSS scheme */
        if (hash_length == SHA512_SIZE+4) {
            memcpy(rule_array+8,"SHA-512 ", 8);
        } else {
            fprintf(messageFile,
                    "  Digital_Signature_Verify: Unsupported hash length for RSASSA-PSS signing: %lu\n", hash_length);
            return ERROR_CODE;
        }
    } else {
        rule_array_count = 1;
        memcpy(rule_array,"PKCS-1.1", 8);		/* PKCS#1 padding */
    }

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
                "  Digital_Signature_Verify: CSNDDSV return_code %08lx reason_code %08lx\n",
                return_code, reason_code);
    }
    if (return_code != 0) {
        CCA_PrintError(return_code, reason_code);
        rc = ERROR_CODE;
    }
    return rc;
}

/* Digital_Signature_Verify_Zero_Padding() verifies the signature using the coprocessor.

   'key_token' can be either the public/private key pair or the public key.
   'hash' is a hash of the data to be verified.
   'signature_field' is the signature to be verified.
*/

int Digital_Signature_Verify_Zero_Padding(unsigned long signature_field_length,	/* input */
                                          unsigned char *signature_field,		/* input */
                                          unsigned long key_token_length,		/* input */
                                          unsigned char *key_token,			/* input */
                                          unsigned long rawPayloadLength,			/* input */
                                          unsigned char *rawPayload)			/* input */
{
    int			rc = 0;
    long		return_code = 0;
    long		reason_code = 0;
    long		exit_data_length = 0;
    long        	rule_array_count = 0;
    unsigned char 	rule_array[16];	/* rule array can be either 1 or 2 8-byte values */

    if (verbose) fprintf(messageFile,
                         "Digital_Signature_Verify_Zero_Padding: "
                         "verify the digital signature using the coprocessor\n");

    exit_data_length = 0;			/* must be 0 */

    rule_array_count = 1;
    memcpy(rule_array,"ZERO-PAD", 8);		/* Zero bytes padding */

    CSNDDSV(&return_code,
            &reason_code,
            &exit_data_length,
            NULL,
            &rule_array_count,
            rule_array,
            (long *)&key_token_length,
            key_token,
            (long *)&rawPayloadLength,
            rawPayload,
            (long *)&signature_field_length,
            signature_field);

    if (verbose || (return_code != 0)) {
        fprintf(messageFile,
                "  Digital_Signature_Verify: CSNDDSV return_code %08lx reason_code %08lx\n",
                return_code, reason_code);
    }
    if (return_code != 0) {
        CCA_PrintError(return_code, reason_code);
        rc = ERROR_CODE;
    }
    return rc;
}

/* PKA_Decrypt decrypts the input data using an RSA private key */

int PKA_Decrypt(unsigned long *cleartext_length,	/* i/o < 512 */
                unsigned char *cleartext,		/* output */
                unsigned long PKA_private_key_length,	/* input */
                unsigned char *PKA_private_key,		/* input */
                unsigned long ciphertext_length,	/* input */
                unsigned char *ciphertext)		/* input */
{
    int			rc = 0;
    long		return_code = 0;
    long		reason_code = 0;
    long		exit_data_length = 0;
    long        	rule_array_count = 0;
    unsigned char 	rule_array[16];	/* rule array can be either 1 or 2 8-byte values */

    if (verbose) fprintf(messageFile,
                         "PKA_Decrypt: Private key decrypt\n");
    if (verbose) PrintAll(messageFile,
                          "  PKA_Decrypt: ciphertext", ciphertext_length, ciphertext);

    exit_data_length = 0;		/* must be 0 */
    long data_structure_length = 0;

    rule_array_count = 1;
    memcpy(rule_array,"PKCS-1.2", 8);	/* PKCS#1 padding */

    CSNDPKD(&return_code,
            &reason_code,
            &exit_data_length,
            NULL,
            &rule_array_count,
            rule_array,
            (long *)&ciphertext_length,		/* source_encrypted_key_length */
            ciphertext,				/* source_encrypted_key */
            &data_structure_length,
            NULL,
            (long *)&PKA_private_key_length,	/* private_key_identifier_length */
            PKA_private_key,			/* private_key_identifier */
            (long *)cleartext_length,		/* clear_target_key_length */
            cleartext);				/* clear_target_key */

    if (verbose || (return_code != 0)) {
        fprintf(messageFile,
                "  PKA_Decrypt: CSNDPKD return_code %08lx reason_code %08lx\n",
                return_code, reason_code);
    }
    if (return_code != 0) {
        CCA_PrintError(return_code, reason_code);
        rc = ERROR_CODE;
    }
    return rc;
}

/* PKA_Encrypt decrypts the input data using an RSA private key */

int PKA_Encrypt(unsigned long *ciphertext_length,	/* output */
                unsigned char *ciphertext,		/* i/o */
                unsigned long PKA_public_key_length,	/* input */
                unsigned char *PKA_public_key,		/* input */
                unsigned long cleartext_length,		/* input */
                unsigned char *cleartext)		/* input < 512 */
{
    int			rc = 0;
    long		return_code = 0;
    long		reason_code = 0;
    long		exit_data_length = 0;
    long        	rule_array_count = 0;
    unsigned char 	rule_array[16];	/* rule array can be either 1 or 2 8-byte values */

    if (verbose) fprintf(messageFile,
                         "PKA_Encrypt: Private key decrypt\n");
    if (verbose) PrintAll(messageFile,
                          "  PKA_Encrypt: cleartext", cleartext_length, cleartext);

    exit_data_length = 0;		/* must be 0 */
    long data_structure_length = 0;

    rule_array_count = 1;
    memcpy(rule_array,"PKCS-1.2", 8);	/* PKCS#1 padding */

    CSNDPKE(&return_code,
            &reason_code,
            &exit_data_length,
            NULL,
            &rule_array_count,
            rule_array,
            (long *)&cleartext_length,		/* clear_source_data_length */
            cleartext,				/* clear_source_data */
            &data_structure_length,
            NULL,
            (long *)&PKA_public_key_length,	/* public_key_identifier_length */
            PKA_public_key,			/* public_key_identifier */
            (long *)ciphertext_length,		/* target_data_length */
            ciphertext);			/* target_data */

    if (verbose || (return_code != 0)) {
        fprintf(messageFile,
                "  PKA_Encrypt: CSNDPKE return_code %08lx reason_code %08lx\n",
                return_code, reason_code);
    }
    if (return_code != 0) {
        CCA_PrintError(return_code, reason_code);
        rc = ERROR_CODE;
    }
    return rc;
}

/* Symmetric_Algorithm_Encipher() encrypts cleartext to ciphertext using key_identifier */

int Symmetric_Algorithm_Encipher(long *ciphertext_length,
                                 unsigned char **ciphertext,	/* freed by caller */
                                 long cleartext_length,
                                 unsigned char *cleartext,
                                 unsigned char *initialization_vector,
                                 const unsigned char *key_identifier)
{
    int			rc = 0;
    long		return_code = 0;
    long		reason_code = 0;
    long		exit_data_length = 0;
    long        	rule_array_count = 4;
    unsigned char 	rule_array[32];			/* 4 8-byte values */
    long 		key_identifier_length = 64;	/* internal key token */
    long 		key_parms_length = 0;
    long 		block_size = 16;
    long 		initialization_vector_length = 16;
    long 		chain_data_length = 32;
    unsigned char 	chain_data[32];
    long		optional_data_length = 0;

    if (rc == 0) {
        memcpy(rule_array,      "AES     ", 8);	/* AES key */
        memcpy(rule_array + 8,  "PKCS-PAD", 8);	/* pad with 1-16 bytes */
        memcpy(rule_array + 16, "KEYIDENT", 8);	/* internal key token */
        memcpy(rule_array + 24, "INITIAL ", 8);	/* select IV */

        memset(chain_data, 0, 32);

        /* add space for PKCS padding */
        *ciphertext_length =  ((cleartext_length + 16)/16) * 16;
#if 1
        /* FIXME hack.  The GA 4765 csulcca returns up to 16 bytes more than it should */
        *ciphertext = malloc((*ciphertext_length) + 16);
#else
        *ciphertext = malloc(*ciphertext_length);
#endif
        if (*ciphertext == NULL) {
            rc = ERROR_CODE;
        }
    }
    if (rc == 0) {
        if (verbose) fprintf(messageFile, "Symmetric_Algorithm_Encipher: AES Encipher the data\n");

        /* AES encrypt */
        CSNBSAE(&return_code,
                &reason_code,
                &exit_data_length,
                NULL,			/* exit data */
                &rule_array_count,
                rule_array,
                &key_identifier_length,
                (unsigned char *)key_identifier,
                &key_parms_length,
                NULL,			/* key_parms */
                &block_size,
                &initialization_vector_length,
                initialization_vector,
                &chain_data_length,
                chain_data,
                &cleartext_length,
                cleartext,
                ciphertext_length,
                *ciphertext,
                &optional_data_length,
                NULL);			/* optional_data */
#if 0
        if (return_code == 0) {
            if (verbose) PrintAll(messageFile,
                                  "  Symmetric_Algorithm_Encipher: ciphertext",
                                  *ciphertext_length,
                                  *ciphertext);
        }
#endif
        if (verbose || (return_code != 0)) {
            fprintf(messageFile,
                    "  Symmetric_Algorithm_Encipher: CSNBSAE return_code %08lx reason_code %08lx\n",
                    return_code, reason_code);
        }
        if (return_code != 0) {
            CCA_PrintError(return_code, reason_code);
            rc = ERROR_CODE;
        }
    }
    return rc;
}

/* Symmetric_Algorithm_Decipher() decrypts ciphertext to cleartext using key_identifier */

int Symmetric_Algorithm_Decipher(long *cleartext_length,
                                 unsigned char **cleartext,	/* freed by caller */
                                 long ciphertext_length,
                                 unsigned char *ciphertext,
                                 unsigned char *initialization_vector,
                                 const unsigned char *key_identifier)
{
    int			rc = 0;
    long		return_code = 0;
    long		reason_code = 0;
    long		exit_data_length = 0;
    long        	rule_array_count = 4;
    unsigned char 	rule_array[32];			/* 4 8-byte values */
    long 		key_identifier_length = 64;	/* internal key token */
    long 		key_parms_length = 0;
    long 		block_size = 16;
    long 		initialization_vector_length = 16;
    long 		chain_data_length = 32;
    unsigned char 	chain_data[32];
    long		optional_data_length = 0;

    if (rc == 0) {
        memcpy(rule_array,      "AES     ", 8);	/* AES key */
        memcpy(rule_array + 8,  "PKCS-PAD", 8);	/* pad with 1-16 bytes */
        memcpy(rule_array + 16, "KEYIDENT", 8);	/* internal key token */
        memcpy(rule_array + 24, "INITIAL ", 8);	/* select IV */

        memset(chain_data, 0, 32);

        *cleartext_length = ciphertext_length;
        *cleartext = malloc(*cleartext_length );

        if (*cleartext == NULL) {
            rc = ERROR_CODE;
        }
    }
    if (rc == 0) {
        if (verbose) fprintf(messageFile, "Symmetric_Algorithm_Decipher: AES Decipher the data\n");

        /* AES decrypt */
        CSNBSAD(&return_code,
                &reason_code,
                &exit_data_length,
                NULL,			/* exit data */
                &rule_array_count,
                rule_array,
                &key_identifier_length,
                (unsigned char *)key_identifier,
                &key_parms_length,
                NULL,			/* key_parms */
                &block_size,
                &initialization_vector_length,
                initialization_vector,
                &chain_data_length,
                chain_data,
                &ciphertext_length,
                ciphertext,
                cleartext_length,
                *cleartext,
                &optional_data_length,
                NULL);			/* optional_data */
#if 0
        if (return_code == 0) {
            if (verbose) PrintAll(messageFile,
                                  "  Symmetric_Algorithm_Decipher: cleartext",
                                  *cleartext_length,
                                  *cleartext);
        }
#endif
        if (verbose || (return_code != 0)) {
            fprintf(messageFile,
                    "  Symmetric_Algorithm_Decipher: CSNBSAD return_code %08lx reason_code %08lx\n",
                    return_code, reason_code);
        }
        if (return_code != 0) {
            CCA_PrintError(return_code, reason_code);
            rc = ERROR_CODE;
        }
    }
    return rc;
}

/* CCA_PrintError() prints the CCA text message based on return_code and reason_code.

   The message text was taken from:

   IBM PCI Cryptographic Coprocessor
   CCA Basic Services Reference and Guide
   Release 2.41, Revised September 2003
   for IBM 4758 Models 002 and 023
*/

void CCA_PrintError(long return_code,
                    long reason_code)
{
    switch (return_code) {
    case 0x00:
        CCA_PrintReturn00(reason_code);
        break;
    case 0x04:
        CCA_PrintReturn04(reason_code);
        break;
    case 0x08:
        CCA_PrintReturn08(reason_code);
        break;
    case 0x0c:
        CCA_PrintReturn0c(reason_code);
        break;
    case 0x10:
        CCA_PrintReturn10(reason_code);
        break;
    default:
        fprintf(messageFile, "Unknown return code: %08lx\n", return_code);
    }
    return;
}

void CCA_PrintReturn00(long reason_code)
{
    switch (reason_code) {
    case 0x000:
        fprintf(messageFile, "The verb completed processing successfully.\n");
        break;
    case 0x002:
        fprintf(messageFile, "One or more bytes of a key do not have odd parity.\n");
        break;
    case 0x008:
        fprintf(messageFile, "No value is present to be processed.\n");
        break;
    case 0x097:
        fprintf(messageFile, "The key token supplies the MAC length or MACLEN4 is the default\n"
                "for key tokens that contain MAC or MACVER keys.\n");
        break;
    case 0x2BD:
        fprintf(messageFile, "A new master-key value was found to have duplicate thirds.\n");
        break;
    case 0x2BE:
        fprintf(messageFile, "A provided master-key part did not have odd parity.\n");
        break;
    case 0x2711:
        fprintf(messageFile, "A key encrypted under the old master-key was used.\n");
        break;
    default:
        fprintf(messageFile, "Unknown return code 00 reason code: %08lx\n", reason_code);
    }
    return;
}
void CCA_PrintReturn04(long reason_code)
{
    switch (reason_code) {

    case 0x001:
        fprintf(messageFile, "The verification test failed.\n");
        break;
    case 0x00D:
        fprintf(messageFile, "The key token has an initialization vector,\n"
                "and the initialization_vector parameter value is nonzero.\n"
                "The verb uses the value in the key token.\n");
        break;
    case 0x010:
        fprintf(messageFile, "The rule array and the rule-array count are too small\n"
                "to contain the complete result.\n");
        break;
    case 0x011:
        fprintf(messageFile, "The requested ID is not present in any profile in the\n"
                "specified cryptographic hardware component.\n");
        break;
    case 0x013:
        fprintf(messageFile, "The financial PIN in a PIN block is not verified.\n");
        break;
    case 0x09E:
        fprintf(messageFile, "The Key_Token_Change, Key_Record_Delete, or Key_Record_Write\n"
                "verbs did not process any records.\n");
        break;
    case 0x0A6:
        fprintf(messageFile, "The control vector is not valid because of parity bits,\n"
                "anti-variant bits, or inconsistent KEK bits, or because\n"
                "bits 59 to 62 are not zero.\n");
        break;
    case 0x0B3:
        fprintf(messageFile,
                "The control-vector keywords that are in the rule array are ignored.\n");
        break;
    case 0x11B:
        fprintf(messageFile, "The Cryptographic Coprocessor battery is low.\n");
        break;
    case 0x11F:
        fprintf(messageFile, "The PIN-block format is not consistent.\n");
        break;
    case 0x1AD:
        fprintf(messageFile, "The digital signature is not verified. The verb completed\n"
                "its processing normally.\n");
        break;
    case 0x400:
        fprintf(messageFile, "Sufficient shares have been processed to create a new master-key.\n");
        break;
    case 0x7F7:
        fprintf(messageFile, "At least one control vector bit cannot be parsed.\n");
        break;
    case 0x7FA:
        fprintf(messageFile, "The supplied passphrase is invalid.\n");
        break;
    default:
        fprintf(messageFile, "Unknown return code 04 reason code: %08lx\n", reason_code);
    }
    return;
}
void CCA_PrintReturn08(long reason_code)
{
    switch (reason_code) {

    case 0x00C:
        fprintf(messageFile, "The token-validation value in an external key token is not valid.\n");
        break;
    case 0x016:
        fprintf(messageFile, "The ID number in the request field is not valid.\n");
        break;
    case 0x017:
        fprintf(messageFile, "An access to the data area is outside the data-area boundary.\n");
        break;
    case 0x018:
        fprintf(messageFile, "The master-key verification pattern is not valid.\n");
        break;
    case 0x019:
        fprintf(messageFile, "The value that the text_length parameter specifies is not valid.\n");
        break;
    case 0x01A:
        fprintf(messageFile, "The value of the PIN is not valid.\n");
        break;
    case 0x01D:
        fprintf(messageFile, "The token-validation value in an internal key token is not valid.\n");
        break;
    case 0x01E:
        fprintf(messageFile, "No record with a matching key label is in key storage.\n");
        break;
    case 0x01F:
        fprintf(messageFile, "The control vector does not specify a DATA key.\n");
        break;
    case 0x020:
        fprintf(messageFile, "A key label format is not valid.\n");
        break;
    case 0x021:
        fprintf(messageFile, "A rule array or other parameter specifies a keyword that is not\n"
                "valid.\n");
        break;
    case 0x022:
        fprintf(messageFile, "A rule-array keyword combination is not valid.\n");
        break;
    case 0x023:
        fprintf(messageFile, "A rule-array count is not valid.\n");
        break;
    case 0x024:
        fprintf(messageFile, "The action command must be specified in the rule array.\n");
        break;
    case 0x025:
        fprintf(messageFile, "The object type must be specified in the rule array.\n");
        break;
    case 0x027:
        fprintf(messageFile, "A control vector violation occurred. Check all control vectors\n"
                "employed with the verb. For security reasons, no detail is provided.\n");
        break;
    case 0x028:
        fprintf(messageFile, "The service code does not contain numerical character data.\n");
        break;
    case 0x029:
        fprintf(messageFile, "The keyword specified by the key_form parameter is not valid.\n");
        break;
    case 0x02A:
        fprintf(messageFile, "The expiration date is not valid.\n");
        break;
    case 0x02B:
        fprintf(messageFile, "The length specified by the key_token_length parameter or the\n"
                "keyword specified by the key_length parameter is not valid.\n");
        break;
    case 0x02C:
        fprintf(messageFile, "A record with a matching key label already exists in key storage.\n");
        break;
    case 0x02D:
        fprintf(messageFile, "The input character string cannot be found in the code table.\n");
        break;
    case 0x02E:
        fprintf(messageFile, "The card-validation value (CVV) is not valid.\n");
        break;
    case 0x02F:
        fprintf(messageFile, "A source key token is unusable because it contains data that is\n"
                "not valid or is undefined.\n");
        break;
    case 0x030:
        fprintf(messageFile, "One or more keys has a master-key verification pattern that is "
                "not valid.\n");
        break;
    case 0x031:
        fprintf(messageFile, "A key-token version number found in a key token is not supported.\n");
        break;
    case 0x032:
        fprintf(messageFile, "The key-serial-number specified in the rule array is not valid.\n");
        break;
    case 0x033:
        fprintf(messageFile, "The value that the text_length parameter identifies is not a\n"
                "multiple of the cryptographic algorithm block length.\n");
        break;
    case 0x036:
        fprintf(messageFile, "The value that the pad_character parameter specifies is not valid.\n");
        break;
    case 0x037:
        fprintf(messageFile, "The initialization vector in the key token is enciphered.\n");
        break;
    case 0x038:
        fprintf(messageFile, "The master-key verification pattern in the OCV is not valid.\n");
        break;
    case 0x03A:
        fprintf(messageFile, "The parity of the operating key is not valid.\n");
        break;
    case 0x03B:
        fprintf(messageFile, "Control information (for example, the processing method or the\n"
                "pad character) in the key token conflicts with that in the rule array.\n");
        break;
    case 0x03C:
        fprintf(messageFile, "A cryptographic request with the FIRST or MIDDLE keywords and a\n"
                "text length less than 8 bytes is not valid.\n");
        break;
    case 0x03D:
        fprintf(messageFile, "The keyword specified by the key_type parameter is not valid.\n");
        break;
    case 0x03E:
        fprintf(messageFile, "The source key is not present.\n");
        break;
    case 0x03F:
        fprintf(messageFile, "A key token has an invalid token header (for example, not an\n"
                "internal token).\n");
        break;
    case 0x040:
        fprintf(messageFile, "The key is not permitted to perform the requested operation. A\n"
                "likely cause is that key distribution usage is not enabled for the key.\n");
        break;
    case 0x041:
        fprintf(messageFile, "The key token failed consistency checking.\n");
        break;
    case 0x042:
        fprintf(messageFile, "The recovered encryption block failed validation checking.\n");
        break;
    case 0x043:
        fprintf(messageFile, "RSA encryption failed.\n");
        break;
    case 0x044:
        fprintf(messageFile, "RSA decryption failed.\n");
        break;
    case 0x048:
        fprintf(messageFile, "The value that the size parameter specifies is not valid (too small,\n"
                "too large, negative, or zero).\n");
        break;
    case 0x051:
        fprintf(messageFile, "The modulus length (key size) exceeds the allowable maximum.\n");
        break;
    case 0x055:
        fprintf(messageFile, "The date or the time value is not valid.\n");
        break;
    case 0x05A:
        fprintf(messageFile, "Access control checking failed. See the Required commands section\n"
                "for the failing verb.\n");
        break;
    case 0x05B:
        fprintf(messageFile, "The time that was sent in your logon request was more than five\n"
                "minutes different from the clock in the secure module.\n");
        break;
    case 0x05C:
        fprintf(messageFile, "The user profile is expired.\n");
        break;
    case 0x05D:
        fprintf(messageFile, "The user profile has not yet reached its activation date.\n");
        break;
    case 0x05E:
        fprintf(messageFile, "The authentication data (for example, passphrase) is expired.\n");
        break;
    case 0x05F:
        fprintf(messageFile, "Access to the data is not authorized.\n");
        break;
    case 0x060:
        fprintf(messageFile, "An error occurred reading or writing the secure clock.\n");
        break;
    case 0x064:
        fprintf(messageFile, "The PIN length is not valid.\n");
        break;
    case 0x065:
        fprintf(messageFile, "The PIN check length is not valid. It must be in the range from\n"
                "4 to the PIN length inclusive.\n");
        break;
    case 0x066:
        fprintf(messageFile, "The value of the decimalization table is not valid.\n");
        break;
    case 0x067:
        fprintf(messageFile, "The value of the validation data is not valid.\n");
        break;
    case 0x068:
        fprintf(messageFile, "The value of the customer-selected PIN is not valid, or the PIN\n"
                "length does not match the value specified by the PIN_length parameter or defined\n"
                "by the PIN-block format specified in the PIN profile.\n");
        break;
    case 0x069:
        fprintf(messageFile, "The value of the transaction_security_parameter is not valid.\n");
        break;
    case 0x06A:
        fprintf(messageFile, "The PIN-block format keyword is not valid.\n");
        break;
    case 0x06B:
        fprintf(messageFile, "The format control keyword is not valid.\n");
        break;
    case 0x06C:
        fprintf(messageFile, "The value or the placement of the padding data is not valid.\n");
        break;
    case 0x06D:
        fprintf(messageFile, "The extraction method keyword is not valid.\n");
        break;
    case 0x06E:
        fprintf(messageFile, "The value of the PAN data is not numeric character data.\n");
        break;
    case 0x06F:
        fprintf(messageFile, "The sequence number is not valid.\n");
        break;
    case 0x070:
        fprintf(messageFile, "The PIN offset is not valid.\n");
        break;
    case 0x072:
        fprintf(messageFile, "The PVV value is not valid.\n");
        break;
    case 0x074:
        fprintf(messageFile, "The clear PIN value is not valid. For example, digits other\n"
                "than 0 - 9 were found.\n");
        break;
    case 0x078:
        fprintf(messageFile, "An origin or destination identifier is not valid.\n");
        break;
    case 0x079:
        fprintf(messageFile, "The value specified by the inbound_key or source_key parameter\n"
                "is not valid.\n");
        break;
    case 0x07A:
        fprintf(messageFile, "The value specified by the inbound_KEK_count or outbound_count\n"
                "parameter is not valid.\n");
        break;
    case 0x07D:
        fprintf(messageFile, "A PKA92-encrypted key having the same EID as the local node cannot\nz"
                "be imported.\n");
        break;
    case 0x081:
        fprintf(messageFile, "Required rule-array keyword not found.\n");
        break;
    case 0x099:
        fprintf(messageFile, "The text length exceeds the system limits.\n");
        break;
    case 0x09A:
        fprintf(messageFile, "The key token that the key_identifier parameter specifies is\n"
                "not an internal key-token or a key label.\n");
        break;
    case 0x09B:
        fprintf(messageFile, "The value that the generated_key_identifier parameter specifies is\n"
                "not valid, or it is not consistent with the value that the key_form parameter\n"
                "specifies.\n");
        break;
    case 0x09C:
        fprintf(messageFile, "A keyword is not valid with the specified parameters.\n");
        break;
    case 0x09D:
        fprintf(messageFile, "The key-token type is not specified in the rule array.\n");
        break;
    case 0x09F:
        fprintf(messageFile, "The keyword supplied with the option parameter is not valid.\n");
        break;
    case 0x0A0:
        fprintf(messageFile, "The key type and the key length are not consistent.\n");
        break;
    case 0x0A1:
        fprintf(messageFile, "The value that the dataset_name_length parameter specifies is not\n"
                "valid.\n");
        break;
    case 0x0A2:
        fprintf(messageFile, "The offset value is not valid.\n");
        break;
    case 0x0A3:
        fprintf(messageFile, "The value that the dataset_name parameter specifies is not valid.\n");
        break;
    case 0x0A4:
        fprintf(messageFile, "The starting address of the output area falls inside the input\n"
                "area.\n");
        break;
    case 0x0A5:
        fprintf(messageFile, "The carryover_character_count that is specified in the chaining "
                "vector is not valid.\n");
        break;
    case 0x0A8:
        fprintf(messageFile, "A hexadecimal MAC value contains characters that are not valid,\n"
                "or the MAC on a request or reply failed because the user session key in the\n"
                "host and the adapter card do not match.\n");
        break;
    case 0x0A9:
        fprintf(messageFile, "The MDC_Generate text length is in error.\n");
        break;
    case 0x0AA:
        fprintf(messageFile, "The value of the mechanism strength in the passphrase authentication\n"
                "data structure of the user profile is less than the minimum authorization level\n"
                "required.\n");
        break;
    case 0x0AB:
        fprintf(messageFile, "The control_array_count value is not valid.\n");
        break;
    case 0x0AF:
        fprintf(messageFile, "The key token cannot be parsed because no control vector is\n"
                "present.\n");
        break;
    case 0x0B4:
        fprintf(messageFile, "A key token presented for parsing is null.\n");
        break;
    case 0x0B5:
        fprintf(messageFile, "The key token is not valid. The first byte is not valid, or an\n"
                "incorrect token type was presented.\n");
        break;
    case 0x0B7:
        fprintf(messageFile, "The key type is not consistent with the key type of the control\n"
                "vector.\n");
        break;
    case 0x0B8:
        fprintf(messageFile, "A required pointer is null.\n");
        break;
    case 0x0B9:
        fprintf(messageFile, "A disk I/O error occurred: perhaps the file is in-use, does not\n"
                "exist, and so forth.\n");
        break;
    case 0x0BA:
        fprintf(messageFile, "The key-type field in the control vector is not valid.\n");
        break;
    case 0x0BB:
        fprintf(messageFile, "The requested MAC length (MACLEN4, MACLEN6, MACLEN8) is not\n"
                "consistent with the control vector (key-A, key-B).\n");
        break;
    case 0x0BF:
        fprintf(messageFile, "The requested MAC length (MACLEN6, MACLEN8) is not consistent with\n"
                "the control vector (MAC-LN-4).\n");
        break;
    case 0x0C0:
        fprintf(messageFile, "A key-storage record contains a record validation value that is not\n"
                "valid.\n");
        break;
    case 0x0CC:
        fprintf(messageFile, "A memory allocation failed. This can occur in the host and in the\n"
                "coprocessor. Try closing other host tasks. If the problem persists, contact the\n"
                "IBM support center.\n");
        break;
    case 0x0CD:
        fprintf(messageFile, "The X9.23 ciphering method is not consistent with the use of the\n"
                "CONTINUE keyword.\n");
        break;
    case 0x143:
        fprintf(messageFile, "The ciphering method that the Decipher verb used does not match the\n"
                "ciphering method that the Encipher verb used.\n");
        break;
    case 0x14F:
        fprintf(messageFile, "Either the specified cryptographic hardware component or the\n"
                "environment cannot implement this function.\n");
        break;
    case 0x154:
        fprintf(messageFile, "One of the input control vectors has odd parity.\n");
        break;
    case 0x157:
        fprintf(messageFile, "Either the data block or the buffer for the block is too small,\n"
                "or a variable has caused an attempt to create an internal data structure that\n"
                "is too large.\n");
        break;
    case 0x176:
        fprintf(messageFile, "Less data was supplied than expected or less data exists than was\n"
                "requested.\n");
        break;
    case 0x179:
        fprintf(messageFile, "A key-storage error occurred.\n");
        break;
    case 0x17E:
        fprintf(messageFile, "A time-limit violation occurred.\n");
        break;
    case 0x181:
        fprintf(messageFile, "The cryptographic hardware component reported that the data passed\n"
                "as part of a command is not valid for that command.\n");
        break;
    case 0x183:
        fprintf(messageFile, "The cryptographic hardware component reported that the user ID or\n"
                "role ID is not valid.\n");
        break;
    case 0x189:
        fprintf(messageFile, "The command was not processed because the profile cannot be used.\n");
        break;
    case 0x18A:
        fprintf(messageFile, "The command was not processed because the expiration date was\n"
                "exceeded.\n");
        break;
    case 0x18D:
        fprintf(messageFile, "The command was not processed because the active profile requires\n"
                "the user to be verified first.\n");
        break;
    case 0x18E:
        fprintf(messageFile, "The command was not processed because the maximum PIN or password\n"
                "failure limit is exceeded.\n");
        break;
    case 0x197:
        fprintf(messageFile, "There is a PIN-block consistency-check-error.\n");
        break;
    case 0x1B7:
        fprintf(messageFile, "Key cannot be completed because all required key parts have not\n"
                "yet been accumulated, or key is already complete.\n");
        break;
    case 0x1B9:
        fprintf(messageFile, "Key part cannot be added because key is complete.\n");
        break;
    case 0x1BA:
        fprintf(messageFile, "DES keys with replicated halves are not allowed.\n");
        break;
    case 0x25D:
        fprintf(messageFile, "The number of output bytes is greater than the number that is\n"
                "permitted.\n");
        break;
    case 0x2BF:
        fprintf(messageFile, "A new master-key value is one of the weak DES keys.\n");
        break;
    case 0x2C0:
        fprintf(messageFile, "A new master key cannot have the same master-key version number\n"
                "or master-key verification pattern as the current master-key.\n");
        break;
    case 0x2C1:
        fprintf(messageFile, "Both exporter keys specify the same key-encrypting key.\n");
        break;
    case 0x2C2:
        fprintf(messageFile, "Pad count in deciphered data is not valid.\n");
        break;
    case 0x2C3:
        fprintf(messageFile, "The master-key registers are not in the state required for the\n"
                "requested function.\n");
        break;
    case 0x2C9:
        fprintf(messageFile, "The algorithm or function is not available on this hardware (DES\n"
                "on a CDMF-only system, or Triple-DES on DES-only or CDMF-only system)\n");
        break;
    case 0x2CA:
        fprintf(messageFile, "A reserved parameter must be a null pointer or an expected value.\n");
        break;
    case 0x2CB:
        fprintf(messageFile, "A parameter that must have a value of zero is not valid.\n");
        break;
    case 0x2CE:
        fprintf(messageFile, "The hash value of the data block in the decrypted RSA-OAEP block\n"
                "does not match the hash of the decrypted data block.\n");
        break;
    case 0x2CF:
        fprintf(messageFile, "The block format (BT) field in the decrypted RSA-OAEP block does\n"
                "not have the correct value.\n");
        break;
    case 0x2D0:
        fprintf(messageFile, "The initial byte (I) in the decrypted RSA-OAEP block does not have\n"
                "a valid value.\n");
        break;
    case 0x2D1:
        fprintf(messageFile, "The V field in the decrypted RSA-OAEP does not have the correct\n"
                "value.\n");
        break;
    case 0x2F0:
        fprintf(messageFile, "The key-storage file path is not usable.\n");
        break;
    case 0x2F1:
        fprintf(messageFile, "Opening the key-storage file failed.\n");
        break;
    case 0x2F2:
        fprintf(messageFile, "An internal call to the key_test command failed.\n");
        break;
    case 0x2F4:
        fprintf(messageFile, "Creation of the key-storage file failed.\n");
        break;
    case 0x2F8:
        fprintf(messageFile, "An RSA key-modulus length in bits or in bytes is not valid.\n");
        break;
    case 0x2F9:
        fprintf(messageFile, "An RSA-key exponent length is not valid.\n");
        break;
    case 0x2FA:
        fprintf(messageFile, "A length in the key value structure is not valid.\n");
        break;
    case 0x2FB:
        fprintf(messageFile, "The section identification number within a key token is not valid.\n");
        break;
    case 0x302:
        fprintf(messageFile, "The PKA key-token has a field that is not valid.\n");
        break;
    case 0x303:
        fprintf(messageFile, "The user is not logged on.\n");
        break;
    case 0x304:
        fprintf(messageFile, "The requested role does not exist.\n");
        break;
    case 0x305:
        fprintf(messageFile, "The requested profile does not exist.\n");
        break;
    case 0x306:
        fprintf(messageFile, "The profile already exists.\n");
        break;
    case 0x307:
        fprintf(messageFile, "The supplied data is not replaceable.\n");
        break;
    case 0x308:
        fprintf(messageFile, "The requested ID is already logged on.\n");
        break;
    case 0x309:
        fprintf(messageFile, "The authentication data is not valid.\n");
        break;
    case 0x30A:
        fprintf(messageFile, "The checksum for the role is in error.\n");
        break;
    case 0x30B:
        fprintf(messageFile, "The checksum for the profile is in error.\n");
        break;
    case 0x30C:
        fprintf(messageFile, "There is an error in the profile data.\n");
        break;
    case 0x30D:
        fprintf(messageFile, "There is an error in the role data.\n");
        break;
    case 0x30E:
        fprintf(messageFile, "The function-control-vector header is not valid.\n");
        break;
    case 0x30F:
        fprintf(messageFile, "The command is not permitted by the function-control-vector value.\n");
        break;
    case 0x310:
        fprintf(messageFile, "The operation you requested cannot be performed because the user\n"
                "profile is in use.\n");
        break;
    case 0x311:
        fprintf(messageFile, "The operation you requested cannot be performed because the role\n"
                "is in use.\n");
        break;
    case 0x401:
        fprintf(messageFile, "The registered public key or retained private key name already\n"
                "exists.\n");
        break;
    case 0x402:
        fprintf(messageFile, "The key name (registered public key or retained private key) does\n"
                "not exist.\n");
        break;
    case 0x403:
        fprintf(messageFile, "Environment identifier data is already set.\n");
        break;
    case 0x404:
        fprintf(messageFile, "Master key share data is already set.\n");
        break;
    case 0x405:
        fprintf(messageFile, "There is an error in the EID data.\n");
        break;
    case 0x406:
        fprintf(messageFile, "There is an error in using the master key share data.\n");
        break;
    case 0x407:
        fprintf(messageFile, "There is an error in using registered public key or retained\n"
                "private key data.\n");
        break;
    case 0x408:
        fprintf(messageFile, "There is an error in using registered public key hash data.\n");
        break;
    case 0x409:
        fprintf(messageFile, "The public key hash was not registered.\n");
        break;
    case 0x40A:
        fprintf(messageFile, "The public key was not registered.\n");
        break;
    case 0x40B:
        fprintf(messageFile, "The public key certificate signature was not verified.\n");
        break;
    case 0x40D:
        fprintf(messageFile, "There is a master key shares distribution error.\n");
        break;
    case 0x40E:
        fprintf(messageFile, "The public key hash is not marked for cloning.\n");
        break;
    case 0x40F:
        fprintf(messageFile, "The registered public key hash does not match the registered hash.\n");
        break;
    case 0x410:
        fprintf(messageFile, "The master key share enciphering key could not be enciphered.\n");
        break;
    case 0x411:
        fprintf(messageFile, "The master key share enciphering key could not be deciphered.\n");
        break;
    case 0x412:
        fprintf(messageFile, "The master key share digital signature generate failed.\n");
        break;
    case 0x413:
        fprintf(messageFile, "The master key share digital signature verify failed.\n");
        break;
    case 0x414:
        fprintf(messageFile, "There is an error in reading VPD data from the adapter.\n");
        break;
    case 0x415:
        fprintf(messageFile, "Encrypting the cloning information failed.\n");
        break;
    case 0x416:
        fprintf(messageFile, "Decrypting the cloning information failed.\n");
        break;
    case 0x417:
        fprintf(messageFile, "There is an error loading new master key from master key shares.\n");
        break;
    case 0x418:
        fprintf(messageFile, "The clone information has one or more sections that are not valid.\n");
        break;
    case 0x419:
        fprintf(messageFile, "The master key share index is not valid.\n");
        break;
    case 0x41A:
        fprintf(messageFile, "The public-key encrypted-key is rejected because the EID with the\n"
                "key is the same as the EID for this node.\n");
        break;
    case 0x41B:
        fprintf(messageFile, "The private key is rejected because the key is not flagged for use\n"
                "in master-key cloning.\n");
        break;
    case 0x41C:
        fprintf(messageFile, "Token identifier of the header section is in the\n"
                "range X'20' - X'FF'.\n");
        break;
    case 0x41D:
        fprintf(messageFile, "The Active flag in section X'14' of the trusted block is not "
                "disabled.\n");
        break;
    case 0x41E:
        fprintf(messageFile, "Token identifier of the header section is not external X'1E'.\n");
        break;
    case 0x41F:
        fprintf(messageFile, "The Active flag in section X'14' of the trusted block is not\n"
                "enabled.\n");
        break;
    case 0x420:
        fprintf(messageFile, "Token identifier of the header section is not internal X'1F'.\n");
        break;
    case 0x421:
        fprintf(messageFile, "Trusted block rule section X'12' rule ID does not match input "
                "parameter rule ID.\n");
        break;
    case 0x422:
        fprintf(messageFile, "Trusted block contains a value that is too small or too large.\n");
        break;
    case 0x423:
        fprintf(messageFile, "A trusted block parameter that must have a value of zero (or a\n"
                "grouping of bits set to zero} is not valid.\n");
        break;
    case 0x424:
        fprintf(messageFile, "Trusted block public-key section failed consistency checking.\n");
        break;
    case 0x425:
        fprintf(messageFile, "Trusted block contains at least one extraneous section or\n"
                "subsection (TLV).\n");
        break;
    case 0x426:
        fprintf(messageFile, "Trusted block has at least one missing section or\n"
                "subsection (TLV).\n");
        break;
    case 0x427:
        fprintf(messageFile, "Trusted block contains at least one duplicate section or\n"
                "subsection (TLV).\n");
        break;
    case 0x428:
        fprintf(messageFile, "The expiration date of the trusted block is expired (compared\n"
                "to the cryptographic coprocessor clock).\n");
        break;
    case 0x429:
        fprintf(messageFile, "The expiration date of the trusted block precedes the activation\n"
                "date.\n");
        break;
    case 0x42A:
        fprintf(messageFile, "Trusted block public key modulus bit length is not consistent with\n"
                "the byte length. The bit length must be less than or equal to 8 * byte length,\n"
                "and greater than 8 (byte length - 1).\n");
        break;
    case 0x42B:
        fprintf(messageFile, "Trusted block public key modulus length in bits exceeds maximum\nzz"
                "allowed bit length as defined by the function control vector (FCV).\n");
        break;
    case 0x42C:
        fprintf(messageFile, "One or more trusted block sections or TLV objects contains data\n"
                "that is not valid (for example, invalid label data in label section X'13').\n");
        break;
    case 0x42D:
        fprintf(messageFile, "Trusted block verification attempted by function other than\n"
                "CSNDDSV, CSNDKTC, CSNBKPI, CSNDRKX, or CSNDTBC.\n");
        break;
    case 0x42E:
        fprintf(messageFile, "Trusted block rule ID contained within the rule section contains\n"
                "one or more invalid characters.\n");
        break;
    case 0x42F:
        fprintf(messageFile, "The key length or control vector of the source key does not match\n"
                "the rule section in the trusted block that was selected by the rule ID input\n"
                "parameter.\n");
        break;
    case 0x430:
        fprintf(messageFile, "The activation date is not valid.\n");
        break;
    case 0x431:
        fprintf(messageFile, "The source-key label does not match the template in the export\n"
                "key DES token parameters TLV object of the selected trusted block rule section.\n");
        break;
    case 0x432:
        fprintf(messageFile, "The control-vector value specified in the common export key\n"
                "parameters TLV object in the selected rule section of the trusted block contains\n"
                "a control vector that is not valid.\n");
        break;
    case 0x433:
        fprintf(messageFile, "The source-key label template in the export key DES token parameters\n"
                "TLV object in the selected rule section of the trusted block contains a label\n"
                "template that is not valid.\n");
        break;
    case 0x435:
        fprintf(messageFile, "Key wrapping option input error.\n");
        break;
    case 0x436:
        fprintf(messageFile, "Key wrapping Security Relevant Data Item (SRDI) error.\n");
        break;
    case 0x44C:
        fprintf(messageFile, "There is a general hardware device driver execution error.\n");
        break;
    case 0x44D:
        fprintf(messageFile, "There is a hardware device driver parameter that is not valid.\n");
        break;
    case 0x44E:
        fprintf(messageFile, "There is a hardware device driver non-valid buffer length.\n");
        break;
    case 0x44F:
        fprintf(messageFile, "The hardware device driver has too many opens. The device cannot\n"
                "open now.\n");
        break;
    case 0x450:
        fprintf(messageFile, "The hardware device driver is denied access.\n");
        break;
    case 0x451:
        fprintf(messageFile, "The hardware device driver device is busy and cannot perform the\n"
                "request now.\n");
        break;
    case 0x452:
        fprintf(messageFile, "The hardware device driver buffer is too small and the received\nz"
                "data is truncated.\n");
        break;
    case 0x453:
        fprintf(messageFile, "The hardware device driver request is interrupted and the request\n"
                "is aborted.\n");
        break;
    case 0x454:
        fprintf(messageFile, "The hardware device driver detected a security tamper event.\n");
        break;
    case 0x7F2:
        fprintf(messageFile, "The environment variable that was used to set the default\n"
                "coprocessor is not valid, or does not exist for a coprocessor in the system.\n");
        break;
    case 0x7F4:
        fprintf(messageFile, "The contents of a chaining vector are not valid. Ensure that the\n"
                "chaining vector was not modified by your application program.\n");
        break;
    case 0x7F6:
        fprintf(messageFile, "No RSA private key information is provided.\n");
        break;
    case 0x7F9:
        fprintf(messageFile, "A default coprocessor environment variable is not valid.\n");
        break;
    case 0x802:
        fprintf(messageFile, "The current-key serial number (CKSN) field in the PIN_profile "
                "variable is not valid (not hexadecimal or too many 1 bits).\n");
        break;
    case 0x803:
        fprintf(messageFile, "There is a non-valid message length in the OAEP-decoded\n"
                "zinformation.\n");
        break;
    case 0x805:
        fprintf(messageFile, "No message found in the OAEP-decoded data.\n");
        break;
    case 0x806:
        fprintf(messageFile, "There is a non-valid RSA Enciphered Key cryptogram: OAEP optional\n"
                "encoding parameters failed validation.\n");
        break;
    case 0x807:
        fprintf(messageFile, "The RSA public key is too small to encrypt the symmetric "
                "(AES or DES) key.\n");
        break;
    case 0x80E:
        fprintf(messageFile, "The active role does not permit you to change the characteristic\n"
                "of a double-length key in the Key_Part_Import parameter.\n");
        break;
    case 0x811:
        fprintf(messageFile, "The specified key token is not null.\n");
        break;
    case 0x829:
        fprintf(messageFile, "There is an inconsistency in the specification of a cryptographic\n"
                "algorithm. The verb contains multiple keywords or parameters that indicate the\n"
                "algorithm to be used, and at least one of these specifies or implies a different\n"
                "algorithm from the others.\n");
        break;
    case 0x82F:
        fprintf(messageFile, "The key_type value is not compatible with the key_form value.\n");
        break;
    case 0x831:
        fprintf(messageFile, "The key_length value is not compatible with the key_type value.\n");
        break;
    case 0x832:
        fprintf(messageFile, "Either an AES key-token contains an invalid clear-key bit length\n"
                "(not 128, 192, or 256), or an external DES key-token with a token version\n"
                "number of X'01' has an invalid key-length flag.\n");
        break;
    case 0x833:
        fprintf(messageFile, "Byte length of encrypted key in AES key-token is invalid.\n");
        break;
    case 0x83A:
        fprintf(messageFile, "An input/output error occurred while accessing the logged on\n"
                "users table.\n");
        break;
    case 0x83E:
        fprintf(messageFile, "Invalid wrapping type.\n");
        break;
    case 0x83F:
        fprintf(messageFile, "Control vector enhanced bit (bit 56) conflicts with key\n"
                "wrapping keyword.\n");
        break;
    case 0x841:
        fprintf(messageFile, "A key token contains invalid payload.\n");
        break;
    case 0x842:
        fprintf(messageFile, "Clear-key bit length is out of range.\n");
        break;
    case 0x843:
        fprintf(messageFile, "Input key token cannot have a key present when importing the\n"
                "first key part; skeleton key token is required.\n");
        break;
    case 0xBB9:
        fprintf(messageFile, "The RSA-OAEP block contains a PIN block and the verb did not\n"
                "request PINBLOCK processing.\n");
        break;
    case 0xBC5:
        fprintf(messageFile, "The LRC checksum in the AES key-token does not match the LRC\n"
                "checksum of the clear key.\n");
        break;
    case 0x1770:
        fprintf(messageFile, "The specified device is already allocated.\n");
        break;
    case 0x1771:
        fprintf(messageFile, "No device is allocated.\n");
        break;
    case 0x1772:
        fprintf(messageFile, "The specified device does not exist.\n");
        break;
    case 0x1773:
        fprintf(messageFile, "The specified device is an improper type.\n");
        break;
    case 0x1774:
        fprintf(messageFile, "Use of the specified device is not authorized for this user.\n");
        break;
    case 0x1775:
        fprintf(messageFile, "The specified device is not varied online.\n");
        break;
    case 0x1776:
        fprintf(messageFile, "The specified device is in a damaged state.\n");
        break;
    case 0x1777:
        fprintf(messageFile, "The key-storage file is not designated.\n");
        break;
    case 0x1778:
        fprintf(messageFile, "The key-storage file is not found.\n");
        break;
    case 0x1779:
        fprintf(messageFile, "The specified key-storage file is either the wrong type or the\n"
                "wrong format.\n");
        break;
    case 0x177A:
        fprintf(messageFile, "The user is not authorized to use the key-storage file.\n");
        break;
    case 0x177B:
        fprintf(messageFile, "The specified CCA verb request is not permitted from a secondary\n"
                "thread.\n");
        break;
    case 0x177C:
        fprintf(messageFile, "A cryptographic resource is already allocated.\n");
        break;
    case 0x177D:
        fprintf(messageFile, "The length of the cryptographic resource name is not valid.\n");
        break;
    case 0x177E:
        fprintf(messageFile, "The cryptographic resource name is not valid, or does not refer\n"
                "to a coprocessor that is available in the system.\n");
        break;
    default:
        fprintf(messageFile, "Unknown return code 08 reason code: %08lx\n", reason_code);
    }
    return;
}

void CCA_PrintReturn0c(long reason_code)
{
    switch (reason_code) {
    case 0x05D:
        fprintf(messageFile, "The security server is not available or not loaded.\n");
        break;
    case 0x061:
        fprintf(messageFile,
                "File space in key storage is insufficient to complete the operation.\n");
        break;
    case 0x0C4:
        fprintf(messageFile,
                "The device driver, the security server, or the directory server is not\n"
                "installed, or is not active, or in AIX, file permissions are not valid\n"
                "for your application.\n");
        break;
    case 0x0C5:
        fprintf(messageFile, "A key-storage file I/O error occurred, or a file was not found.\n");
        break;
    case 0x0CE:
        fprintf(messageFile,
                "The key-storage file is not valid, or the master-key verification failed.\n"
                "There is an unlikely but possible synchronization problem with the\n"
                "Master_Key_Process verb.\n");
        break;
    case 0x0CF:
        fprintf(messageFile, "The verification method flags in the profile are not valid.\n");
        break;
    case 0x144:
        fprintf(messageFile,
                "There was insufficient memory available to process your request, either\n"
                "memory in the host computer, or memory inside the Coprocessor including\n"
                "the Flash EPROM used to store keys, profiles, and other application data.\n");
        break;
    case 0x152:
        fprintf(messageFile, "This cryptographic hardware device driver is not installed or is not\n"
                "responding, or the CCA code is not loaded in the Coprocessor.\n");
        break;
    case 0x153:
        fprintf(messageFile, "A system error occurred in interprocess communication routine.\n");
        break;
    case 0x2FC:
        fprintf(messageFile, "The master key(s) are not loaded and therefore a key could not be\n"
                "recovered or enciphered.\n");
        break;
    case 0x300:
        fprintf(messageFile,
                "One or more paths for key-storage directory operations is improperly specified.\n");
        break;
    case 0x7FD:
        fprintf(messageFile, "The CCA software was unable to claim a semaphore. The system may be\n"
                "short of resources.\n");
        break;
    case 0x7FE:
        fprintf(messageFile, "The CCA software was unable to list all of the keys. The limit of\n"
                "500 000 keys may have been reached.\n");
        break;
    default:
        fprintf(messageFile, "Unknown return code 0c reason code: %08lx\n", reason_code);
    }
    return;
}
void CCA_PrintReturn10(long reason_code)
{
    switch (reason_code) {
    case 0x063:
        fprintf(messageFile, "An unrecoverable error occurred in the security server; contact your\n"
                "IBM service representative.\n");
        break;
    case 0x150:
        fprintf(messageFile,
                "An error occurred in a cryptographic hardware or software component.\n");
        break;
    case 0x151:
        fprintf(messageFile, "A device software error occurred.\n");
        break;
    case 0x1BC:
        fprintf(messageFile, "The verb-unique-data had an invalid length.\n");
        break;
    case 0x22C:
        fprintf(messageFile, "The request parameter block failed consistency checking.\n");
        break;
    case 0x2C4:
        fprintf(messageFile, "Inconsistent data was returned from the cryptographic engine.\n");
        break;
    case 0x2C5:
        fprintf(messageFile,
                "Cryptographic engine internal error, could not access the master-key data.\n");
        break;
    case 0x2C6:
        fprintf(messageFile,
                "An unrecoverable error occurred while attempting to update master-key data\n"
                "items.\n");
        break;
    case 0x2C8:
        fprintf(messageFile, "An unexpected error occurred in the master-key manager.\n");
        break;
    case 0x301:
        fprintf(messageFile, "The host system code or the CCA application in the Coprocessor\n"
                "encountered an unexpected error and was unable to process the request.\n"
                "Windows NT and 2000, and OS/2 support is limited to 32 concurrent requests.\n");
        break;
    case 0x7FF:
        fprintf(messageFile, "Unable to transfer Request Data from host to Coprocessor.\n");
        break;
    case 0x809:
        fprintf(messageFile, "Internal error: memory allocation failure.\n");
        break;
    case 0x80A:
        fprintf(messageFile, "Internal error: unexpected return code from OAEP routines.\n");
        break;
    case 0x80B:
        fprintf(messageFile, "Internal error: OAEP SHA-1 request failure.\n");
        break;
    case 0x80D:
        fprintf(messageFile,
                "Internal error in CSNDSYI, OAEP-decode: enciphered message too long.\n");
        break;
    default:
        fprintf(messageFile, "Unknown return code 10 reason code: %08lx\n", reason_code);
    }
    return;
}
