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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

#include "cca_functions.h"
#include "ossl_functions.h"
#include "framework_utils.h"
#include "mail.h"
#include "utils.h"
#include "debug.h"

/* local prototypes */

int GetArgs(const char **profileId,
            const char **sender,
            int argc,
            char **argv);
void PrintUsage(void);

/* global variables */

FILE *messageFile  = NULL;
int verbose = TRUE;
int debug = FALSE;

int main(int argc, char** argv)
{
    int 	rc = 0;
    size_t	i;

    /* program command line arguments */
    const char *sender = NULL;				/* sender email address */
    const char *profileId= NULL;			/* CCA profile ID for the sender */

    FrameworkConfig 	frameworkConfig;
    unsigned char 	eku[AES128_SIZE];			/* password encryption key */
    unsigned char 	aku[AKU_SIZE];			/* password authentication HMAC key */
    unsigned char 	initialization_vector[IV_SIZE];	/* needed for AES encryption */
    char 		passwordText[64 + 1];		/* generated password plaintext */

    unsigned char 	*encryptedPassword = NULL;	/* in binary, freed @2 */
    long 		encryptedPasswordLength;
    unsigned char 	hmac[HMAC_SIZE];		/* encrypted password authentication HMAC */
    char 		*passwordString = NULL;		/* hex ASCII combined IV, HMAC, encrypted
                                               pwd *//* freed @3 */
    size_t		passwordStringLength;

    FILE 		*outputBodyFile = NULL;		/* closed @4 */

    /* this is a stand alone program, so trace always goes to stdout */
    messageFile = stdout;

    FrameworkConfig_Init(&frameworkConfig);	/* freed @1 */
    /*
      get the command line arguments
    */
    if (rc == 0) {
        rc = GetArgs(&profileId,
                     &sender,
                     argc, argv);
    }
    if (rc == 0) {
        if (verbose) fprintf(messageFile, "Sender: %s\n", sender);
        if (verbose) fprintf(messageFile, "CCA Profile ID: %s\n", profileId);
    }
    /*
      get parameters from the framework configuration file
    */
    if (rc == 0) {
        rc = FrameworkConfig_Parse(TRUE,	/* need master key */
                                   FALSE,	/* do not validate */
                                   &frameworkConfig);
    }
    /* open framework audit log file for append */
    /* NOTE Is it legitimate to use the framework audit log?  There can be a race condition if an
       email is being processed at the same time.  On the other hand, this is low probability, and
       it's probably not worth yet another audit log file. */
    if (rc == 0) {
        frameworkConfig.frameworkLogFile =
            fopen(frameworkConfig.frameworkLogFilename, "a");	/* closed @6 */
        if (frameworkConfig.frameworkLogFile == NULL) {
            fprintf(messageFile,
                    "Error opening: %s\n", frameworkConfig.frameworkLogFilename);
            frameworkConfig.frameworkLogFile = stdout;
            rc = ERROR_CODE;
        }
        else {
            /* no buffering, so log can be monitored while the framework is running */
            setvbuf(frameworkConfig.frameworkLogFile, 0, _IONBF, 0);
        }
    }
    /* begin the audit log entry */
    if (rc == 0) {
        File_LogTime(frameworkConfig.frameworkLogFile);
        fprintf(frameworkConfig.frameworkLogFile, "\tPassword generation\n");
        fprintf(frameworkConfig.frameworkLogFile, "\tSender: %s\n", sender);
        fprintf(frameworkConfig.frameworkLogFile, "\tCCA Profile ID: %s\n", profileId);
    }
    /*
      generate the encryption and HMAC keys from the master AES key mixed with the sender email
      address
    */
    if (rc == 0) {
        if (verbose) fprintf(messageFile, "Deriving password HMAC and encryption keys\n");
        rc = Password_KDF(eku,		/* user encryption key */
                          aku,		/* user authentication HMAC key */
                          profileId, /* authenticated email sender */
                          frameworkConfig.masterAesKeyToken);
    }
    /*
      generate a strong password
    */
    if (rc == 0) {
        if (verbose) fprintf(messageFile, "Generating a password\n");
        memset(passwordText, '\0', sizeof(passwordText));		/* NUL terminator */
        rc = Password_Generate(passwordText, sizeof(passwordText));
    }

#if 0	/* For tracing.  Must be removed from the final product. */
    if (rc == 0) {
        if (verbose) fprintf(messageFile, "Password %s\n", passwordText);
    }
#endif
    /*
      encrypt, HMAC, and convert the password
    */
    /* generate a random IV for the password */
    if (rc == 0) {
        if (verbose) fprintf(messageFile, "Generating AES initialization vector\n");
        rc = Random_Number_Generate_Long(initialization_vector, IV_SIZE);
        if (verbose) PrintAll(messageFile,
                              "IV", IV_SIZE, initialization_vector);
    }
    /* encrypt the password */
    if (rc == 0) {
        if (verbose) fprintf(messageFile, "Encrypt the Password\n");
        rc = Ossl_AES_Encrypt(&encryptedPassword,		/* freed @2 */
                              (size_t *)&encryptedPasswordLength,
                              (unsigned char *)passwordText,
                              sizeof(passwordText),
                              initialization_vector,
                              eku);	/* derived encryption key */
    }
    if (rc == 0) {
        if (verbose) PrintAll(messageFile,
                              "Encrypted password\n", encryptedPasswordLength, encryptedPassword);
    }
    /* HMAC the encrypted password */
    if (rc == 0) {
        if (verbose) fprintf(messageFile, "HMAC the Password\n");
        Ossl_HMAC_Generate(hmac,			/* HMAC result */
                           aku,				/* derived HMAC key */
                           encryptedPasswordLength,
                           encryptedPassword,
                           0, NULL);
        if (verbose) PrintAll(messageFile,
                              "HMAC", HMAC_SIZE, hmac);
    }
    /* concatenate the IV, HMAC, and encrypted password, convert to hex ASCII */
    if (rc == 0) {
        if (verbose) fprintf(messageFile,
                             "Concatenate IV, HMAC, Encrypted Password and convert to string\n");
        rc = Password_ToString(&passwordString,		/* freed @3 */
                               &passwordStringLength,
                               initialization_vector,
                               hmac,
                               encryptedPassword, 		/* encrypted password */
                               encryptedPasswordLength); 	/* password */
    }
    if (rc == 0) {
        if (verbose) fprintf(messageFile, "Password String length %d\n", (int)passwordStringLength);
        if (verbose) fprintf(messageFile, "Password String:\n%s\n", passwordString);
    }
    /*
      sanity check - convert back and compare
    */
    if (rc == 0) {
        if (verbose) fprintf(messageFile, "Password encryption validation\n");

        unsigned char 	initialization_vector_out[IV_SIZE];
        unsigned char 	hmac_out[HMAC_SIZE];
        unsigned char 	*ciphertext_out = NULL;		/* freed @1 */
        long 		ciphertext_length_out;
        long 		cleartext_length_out;
        unsigned char 	*cleartext_out = NULL;		/* freed @2 */
        int 		hmac_valid;

        /* convert the hex ASCII back to IV, HMAC, and encrypted password */
        if (rc == 0) {
            rc = Password_FromString(initialization_vector_out,
                                     hmac_out,
                                     &ciphertext_out,	/* freed @4 */
                                     (size_t *)&ciphertext_length_out,
                                     passwordString,
                                     passwordStringLength,
                                     frameworkConfig.frameworkLogFile);
        }
        /* validate the converted IV */
        if (rc == 0) {
            rc = memcmp(initialization_vector, initialization_vector_out, IV_SIZE);
            if (rc != 0) {
                fprintf(messageFile, "IV conversion mismatch\n");
                rc = ERROR_CODE;
            }
        }
        /* validate the converted HMAC */
        if (rc == 0) {
            rc = memcmp(hmac, hmac_out, HMAC_SIZE);
            if (rc != 0) {
                fprintf(messageFile, "HMAC conversion mismatch\n");
                rc = ERROR_CODE;
            }
        }
        /* validate the converted encrypted password */
        if (rc == 0) {
            if (encryptedPasswordLength != ciphertext_length_out) {
                fprintf(messageFile, "Password ciphertext length mismatch\n");
                rc = ERROR_CODE;
            }
        }
        if (rc == 0) {
            rc = memcmp(encryptedPassword, ciphertext_out, encryptedPasswordLength );
            if (rc != 0) {
                fprintf(messageFile, "ciphertext conversion mismatch\n");
                rc = ERROR_CODE;
            }
        }
        /* validate the HMAC */
        if (rc == 0) {
            Ossl_HMAC_Check(&hmac_valid,
                            hmac,
                            aku,
                            encryptedPasswordLength,
                            encryptedPassword,
                            0, NULL);
        }
        if (rc == 0) {
            if (!hmac_valid) {
                fprintf(messageFile, "Password HMAC check failed\n\n");
                rc = ERROR_CODE;
            }
        }
        /* decrypt the password */
        if (rc == 0) {
            rc = Ossl_AES_Decrypt(&cleartext_out,	/* freed @2 */
                                  (size_t *)&cleartext_length_out,
                                  encryptedPassword,
                                  encryptedPasswordLength,
                                  initialization_vector,
                                  eku);
        }
        /* validate the decryption */
        if (rc == 0) {
            rc = memcmp((unsigned char *)passwordText, cleartext_out, cleartext_length_out);
            if (rc != 0) {
                fprintf(messageFile, "Decrypt error\n");
                fprintf(messageFile, "Cleartext in %s\n", passwordText);
                fprintf(messageFile, "Cleartext out %s\n", cleartext_out);
                fprintf(messageFile, "Cleartext length out %lu\n", cleartext_length_out);
                rc = ERROR_CODE;
            }
        }
        free(ciphertext_out);	/* @1 */
        if (cleartext_out != NULL) {
            memset(cleartext_out, 0, cleartext_length_out);
        }
        free(cleartext_out);	/* @2 */
    }
    /*
      Change the password in CCA on the coprocessor card
    */
    if (rc == 0) {
        if (verbose) fprintf(messageFile, "Login with CCA Profile: %s, default password: aaaaaa\n",
                             profileId);
        rc = Login_Control(TRUE,
                           profileId,
                           "aaaaaa");
        if (rc != 0) {
            File_Printf(frameworkConfig.frameworkLogFile, messageFile,
                        "ERROR1001, Cannot log in CCA Profile: %s with password aaaaaa\n",
                        profileId);
        }
    }
    /* send password change to card */
    if (rc == 0) {
        if (verbose) fprintf(messageFile, "Change password\n");
        rc = Access_Control_Initialization(profileId,
                                           frameworkConfig.passwordExpire,	/* password
                                                                               expiration */
                                           passwordText);
        if (rc != 0) {
            File_Printf(frameworkConfig.frameworkLogFile, messageFile,
                        "ERROR1002, Cannot change password for CCA Profile: %s\n", profileId);
        }
    }
    /* logout */
    if (rc == 0) {
        if (verbose) fprintf(messageFile, "Logout: Profile: %s\n", profileId);
        rc = Login_Control(FALSE,
                           profileId,
                           NULL);	/* password */
        if (rc != 0) {
            File_Printf(frameworkConfig.frameworkLogFile, messageFile,
                        "ERROR1003, Cannot log out CCA Profile: %s\n", profileId);
        }
    }
    /*
      sanity check - try to log in with the new password
    */
    if (rc == 0) {
        if (verbose) fprintf(messageFile, "Login with CCA Profile: %s, and changed password\n",
                             profileId);
        rc = Login_Control(TRUE,
                           profileId,
                           passwordText);
    }
    /* logout */
    if (rc == 0) {
        if (verbose) fprintf(messageFile, "Logout: Profile: %s\n", profileId);
        rc = Login_Control(FALSE,
                           profileId,
                           NULL);	/* password */

    }

    /* open the email response file */
    if (rc == 0) {
        outputBodyFile = fopen(frameworkConfig.outputBodyFilename, "w");
        if (outputBodyFile == NULL) {
            fprintf(messageFile, "Error opening %s, %s\n",
                    frameworkConfig.outputBodyFilename, strerror(errno));
            rc = ERROR_CODE;
        }
    }

    /* construct the email response */
    if (rc == 0) {
        fprintf(outputBodyFile, "A password has been generated for: %s\n", profileId);
        fprintf(outputBodyFile, "It is valid for %u months.\n",
                frameworkConfig.passwordExpire);
        fprintf(outputBodyFile, "\n");
        fprintf(outputBodyFile, "You must retain the following encrypted password to perform signing requests.\n");
        fprintf(outputBodyFile, "This password should be placed in a file with permissions set appropriately\n");
        fprintf(outputBodyFile, "to block access to it by anyone other than yourself.\n\n");
        fprintf(outputBodyFile, "Encrypted Password : %s\n", passwordString);
        fprintf(outputBodyFile, "\n");
        fprintf(outputBodyFile, "This password will grant you access to the signing server but you will also need\n");
        fprintf(outputBodyFile, "access to a specific project.\n");
        fprintf(outputBodyFile, "\n");
        fprintf(outputBodyFile, "For project names, contact the administrator at:\n");
        for (i = 0 ; i < frameworkConfig.frameworkAdminCount ; i++) {
            fprintf(outputBodyFile,
                    "\t%s\n", frameworkConfig.frameworkAdmins[i]);
        }
        fprintf(outputBodyFile, "\n");
        /* close the email response file */
        fclose(outputBodyFile);
        outputBodyFile = NULL;
    }

    /* send the email response */
    if (rc == 0) {
        /* send the enrollment message to the signer */
        rc = SendMailFile(&frameworkConfig, sender, "Signer Framework Enrollment", frameworkConfig.outputBodyFilename);
        if (rc != 0) {
            fprintf(messageFile, "SendMail failed, status %u\n", rc);
            rc = ERROR_CODE;
        }
        remove(frameworkConfig.outputBodyFilename);
    }

    /* log the results to the framework audit log */
    if (rc == 0) {
        fprintf(frameworkConfig.frameworkLogFile, "\tEncrypted password:\n\t%s\n", passwordString);
    }
    if (rc == 0) {
        fprintf(messageFile, "\npassword_generate succeeded\n\n");
    }
    else {
        fprintf(messageFile, "\npassword_generate failed\n\n");
    }
    /* cleanup */
    if (frameworkConfig.frameworkLogFile != stdout) {
        fclose(frameworkConfig.frameworkLogFile);	/* @6 */
    }
    FrameworkConfig_Delete(&frameworkConfig);		/* @1 */
    free(encryptedPassword);				/* @2 */
    free(passwordString);				/* @3 */
    if (outputBodyFile !=  NULL) {
        fclose(outputBodyFile);				/* @4 */
    }
    /* erase the secret keys before exit */
    memset(eku, 0, AES128_SIZE);
    memset(aku, 0, AKU_SIZE);
    memset(passwordText, '\0', sizeof(passwordText));
    return rc;
}

/* GetArgs() gets the command line arguments

   Returns ERROR_CODE on error.
*/

int GetArgs(const char **profileId,
            const char **sender,
            int argc,
            char **argv)
{
    int		rc = 0;
    int 	i;

    /* command line argument defaults */
    *profileId = NULL;
    *sender = NULL;
    verbose = FALSE;

    /* get the command line arguments */
    for (i=1 ; (i<argc) && (rc == 0) ; i++) {
        if (strcmp(argv[i],"-sender") == 0) {
            i++;
            if (i < argc) {
                *sender = argv[i];
            }
            else {
                fprintf(messageFile, "password_generate: Error, -sender option needs a value\n");
                rc = ERROR_CODE;
            }
        }
        else if (strcmp(argv[i],"-profile") == 0) {
            i++;
            if (i < argc) {
                *profileId = argv[i];
            }
            else {
                fprintf(messageFile, "password_generate: Error, -profile option needs a value\n");
                rc = ERROR_CODE;
            }
        }
        else if (strcmp(argv[i],"-h") == 0) {
            PrintUsage();
            rc = ERROR_CODE;
        }
        else if (strcmp(argv[i],"-v") == 0) {
            verbose = TRUE;
        }
        else {
            fprintf(messageFile, "password_generate: Error, %s is not a valid option\n", argv[i]);
            PrintUsage();
            rc = ERROR_CODE;
        }
    }
    /* verify command line arguments */
    if (rc == 0) {
        if (*sender == NULL) {
            fprintf(messageFile, "password_generate: Error, -sender option must be specified\n");
            rc = ERROR_CODE;
        }
    }
    if (rc == 0) {
        if (*profileId == NULL) {
            fprintf(messageFile, "password_generate: Error, -profile option must be specified\n");
            rc = ERROR_CODE;
        }
    }
    return rc;
}

void PrintUsage()
{
    fprintf(messageFile, "\n");
    fprintf(messageFile, "password_generate:\n"
            "\t-profile - CCA profile ID\n"
            "\t-sender - email sender\n"
            "\t[-v - verbose tracing]\n"
            "\t[-h - print usage help]\n");
    fprintf(messageFile, "\n");
    fprintf(messageFile, "Creates a strong CCA profile password, installs the password, and\n"
            "returns the password encrypted and mixed with the sender email address\n");
    fprintf(messageFile, "\n");
    fprintf(messageFile, "It assumes that the original password is 'aaaaaa'\n");
    fprintf(messageFile, "\n");
    return;
}
