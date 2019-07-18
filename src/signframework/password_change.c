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
#include <time.h>

#include "cca_functions.h"
#include "ossl_functions.h"
#include "framework_utils.h"
#include "mail.h"
#include "utils.h"
#include "debug.h"

/* local prototypes */

int GetArgs(const char **outputBodyFilename,
            const char **profileId,
            const char **epassword,
            const char **password,
            const char **projectLogFileName,
            const char **sender,
            const char **project,
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
    const char *outputBodyFilename = NULL;
    const char *profileId = NULL;			/* CCA profile ID for the sender */
    const char *epassword = NULL;			/* old encrypted password */
    const char *password = NULL;			/* old plaintext password */
    const char 	*projectLogFileName = NULL;			/* program audit log */
    FILE	*projectLogFile = NULL;
    time_t      log_time;
    const char *sender = NULL;				/* sender email address */
    const char 	*project = NULL;

    FrameworkConfig 	frameworkConfig;		/* framework configuration file object */
    unsigned char 	eku[AES128_SIZE];		/* password encryption key */
    unsigned char 	aku[AKU_SIZE];			/* password authentication HMAC key */
    char 		passwordText[64 + 1];		/* new generated password plaintext */
    unsigned char 	initialization_vector[IV_SIZE];	/* needed for AES encryption */
    unsigned char 	*encryptedPassword = NULL;	/* new, in binary, freed @3 */
    long 		encryptedPasswordLength;
    unsigned char 	hmac[HMAC_SIZE];		/* new password authentication HMAC */
    char 		*passwordString = NULL;		/* new hex ASCII combined IV, HMAC,
                                               encrypted pwd *//* freed @4 */
    size_t		passwordStringLength;

    messageFile = stdout;
    FrameworkConfig_Init(&frameworkConfig);	/* freed @1 */
    /*
      get the command line arguments
    */
    if (rc == 0) {
        rc = GetArgs(&outputBodyFilename,
                     &profileId,
                     &epassword,
                     &password,
                     &projectLogFileName,
                     &sender,
                     &project,
                     argc, argv);
    }
    if (rc == 0) {
        if (verbose) fprintf(messageFile, "Sender: %s\n", sender);
        if (verbose) fprintf(messageFile, "CCA Profile ID: %s\n", profileId);
    }
    /* project audit log */
    if (rc == 0) {
        if (verbose) fprintf(messageFile, "Opening audit log %s\n", projectLogFileName);
        projectLogFile = fopen(projectLogFileName, "a");
        if (projectLogFile == NULL) {
            fprintf(messageFile, "ERROR1015: Cannot open audit log %s, %s\n",
                    projectLogFileName, strerror(errno));
            rc = ERROR_CODE;
        }
    }
    /* update framework audit log, begin this entry */
    if (projectLogFile != NULL) {
        if (verbose) fprintf(messageFile, "Updating audit log\n");
        log_time = time(NULL);
        fprintf(projectLogFile, "\n%s", ctime(&log_time));
        fprintf(projectLogFile, "\tSender: %s\n", sender);
        fprintf(projectLogFile, "\tProject: %s\n", project);
        fprintf(projectLogFile, "\tProgram: %s\n", argv[0]);
        fprintf(projectLogFile, "\tCCA Profile ID: %s\n", profileId);
        fprintf(projectLogFile, "\tInput password:\n\t%s\n", epassword);
    }
    /*
      get parameters from the framework configuration file
    */
    if (rc == 0) {
        rc = FrameworkConfig_Parse(TRUE,		/* need master key */
                                   TRUE,		/* validate */
                                   &frameworkConfig);
    }
    /*
      generate the encryption and HMAC keys from the master AES key mixed with the sender email
      address
    */
    if (rc == 0) {
        if (verbose) fprintf(messageFile, "Deriving password HMAC and encryption keys\n");
        rc = Password_KDF(eku,		/* user encryption key */
                          aku,		/* user authentication HMAC key */
                          sender,	/* authenticated email sender */
                          frameworkConfig.masterAesKeyToken);
    }
    /*
      generate a new strong password
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
      encrypt, HMAC, and convert the new password
    */
    /* generate a random IV for the new password */
    if (rc == 0) {
        if (verbose) fprintf(messageFile, "Generating AES initialization vector\n");
        rc = Random_Number_Generate_Long(initialization_vector, IV_SIZE);
        if (verbose) PrintAll(messageFile,
                              "IV", IV_SIZE, initialization_vector);
    }
    /* encrypt the new password */
    if (rc == 0) {
        if (verbose) fprintf(messageFile, "Encrypt the Password\n");
        rc = Ossl_AES_Encrypt(&encryptedPassword,		/* freed @3 */
                              (size_t *)&encryptedPasswordLength,
                              (unsigned char *)passwordText,
                              sizeof(passwordText),
                              initialization_vector,
                              eku);			/* derived encryption key */
    }
    if (rc == 0) {
        if (verbose) PrintAll(messageFile,
                              "Encrypted password\n", encryptedPasswordLength, encryptedPassword);
    }
    /* HMAC the encrypted new password */
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
        rc = Password_ToString(&passwordString,		/* freed @4 */
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
                                     projectLogFile);
        }
        /* validate the converted IV */
        if (rc == 0) {
            rc = memcmp(initialization_vector, initialization_vector_out, IV_SIZE);
            if (rc != 0) {
                fprintf(messageFile, "Error, IV conversion mismatch\n");
                rc = ERROR_CODE;
            }
        }
        /* validate the converted HMAC */
        if (rc == 0) {
            rc = memcmp(hmac, hmac_out, HMAC_SIZE);
            if (rc != 0) {
                fprintf(messageFile, "Error, HMAC conversion mismatch\n");
                rc = ERROR_CODE;
            }
        }
        /* validate the converted encrypted password length */
        if (rc == 0) {
            if (encryptedPasswordLength != ciphertext_length_out) {
                fprintf(messageFile, "Error, Password ciphertext length mismatch\n");
                rc = ERROR_CODE;
            }
        }
        /* validate the converted encrypted password */
        if (rc == 0) {
            rc = memcmp(encryptedPassword, ciphertext_out, encryptedPasswordLength );
            if (rc != 0) {
                fprintf(messageFile, "Error, Ciphertext conversion mismatch\n");
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
                fprintf(messageFile, "Error, Password HMAC check failed\n\n");
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
                fprintf(messageFile, "Error, Decrypt error\n");
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
        if (verbose) fprintf(messageFile, "Login with CCA Profile: %s\n", profileId);
        rc = Login_Control(TRUE,
                           profileId,
                           password);
        if (rc != 0) {
            File_Printf(projectLogFile, messageFile,
                        "ERROR1001, Cannot log in CCA Profile: %s\n", profileId);
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
            File_Printf(projectLogFile, messageFile,
                        "ERROR1008, Cannot change password for CCA Profile: %s\n", profileId);
        }
    }
    /* logout */
    if (rc == 0) {
        if (verbose) fprintf(messageFile, "Logout: Profile: %s\n", profileId);
        rc = Login_Control(FALSE,
                           profileId,
                           NULL);	/* password */
        if (rc != 0) {
            File_Printf(projectLogFile, messageFile,
                        "ERROR1001, Cannot log out CCA Profile: %s\n", profileId);
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
    /* update audit log */
    if (rc == 0) {
        fprintf(projectLogFile, "\tOutput password:\n\t%s\n", passwordString);
    }
    /* construct the email response */
    if (rc == 0) {
        fprintf(messageFile, "A password has been changed for: %s\n", sender);
        fprintf(messageFile, "It is valid for %u months.\n",
                frameworkConfig.passwordExpire);
        fprintf(messageFile, "\n");
        fprintf(messageFile, "You must retain the following encrypted password to perform signing requests.\n");
        fprintf(messageFile, "This password should be placed in a file with permissions set appropriately\n");
        fprintf(messageFile, "to block access to it by anyone other than yourself.\n\n");
        fprintf(messageFile, "Encrypted Password : %s\n", passwordString);
        fprintf(messageFile, "\n");
        fprintf(messageFile, "This password will grant you access to the signing server but you will also need\n");
        fprintf(messageFile, "access to a specific project.\n");
        fprintf(messageFile, "\n");
        fprintf(messageFile, "For project names, contact an administrator at:\n");
        for (i = 0 ; i < frameworkConfig.frameworkAdminCount ; i++) {
            fprintf(messageFile,
                    "\t%s\n", frameworkConfig.frameworkAdmins[i]);
        }
        fprintf(messageFile, "\n");
        /* close the email response file */
        fclose(messageFile);
        messageFile = NULL;
    }
    /* cleanup */
    FrameworkConfig_Delete(&frameworkConfig);	/* @1 */
    free(encryptedPassword);			/* @3 */
    free(passwordString);			/* @4 */
    /* erase the secret keys before exit */
    memset(eku, 0, AES128_SIZE);
    memset(aku, 0, AKU_SIZE);
    memset(passwordText, '\0', sizeof(passwordText));
    return rc;
}

/* GetArgs() gets the command line arguments

   Returns ERROR_CODE on error.
*/

int GetArgs(const char **outputBodyFilename,
            const char **profileId,
            const char **epassword,
            const char **password,
            const char **projectLogFileName,
            const char **sender,
            const char **project,
            int argc,
            char **argv)
{
    int		rc = 0;
    int 	i;
    FILE	*tmpFile;

    /* command line argument defaults */
    *outputBodyFilename = NULL;
    *profileId = NULL;
    *epassword = NULL;
    *password = NULL;
    *projectLogFileName = NULL,
        *sender = NULL;
    *project = NULL;
    verbose = FALSE;

    /* get the command line arguments */
    for (i=1 ; (i<argc) && (rc == 0) ; i++) {
        if (strcmp(argv[i],"-obody") == 0) {
            i++;
            if (i < argc) {
                *outputBodyFilename = argv[i];
                rc = File_Open(&tmpFile, *outputBodyFilename, "a");
                /* switch messageFile from stdout ASAP so all messages get returned via email */
                if (rc == 0) {
                    messageFile = tmpFile;
                    setvbuf(messageFile , 0, _IONBF, 0);
                }
            }
            else {
                fprintf(messageFile,
                        "ERROR1002: -obody option (output email body) needs a value\n");
                rc = ERROR_CODE;
            }
        }
        else if (strcmp(argv[i],"-usr") == 0) {
            i++;
            if (i < argc) {
                *profileId = argv[i];
            }
            else {
                fprintf(messageFile,
                        "ERROR1003: -usr option (CCA user ID) needs a value\n");
                rc = ERROR_CODE;
            }
        }
        else if (strcmp(argv[i],"-epwd") == 0) {
            i++;
            if (i < argc) {
                *epassword = argv[i];
            }
            else {
                fprintf(messageFile,
                        "ERROR1004: -epwd option (CCA password) needs a value\n");
                rc = ERROR_CODE;
            }
        }
        else if (strcmp(argv[i],"-pwd") == 0) {
            i++;
            if (i < argc) {
                *password = argv[i];
            }
            else {
                fprintf(messageFile,
                        "ERROR1004: -pwd option (CCA password) needs a value\n");
                rc = ERROR_CODE;
            }
        }
        else if (strcmp(argv[i],"-log") == 0) {
            i++;
            if (i < argc) {
                *projectLogFileName = argv[i];
            }
            else {
                fprintf(messageFile,
                        "ERROR1005: -log option (audit log file name) needs a value\n");
                rc = ERROR_CODE;
            }
        }
        else if (strcmp(argv[i],"-sender") == 0) {
            i++;
            if (i < argc) {
                *sender = argv[i];
            }
            else {
                fprintf(messageFile,
                        "ERROR1006: -sender option needs a value\n");
                rc = ERROR_CODE;
            }
        }
        else if (strcmp(argv[i],"-project") == 0) {
            i++;
            if (i < argc) {
                *project = argv[i];
            }
            else {
                fprintf(messageFile,
                        "ERROR1007: -project option needs a value\n");
                rc = ERROR_CODE;
            }
        }
        /* this allows the framework to probe whether the project specific program can be called.
           The program should do nothing except return success. */
        else if (strcmp(argv[i],"-h") == 0) {
            PrintUsage();
            exit(0);
        }
        else if (strcmp(argv[i],"-v") == 0) {
            verbose = TRUE;
        }
        /* This code intentionally does not have an 'else error' clause.  The framework can in
           general add command line arguments that are ignored by the project specific program. */
    }
    /* verify command line arguments */
    if (rc == 0) {
        // If the usr isn't specified just use the sender
        if (*profileId == NULL) {
            *profileId = *sender;
        }
        if (*profileId == NULL) {
            fprintf(messageFile,
                    "ERROR1010: -usr option missing\n");
            rc = ERROR_CODE;
        }
    }
    if (rc == 0) {
        if (*projectLogFileName == NULL) {
            fprintf(messageFile,
                    "ERROR1012: -log option missing\n");
            rc = ERROR_CODE;
        }
    }
    if (rc == 0) {
        if (*sender == NULL) {
            fprintf(messageFile,
                    "ERROR1013: -sender option missing\n");
            rc = ERROR_CODE;
        }
    }
    return rc;
}

void PrintUsage()
{
    fprintf(messageFile, "\n");
    fprintf(messageFile, "password_change:\n"
            "\n"
            "Common arguments:\n"
            "\n"
            "\t-usr        - CCA user (profile) ID\n"
            "\t[-v         - verbose logging]\n"
            "\t[-h         - print usage help]\n"
            "\n"
            "Email only arguments:\n"
            "\n"
            "\t-project    - project name\n"
            "\t-epwd       - CCA user password (encrypted)\n"
            "\n"
            "Command line only arguments:\n"
            "\n"
            "\t-obody      - output email body file name (should be first argument)\n"
            "\t-sender     - email sender\n"
            "\t-log        - project audit log file name\n"
            "\t-pwd        - CCA user password (plaintext)\n"
            );
    fprintf(messageFile, "\n");
    fprintf(messageFile, "Changes the strong CCA profile password, installs the password, and\n"
            "returns the password encrypted and mixed with the sender email address\n");
    fprintf(messageFile, "\n");
    return;
}
