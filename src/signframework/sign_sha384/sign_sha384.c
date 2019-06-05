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

/* This program sign an input SHA-384 digest with an RSA key
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>

#include "cca_functions.h"
#include "cca_structures.h"
#include "ossl_functions.h"
#include "utils.h"
#include "debug.h"

/* local prototypes */

int GetArgs(const char **outputBodyFilename,
            const char **usr,
            const char **password,
            const char **projectLogFileName,
            const char **sender,
            const char **project,
            const char **keyFileName,
            const char **inputAttachmentFileName,
            const char **outputAttachmentFileName,
            unsigned int *bitSize,
            int *text,
            int *verbose,
            int argc,
            char **argv);
void PrintUsage(void);

int Sign(const char 	*keyFileName,
         const char 	*inputAttachmentFileName,
         const char 	*outputAttachmentFileName,
         int		    text,
         unsigned int   bitSize,
         FILE 		    *projectLogFile);

/* messages are traced here */
FILE *messageFile = NULL;
/* FILE *frameworkLogFile = NULL;*/
int verbose = FALSE;
int debug = FALSE;
unsigned int MOD_SIZE = N_SIZE;

int main(int argc, char** argv)
{
    int 	rc = 0;
    const char  *usr = NULL;
    const char 	*password = NULL;
    const char 	*projectLogFileName = NULL;
    FILE	*projectLogFile = NULL;
    time_t      log_time = 0;
    const char 	*sender = NULL;
    const char 	*project = NULL;
    const char 	*keyFileName = NULL;
    const char 	*inputAttachmentFileName = NULL;
    const char 	*outputAttachmentFileName = NULL;
    const char 	*outputBodyFilename = NULL;
    unsigned int bitSize = 4096;  /* default RSA key size */
    int		text = 0;

    messageFile = stdout;

    /* get caller's command line arguments */
    if (rc == 0) {
        rc = GetArgs(&outputBodyFilename,
                     &usr,
                     &password,
                     &projectLogFileName,
                     &sender,
                     &project,
                     &keyFileName,
                     &inputAttachmentFileName,
                     &outputAttachmentFileName,
                     &bitSize,
                     &text,
                     &verbose,
                     argc, argv);
    }
    /* log in to CCA */
    if (rc == 0) {
        if (verbose) fprintf(messageFile, "Logging in with user name %s\n", usr);
        rc = Login_Control(TRUE,	/* log in */
                           usr,		/* CCA profile */
                           password);	/* CCA password */
    }
    /* audit logging */
    if (rc == 0) {
        if (verbose) fprintf(messageFile, "Opening audit log %s\n", projectLogFileName);
        projectLogFile = fopen(projectLogFileName, "a");
        if (projectLogFile == NULL) {
            fprintf(messageFile, "ERROR1015: Cannot open audit log %s, %s\n",
                    projectLogFileName, strerror(errno));
            rc = ERROR_CODE;
        }
    }
    /* update audit log, begin this entry */
    if (projectLogFile != NULL) {
        if (verbose) fprintf(messageFile, "Updating audit log\n");
        log_time = time(NULL);
        fprintf(projectLogFile, "\n%s", ctime(&log_time));
        fprintf(projectLogFile, "\tSender: %s\n", sender);
        fprintf(projectLogFile, "\tProject: %s\n", project);
        fprintf(projectLogFile, "\tProgram: %s\n", argv[0]);
        fprintf(projectLogFile, "\tKey file: %s\n", keyFileName);
        fprintf(projectLogFile, "\tProfile %s\n", usr);
    }
    /*
      sign and verify
    */
    if (rc == 0) {
        if (verbose) fprintf(messageFile, "Signing\n");
        if (verbose) fprintf(messageFile, "  Input attachment %s\n", inputAttachmentFileName);
        if (verbose) fprintf(messageFile, "  Output attachment %s\n", outputAttachmentFileName);
        rc = Sign(keyFileName,
                  inputAttachmentFileName,
                  outputAttachmentFileName,
                  text,
                  bitSize,
                  projectLogFile);
    }
    /* log out of CCA */
    if (rc == 0) {
        if (verbose) fprintf(messageFile, "Logging out with user name %s\n", usr);
        rc = Login_Control(FALSE,	/* log out */
                           usr,		/* CCA profile */
                           NULL);	/* password */
    }
    File_Printf(projectLogFile, messageFile,
                "Return code: %u\n", rc);
    /* clean up */
    if (projectLogFile != NULL) {
        fclose(projectLogFile);
    }
    if (messageFile != stdout) {
        fflush(messageFile);
        fclose(messageFile);
    }
    return rc;
}

/* Sign() signs and verifies a SHA-384 digest

 */

int Sign(const char 	*keyFileName,
         const char 	*inputAttachmentFileName,
         const char 	*outputAttachmentFileName,
         int		    text,
         unsigned int   bitSize,
         FILE 		    *projectLogFile)
{
    int		rc = 0;
    int		valid = FALSE; /* true if signature verifies */

    /*
      signing key
    */
    unsigned char 	*keyToken = NULL;	/* CCA key token */
    size_t		keyTokenLength = 0;
    RsaKeyTokenPublic 	rsaKeyTokenPublic;	/* CCA public key structure */
    unsigned char	*digest = NULL;		/* received digest */
    size_t 		digestLength = 0;      /* received digest length */

    /* http://tools.ietf.org/html/draft-ietf-smime-sha2-11 */
    /* SHA-384 with RSA OID (Object Identifier) */
    static const unsigned char sha384_rsa_oid[] = {0x30, 0x41, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86,
	                                               0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
	                                               0x00, 0x04, 0x30};
    /*
      digest to be signed
    */
    unsigned char 	hash384[sizeof(sha384_rsa_oid) + SHA384_SIZE];	/* OID + SHA-384 digest */
    /*
      signature
    */
    unsigned char  	signature[N_SIZE_MAX];
    unsigned long 	signatureLength = 0;
    unsigned long 	signatureBitLength = 0;

    /* get the CCA key token */
    if (rc == 0) {
        if (verbose) fprintf(messageFile, "Sign: Reading CCA key token file %s\n",
                             keyFileName);
        rc = File_ReadBinaryFile(&keyToken, &keyTokenLength, 2000, keyFileName); /* freed @1 */
        if (rc != 0) {
            File_Printf(projectLogFile, messageFile,
                        "Error: Could not open key file: %s\n", keyFileName);
        }
    }
    /* get the input digest */
    if (rc == 0) {
        if (verbose) fprintf(messageFile, "Sign: Reading input file %s\n",
                             inputAttachmentFileName);
        rc = File_ReadBinaryFile(&digest, &digestLength, SHA384_SIZE,
                                 inputAttachmentFileName);	/* freed @2 */
        if (rc != 0) {
            File_Printf(projectLogFile, messageFile,
                        "ERROR1018 while opening the attachment, file: %s\n",
                        inputAttachmentFileName);
        }
    }
    /* extract the CCA public key from the CCA key token  */
    if (rc == 0) {
        if (verbose) fprintf(messageFile, "Sign: key token length %d\n",
                             (int)keyTokenLength);
        if (verbose)
            fprintf(messageFile, "Sign: extract the public key from CCA key token\n");
        rc = getPKA96PublicKey(&rsaKeyTokenPublic,	/* output: structure */
                               keyTokenLength,
                               keyToken,		/* input: PKA96 key token */
                               bitSize);
    }
    /* verify the public key length */
    if (rc == 0) {
        if (verbose) fprintf(messageFile, "Sign: public key length %u\n", rsaKeyTokenPublic.nByteLength);
        if (rsaKeyTokenPublic.nByteLength != (bitSize/8)) {
            File_Printf(projectLogFile, messageFile,
                        "ERROR1019: public key length invalid %u\n",
                        rsaKeyTokenPublic.nByteLength);
            rc = ERROR_CODE;
        }
    }

    /* check the incoming digest length */
    if (rc == 0) {
        if (verbose) fprintf(messageFile, "Sign: Checking input file length\n");
        if (digestLength != SHA384_SIZE) {
            File_Printf(projectLogFile, messageFile,
                        "ERROR1019: attachment length %u not %u\n",
                        digestLength, SHA384_SIZE);
            rc = ERROR_CODE;
        }
    }
    if (rc == 0) {
        if (verbose) fprintf(messageFile, "Sign: Prepending OID\n");
        /* prepend OID */
        memcpy(hash384, sha384_rsa_oid, sizeof(sha384_rsa_oid));
        /* append digest */
        memcpy(hash384 + sizeof(sha384_rsa_oid), digest, SHA384_SIZE);
    }
    /* sign with the coprocessor.  The coprocessor doesn't know the digest algorithm.  It just
       signs an OID + digest1 */
    if (rc == 0) {
        if (verbose) PrintAll(messageFile,
                              "Sign: hash to sign",
                              sizeof(sha384_rsa_oid) + SHA384_SIZE,
                              hash384);
        signatureLength = MOD_SIZE;
        rc = Digital_Signature_Generate(&signatureLength,		/* i/o */
                                        &signatureBitLength,		/* output */
                                        signature,			/* output */
                                        keyTokenLength,			/* input */
                                        keyToken,			/* input */
                                        sizeof(sha384_rsa_oid) + SHA384_SIZE, /* input */
                                        hash384);			/* input */

    }
    /* create the audit log entry */
    if (rc == 0) {
        if (verbose) fprintf(messageFile, "Sign: Updating audit log\n");
        /* binary data as printable */
        char pubkey_string[N_SIZE_MAX * 4];
        char digest_string[SHA384_SIZE * 4];
        char sig_string[N_SIZE_MAX * 4];

        /* get the user and group structures */
        /* binary to printable */
        sprintAll(pubkey_string, MOD_SIZE, rsaKeyTokenPublic.n);
        sprintAll(digest_string, SHA384_SIZE, digest);
        sprintAll(sig_string, MOD_SIZE, signature);
        /* send to audit log */
        fprintf(projectLogFile, "\tPublic Key:\n %s\n", pubkey_string);
        fprintf(projectLogFile, "\tDigest:\n %s\n", digest_string);
        fprintf(projectLogFile, "\tSignature:\n %s\n", sig_string);
    }
    /*
      The verify functions should never fail.  They are just sanity checks on the code.
    */
    /* sanity check on the signature length */
    if (rc == 0) {
        if (signatureLength != MOD_SIZE) {
            File_Printf(projectLogFile, messageFile,
                        "ERROR1001: signature invalid length %lu\n", signatureLength);
            rc = ERROR_CODE;
        }
    }
    /* verify the signature with the coprocessor key CCA token */
    if (rc == 0) {
        if (verbose) fprintf(messageFile,
                             "Sign: verify signature with the coprocessor key token\n");
        rc = Digital_Signature_Verify(MOD_SIZE,			/* input */
                                      signature,		/* input signature */
                                      keyTokenLength,		/* input */
                                      keyToken,			/* input key */
                                      sizeof(sha384_rsa_oid) + SHA384_SIZE,	/* input */
                                      hash384);			/* input hash */
    }
    /* code to verify the signature using openssl */
    if (rc == 0) {
        if (verbose) fprintf(messageFile,
                             "Sign: verify signature with OpenSSL and the key token\n");
        rc = osslVerify384(&valid,
                           digest,			/* input: digest to be verified */
                           rsaKeyTokenPublic.e,		/* exponent */
                           rsaKeyTokenPublic.eLength,
                           rsaKeyTokenPublic.n, 	/* public key */
                           rsaKeyTokenPublic.nByteLength,
                           signature,			/* signature */
                           signatureLength);
        if (!valid) {
            File_Printf(projectLogFile, messageFile,
                        "Sign: Error verifying signature with OpenSSL and the key token\n");
            rc = ERROR_CODE;
        }
    }
    /* write signature to the output attachment if supplied */
    if (rc == 0) {
        if (verbose) fprintf(messageFile, "Sign: Writing output file %s\n",
                             outputAttachmentFileName);
        rc = File_WriteBinaryFile(signature, signatureLength, outputAttachmentFileName);
    }
    /* write signature to the output body if specified */
    if ((rc == 0) && text) {
        /* write the signature as hex ascii to the output body */
        if (rc == 0) {
            char *signatureString = NULL;	/* freed @3 */
            if (rc == 0) {
                rc = Malloc_Safe((unsigned char **)&signatureString,
                                 signatureLength * 4,
                                 signatureLength * 4);
            }
            if (rc == 0) {
                sprintAll(signatureString, signatureLength, signature);
                fprintf(messageFile, "Signature\n%s\n",
                        signatureString);
            }
            free(signatureString);	/* @3 */
        }
    }
    /* clean up */
    free(keyToken);	/* @1 */
    free(digest);	/* @2 */
    return rc;
}

/* GetArgs() gets the command line arguments from the framework.
 */

int GetArgs(const char **outputBodyFilename,
            const char **usr,
            const char **password,
            const char **projectLogFileName,
            const char **sender,
            const char **project,
            const char **keyFileName,
            const char **inputAttachmentFileName,
            const char **outputAttachmentFileName,
            unsigned int *bitSize,
            int *text,
            int *verbose,
            int argc,
            char **argv)
{
    long	rc = 0;
    int 	i = 0;
    FILE	*tmpFile = NULL;
    char 	dummy = '\0';  /* extra characters */

    /* command line argument defaults */
    *outputBodyFilename = NULL;
    *text = FALSE;
    *verbose = FALSE;

    /* get the command line arguments */
    for (i = 1 ; (i < argc) && (rc == 0) ; i++) {
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
                *usr = argv[i];
            }
            else {
                fprintf(messageFile,
                        "ERROR1003: -usr option (CCA user ID) needs a value\n");
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
        else if (strcmp(argv[i],"-key") == 0) {
            i++;
            if (i < argc) {
                *keyFileName = argv[i];
            }
            else {
                fprintf(messageFile,
                        "ERROR1008: -key option needs a value\n");
                rc = ERROR_CODE;
            }
        }
        else if (strcmp(argv[i],"-di") == 0) {
            i++;
            if (i < argc) {
                *inputAttachmentFileName = argv[i];
            }
            else {
                fprintf(messageFile,
                        "ERROR1016: -di option needs a value\n");
                rc = ERROR_CODE;
            }
        }
        else if (strcmp(argv[i],"-do") == 0) {
            i++;
            if (i < argc) {
                *outputAttachmentFileName = argv[i];
            }
            else {
                fprintf(messageFile,
                        "ERROR1009: -do option needs a value\n");
                rc = ERROR_CODE;
            }
        }
        else if (strcmp(argv[i],"-text") == 0) {
            *text = TRUE;
        }
        /* this allows the framework to probe whether the project specific program can be called.
           The program should do nothing except return success. */
        else if (strcmp(argv[i],"-h") == 0) {
            PrintUsage();
            exit(0);
        }
        else if (strcmp(argv[i],"-sz") == 0) {
            i++;
            int irc = sscanf(argv[i], "%u%c", bitSize, &dummy);
            if (irc != 1 || *bitSize < N_BIT_SIZE ||
                *bitSize > N_BIT_SIZE_MAX) {
                fprintf(messageFile,
                        "ERROR1009: -sz illegal\n");
                rc = ERROR_CODE;
            }
        }
        else if (strcmp(argv[i],"-v") == 0) {
            *verbose = TRUE;
        }
        /* This code intentionally does not have an 'else error' clause.  The framework can in
           general add command line arguments that are ignored by the project specific program. */
    }
    /* verify mandatory command line arguments */
    if (rc == 0) {
        // If the usr isn't specified just use the sender
        if (*usr == NULL) {
            *usr = *sender;
        }
        if (*usr == NULL) {
            fprintf(messageFile,
                    "ERROR1010: -usr option missing\n");
            rc = ERROR_CODE;
        }
    }
    if (rc == 0) {
        if (*password == NULL) {
            fprintf(messageFile,
                    "ERROR1017: -pwd option missing\n");
            rc = ERROR_CODE;
        }
    }
    if (rc == 0) {
        if (*sender== NULL) {
            fprintf(messageFile,
                    "ERROR1011: -sender option missing\n");
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
        if (*keyFileName == NULL) {
            fprintf(messageFile,
                    "ERROR1014: -key option missing\n");
            rc = ERROR_CODE;
        }
    }
    if (rc == 0) {
        if (*inputAttachmentFileName == NULL) {
            fprintf(messageFile,
                    "ERROR1017: -di option missing\n");
            rc = ERROR_CODE;
        }
    }
    if (rc == 0) {
        if (*outputAttachmentFileName == NULL) {
            fprintf(messageFile,
                    "ERROR1020: -do option missing\n");
            rc = ERROR_CODE;
        }
    }
    if (rc == 0) {
        if (*bitSize == N_BIT_SIZE) {
            MOD_SIZE = N_SIZE;
        } else if (*bitSize == N_BIT_SIZE_MAX) {
            MOD_SIZE = N_SIZE_MAX;
        } else {
            fprintf(messageFile,
                    "ERROR1020: -sz unsupported size\n");
            rc = ERROR_CODE;
        }
    }
    return rc;
}

void PrintUsage()
{
    fprintf(messageFile, "\n");
    fprintf(messageFile,
            "\tsign_sha384 usage:\n"
            "\n"
            "Common arguments:\n"
            "\n"
            "\t-usr        - CCA user (profile) ID\n"
            "\t[-text      - Include a hex ascii signature in the email body]\n"
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
            "\t-di         - input attachment file name\n"
            "\t-do         - output attachment file name\n"
            "\t-log        - project audit log file name\n"
            "\t-key        - project CCA signing key token\n"
            "\t-pwd        - CCA user password (plaintext)\n"
            );
    fprintf(messageFile, "\n");
    return;
}
