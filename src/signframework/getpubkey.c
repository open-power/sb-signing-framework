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
#include <errno.h>

#include "openssl/evp.h"
#include "openssl/pem.h"

/* local */
#include "framework_utils.h"
#include "cca_structures.h"
#include "ossl_functions.h"
#include "utils.h"
#include "debug.h"

/* global variables */

FILE *messageFile = NULL;		/* needed for utilities */
int verbose = FALSE;
int debug = FALSE;

#define FORMAT_BINARY 0
#define FORMAT_LE32 1
#define FORMAT_PEM 2

/* local prototypes */

int pubkeyBinToC(unsigned long *pubkeyc_length,
                 char **pubkeyc,
                 unsigned long pubkey_length,
                 unsigned char *pubkey);

int GetArgs(const char **outputBodyFilename,
            const char **outputAttachmentFileName,
            const char **projectLogFileName,
            const char **sender,
            const char **project,
            const char **signproject,
            unsigned int *format,
            int *verbose,
            int argc,
            char **argv);

void PrintUsage(void);

/* see printUsage() for the program description */

int main(int argc, char** argv)
{
    int			rc = 0;		/* general return code */

    /* command line arguments */
    const char 		*outputBodyFilename = NULL;
    const char 		*outputAttachmentFileName = NULL;
    const char 		*projectLogFileName = NULL;	/* project audit log */
    FILE		*projectLogFile = NULL;	/* closed @5 */
    const char 		*sender = NULL;
    const char 		*project = NULL;
    const char 		*signproject = NULL;
    unsigned int	format = FORMAT_BINARY;	/* return format */

    unsigned char 	*keyToken = NULL;	/* CCA key token, freed @6 */
    size_t	 	keyTokenLength;
    RsaKeyTokenPublic 	rsaKeyTokenPublic;	/* CCA public key structure */
    char 		*pubkeyc = NULL;	/* public key as EFI C code, freed @7 */
    unsigned long 	pubkeyc_length;

    const char		*frameworkConfigFileName = NULL;
    FILE		*frameworkConfigFile = NULL;	/* freed @1 */
    char		*projectConfigFilename = NULL;	/* freed @2 */
    FILE 		*projectConfigFile = NULL;	/* closed @3 */
    ProjectConfig 	projectConfig;
    char 		*keyFileName = NULL;	/* signing CCA key token file, freed @4 */

    char		lineBuffer[MAX_LINE_SIZE];

    messageFile = stdout;
    ProjectConfig_Init(&projectConfig);		/* freed @9 */

    /* command line argument defaults */
    verbose = FALSE;
    debug = FALSE;

    /* get command line arguments */
    if (rc == 0) {
        rc = GetArgs(&outputBodyFilename,
                     &outputAttachmentFileName,
                     &projectLogFileName,
                     &sender,
                     &project,
                     &signproject,
                     &format,
                     &verbose,
                     argc, argv);
    }
    /* project audit log */
    if (rc == 0) {
        if (verbose) fprintf(messageFile, "Opening audit log %s\n", projectLogFileName);
        projectLogFile = fopen(projectLogFileName, "a");		/* closed @5 */
        if (projectLogFile == NULL) {
            fprintf(messageFile, "ERROR1015: Cannot open audit log %s, %s\n",
                    projectLogFileName, strerror(errno));
            rc = ERROR_CODE;
        }
    }
    /* update audit log, begin this entry */
    if (projectLogFile != NULL) {
        if (verbose) fprintf(messageFile, "Updating audit log\n");
        File_LogTime(projectLogFile);
        fprintf(projectLogFile, "\tSender: %s\n", sender);
        fprintf(projectLogFile, "\tProject: %s\n", project);
        fprintf(projectLogFile, "\tProgram: %s\n", argv[0]);
        fprintf(projectLogFile, "\tSigning Project: %s\n", signproject);
    }

    /*
      get parameters from the configuration files
    */
    /* get the file name of the framework configuration file from an environment variable */
    if (rc == 0) {
        frameworkConfigFileName = getenv("FRAMEWORK_CONFIG_FILE");
        if (frameworkConfigFileName == NULL) {
            File_Printf(projectLogFile, messageFile,
                        "ERROR1014, FRAMEWORK_CONFIG_FILE environment variable not set\n");
            rc = ERROR_CODE;
        }
    }
    /* open the framework configuration file */
    if (rc == 0) {
        if (verbose) fprintf(messageFile, "Framework configuration file %s\n",
                             frameworkConfigFileName);
        frameworkConfigFile = fopen(frameworkConfigFileName, "r");	/* freed @1 */
        if (frameworkConfigFile == NULL) {
            File_Printf(projectLogFile, messageFile,
                        "ERROR1016, Cannot open %s\n", frameworkConfigFileName);
            rc = ERROR_CODE;
        }
    }
    /* get the file name for project configuration file */
    if (rc == 0) {
        rc = File_MapNameToValue(&projectConfigFilename,	/* freed @2 */
                                 signproject,
                                 lineBuffer,
                                 MAX_LINE_SIZE,
                                 frameworkConfigFile);
        if (rc != 0) {
            File_Printf(projectLogFile, messageFile,
                        "ERROR1019, Cannot find project %s\n", signproject);
        }
    }

    /* open the project configuration file */
    if (rc == 0) {
        if (verbose) fprintf(messageFile, "Project configuration file %s\n",
                             projectConfigFilename);
        projectConfigFile = fopen(projectConfigFilename, "r");	/* freed @3 */
        if (projectConfigFile == NULL) {
            File_Printf(projectLogFile, messageFile,
                        "ERROR1017, Cannot open %s\n", projectConfigFilename);
            rc = ERROR_CODE;
        }
    }
    /* get the file name for the signing key */
    if (rc == 0) {
        rc = File_MapNameToValue(&keyFileName,	/* freed @4 */
                                 "key",
                                 lineBuffer,
                                 MAX_LINE_SIZE,
                                 projectConfigFile);
    }
    /* log the keyFileName */
    if (rc == 0) {
        fprintf(projectLogFile, "\tSigning Key file: %s\n", keyFileName);
        if (verbose) fprintf(messageFile, "Signing key file %s\n",
                             keyFileName);
    }
#if 0
    /* check the sender authorization */
    /* NOTE: There's nothing really secret about the public key.  Anyone can read it.  This step is
       more a demo of how a project program could check secondary authorization. */
    /* determine whether senders are needed */
    if (rc == 0) {
        rc = File_MapNameToBool(&(projectConfig.needSenders),
                                "needsenders",
                                lineBuffer,
                                MAX_LINE_SIZE,
                                projectConfigFile);
    }
    if (rc == 0) {
        if (verbose) fprintf(messageFile,
                             "Signing project needs senders: %d\n", projectConfig. needSenders);
    }
    /* read the list of authorized senders */
    if (rc == 0) {
        rc = File_GetNameValueArray(&(projectConfig.senders),	/* freed by caller */
                                    &(projectConfig.senderemails),	/* freed by caller */
                                    &(projectConfig.sendersCount), /* number of authorized senders */
                                    lineBuffer,
                                    MAX_LINE_SIZE,
                                    projectConfigFile);
    }
    /* check the sender authorization */
    if (rc == 0) {
        rc = ProjectConfig_ValidateSender(sender,
                                          &projectConfig, NULL);
        if (rc != 0) {
            File_Printf(projectLogFile, messageFile,
                        "ERROR1018: %s is not authorized for project: %s\n",
                        sender, signproject);
            fprintf(messageFile,
                    "Contact framework administrator\n");
        }
    }
#endif
    /* get the key token */
    if (rc == 0) {
        if (verbose) fprintf(messageFile, "Key token at %s\n",
                             keyFileName);
        rc = File_ReadBinaryFile(&keyToken, &keyTokenLength, 4000, keyFileName); /* freed @1 */
    }
    if (rc == 0) {
        if (verbose) fprintf(messageFile, "Key token length %lu\n",
                             (unsigned long)keyTokenLength);
    }
    /* extract the public key from the key token */
    if (rc == 0) {
        if (verbose) fprintf(messageFile, "Extract the public key from the key token\n");
        rc = getPKA96PublicKey(&rsaKeyTokenPublic,	/* output: CCA structure */
                               keyTokenLength,
                               keyToken,		/* input: PKA96 key token */
                               0);
    }
    /* verify the public key length */
    if (rc == 0) {
        if (verbose) fprintf(messageFile, "Public key length %u\n",
                             rsaKeyTokenPublic.nByteLength);
    }
    /* write the public key binary to the output attachment */
    if (rc == 0) {

        EVP_PKEY *publicKey = NULL;          	/* OpenSSL public key, freed @1*/
        RSA *rsaPubKey = NULL;			/* OpenSSL public key, freed @2 */
        FILE *pubkeyFile = NULL;

        switch (format) {
        case FORMAT_BINARY:	/* return binary */
            if (verbose) fprintf(messageFile, "Writing binary to output file %s\n",
                                 outputAttachmentFileName);
            rc = File_WriteBinaryFile(rsaKeyTokenPublic.n, rsaKeyTokenPublic.nByteLength,
                                      outputAttachmentFileName);
            break;
        case FORMAT_LE32:
            /* convert the binary big endian public key to EFI format C code */
            if (rc == 0) {
                rc = pubkeyBinToC(&pubkeyc_length,
                                  &pubkeyc,		/* freed @7 */
                                  rsaKeyTokenPublic.nByteLength,
                                  rsaKeyTokenPublic.n);
            }
            /* write the EFI format C code public key to a file */
            if (rc == 0) {
                if (verbose) fprintf(messageFile,
                                     "Writing little endian 32-bit to output file %s\n",
                                     outputAttachmentFileName);
                rc = File_WriteBinaryFile((unsigned char *)pubkeyc,
                                          pubkeyc_length-1,	/* omit the nuil terminator */
                                          outputAttachmentFileName);
            }
            break;
        case FORMAT_PEM:
            /* allocate the EVP structure */
            if (rc == 0) {
                OpenSSL_add_all_algorithms();
                publicKey = EVP_PKEY_new();			/* freed @1 */
                if (publicKey == NULL) {
                    File_Printf(projectLogFile, messageFile,
                                "ERROR1011: Unable to create openssl EVP_PKEY structure");
                    rc = ERROR_CODE;
                }
            }
            /* convert the raw public key to openssl RSA structure */
            if (rc == 0) {
                rc = osslBinToRSA(&rsaPubKey,			/* freed %2 */
                                  rsaKeyTokenPublic.e,
                                  rsaKeyTokenPublic.eLength,
                                  rsaKeyTokenPublic.n,
                                  rsaKeyTokenPublic.nByteLength);
                if (rc != 0) {
                    File_Printf(projectLogFile, messageFile,
                                "ERROR1020: Unable to convert public key to openssl RSA");
                    rc = ERROR_CODE;
                }
            }
            /* convert the RSA structure to EVP */
            if (rc == 0) {
                /* 1 success, 0 failure */
                rc = EVP_PKEY_assign_RSA(publicKey, rsaPubKey);
                if (rc != 1) {
                    File_Printf(projectLogFile, messageFile,
                                "ERROR1022: Unable to convert public key to openssl EVP");
                    rc = ERROR_CODE;
                }
                else {
                    rc = 0;
                }
            }
            if (rc == 0) {
                pubkeyFile = fopen(outputAttachmentFileName,"wb");
                if (pubkeyFile == NULL) {
                    File_Printf(projectLogFile, messageFile,
                                "ERROR1023: Unable to open %s\n", outputAttachmentFileName);
                    rc = ERROR_CODE;
                }
            }
            if (rc == 0) {
                /* 1 success, 0 failure */
                rc = PEM_write_PUBKEY(pubkeyFile, publicKey);
                if (rc != 1) {
                    File_Printf(projectLogFile, messageFile,
                                "ERROR1024: Unable to write public key to %s\n",
                                outputAttachmentFileName);
                    rc = ERROR_CODE;
                }
                else {
                    rc = 0;
                }
            }
            if (publicKey != NULL) {		/* @2, also frees the RSA structure */
                EVP_PKEY_free(publicKey);
                rsaPubKey = NULL;
            }
            if (rsaPubKey != NULL) {
                RSA_free(rsaPubKey);		/* @1, if not freed above */
            }
            break;
        default:
            File_Printf(projectLogFile, messageFile,
                        "ERROR1003: format has illegal value: %u\n", format);
            rc = ERROR_CODE;
            break;
        }

    }
    if (rc == 0) {
        PrintAll(projectLogFile, "\tPublic Key", rsaKeyTokenPublic.nByteLength, rsaKeyTokenPublic.n);
    }
    /* cleanup */
    File_Printf(projectLogFile, messageFile, "Return code: %u\n", rc);
    /* close the framework configuration file */
    if (frameworkConfigFile != NULL) {
        fclose(frameworkConfigFile);		/* @1 */
    }
    free(projectConfigFilename);		/* @2 */
    /* close the project configuration file */
    if (projectConfigFile != NULL) {
        fclose(projectConfigFile);		/* @3 */
    }
    free(keyFileName);				/* @4 */
    free(keyToken);				/* @6 */
    free(pubkeyc);				/* @7 */
    ProjectConfig_Delete(&projectConfig);	/* @9 */
    if (projectLogFile != NULL) {
        fclose(projectLogFile);			/* @5 */
    }
    if (messageFile != stdout) {
        fflush(messageFile);
        fclose(messageFile);			/* @8 */
        messageFile = stdout;
    }
    return rc;
}

/* convert a binary public key to EFI (little endian) C code
 */

int pubkeyBinToC(unsigned long *pubkeyc_length,	/* in bytes */
                 char **pubkeyc,
                 unsigned long pubkey_length,		/* in bytes */
                 unsigned char *pubkey)
{
    int			rc = 0;		/* general return code */
    size_t		max;		/* total length of pubkeyc */
    size_t 		preamble_length;
    size_t 		postamble_length;
    size_t		i;		/* counts words */
    size_t		j;		/* counts bytes in a word */
    unsigned long	pubkey_length_words;

    const char *preamble = "static UINTN mPlatformKey[] = \n{";
    const char *postamble = "\n};\n";

    if (rc == 0) {
        pubkey_length_words = pubkey_length / 4;
        *pubkeyc_length = 0;
        preamble_length = strlen(preamble);
        postamble_length = strlen(postamble);
        max = preamble_length +
            (pubkey_length * 8) +	/* this is overly conservative, 4 bytes needs about 12
                                       bytes */
            postamble_length;
        *pubkeyc = malloc(max);
        if (*pubkeyc == NULL) {
            printf("ERROR1004, failure to malloc %u bytes\n", (uint)max);
            rc = ERROR_CODE;
        }
    }
    /* copy the preamble */
    if (rc == 0) {
        strcpy((*pubkeyc) + *pubkeyc_length, preamble);
        *pubkeyc_length += preamble_length;

        for (i = 0 ; i <  pubkey_length_words ; i ++) {
            /* every 4 32-bit ints is a new line */
            if ((i % 4) == 0) {
                if (i != 0) {		/* no comma before first int */
                    *pubkeyc_length += sprintf((*pubkeyc) + *pubkeyc_length, ",");
                }
                *pubkeyc_length += sprintf((*pubkeyc) + *pubkeyc_length, "\n  0x");
            }
            /* every 32-bit int is a new word */
            else  {
                *pubkeyc_length += sprintf((*pubkeyc) + *pubkeyc_length, ", 0x");
            }
            /* print the 4 bytes in an int, starting at the lsb's */
            for (j = 0 ; j < 4 ; j++) {
                *pubkeyc_length += sprintf((*pubkeyc) + *pubkeyc_length, "%02x",
                                           pubkey[((pubkey_length_words - i - 1) * 4) + j]);
            }
        }
        /* copy the postamble */
        strcpy((*pubkeyc) + *pubkeyc_length, postamble);
        *pubkeyc_length += postamble_length + 1;	/* +1 for the nul terminator */

        if (verbose) fprintf(messageFile, "pubkeyBinToC: public key\n%s\n", *pubkeyc);
    }
    return rc;
}

int GetArgs(const char **outputBodyFilename,
            const char **outputAttachmentFileName,
            const char **projectLogFileName,
            const char **sender,
            const char **project,
            const char **signproject,
            unsigned int *format,
            int *verbose,
            int argc,
            char **argv)
{
    long	rc = 0;
    int 	i;
    FILE	*tmpFile;

    /* command line argument defaults */
    *outputBodyFilename = NULL;
    *outputAttachmentFileName = NULL;

    /* get the command line arguments */
    for (i=1 ; (i<argc) && (rc == 0) ; i++) {
        if (strcmp(argv[i],"-obody") == 0) {
            i++;
            if (i < argc) {
                *outputBodyFilename = argv[i];
                rc = File_Open(&tmpFile, *outputBodyFilename, "a");	/* closed @8 */
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
        else if (strcmp(argv[i],"-signproject") == 0) {
            i++;
            if (i < argc) {
                *signproject = argv[i];
            }
            else {
                fprintf(messageFile,
                        "ERROR1007: -signproject option needs a value\n");
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
        else if (strcmp(argv[i],"-format") == 0) {
            i++;
            if (strcmp(argv[i],"binary") == 0) {
                *format = FORMAT_BINARY;
            }
            else if (strcmp(argv[i],"le32") == 0) {
                *format = FORMAT_LE32;
            }
            else if (strcmp(argv[i],"pem") == 0) {
                *format = FORMAT_PEM;
            }
            else {
                fprintf(messageFile, "ERROR1005: -format has illegal value: %s\n", argv[i]);
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
            *verbose = TRUE;
        }
        /* This code intentionally does not have an 'else error' clause.  The framework can in
           general add command line arguments that are ignored by the project specific program. */
    }
    /* verify command line arguments */
    if (rc == 0) {
        if (*outputAttachmentFileName == NULL) {
            fprintf(messageFile,
                    "ERROR1007: -do option missing\n");
            rc = ERROR_CODE;
        }
    }
    if (rc == 0) {
        if (*projectLogFileName == NULL) {
            fprintf(messageFile,
                    "ERROR1008: -log option missing\n");
            rc = ERROR_CODE;
        }
    }
    if (rc == 0) {
        if (*sender == NULL) {
            fprintf(messageFile,
                    "ERROR1010: -sender option missing\n");
            rc = ERROR_CODE;
        }
    }
    if (rc == 0) {
        if (*project == NULL) {
            fprintf(messageFile,
                    "ERROR1012: -project option missing\n");
            rc = ERROR_CODE;
        }
    }
    if (rc == 0) {
        if (*signproject == NULL) {
            fprintf(messageFile,
                    "ERROR1013: -signproject option missing\n");
            rc = ERROR_CODE;
        }
    }
    return rc;
}

void PrintUsage()
{
    fprintf(messageFile, "\n");
    fprintf(messageFile,
            "\tgetpubkey usage:\n"
            "\n"
            "Common arguments:\n"
            "\n"
            "\t-signproject - signing project name\n"
            "\t[-format     - return format (default binary)]\n"
            "\t             binary - returns public key in binary\n"
            "\t             le32   - returns public key as C code, 32-bit, little endian\n"
            "\t             pem    - returns public key as pem\n"
            "\t[-v          - verbose logging]\n"
            "\t[-h          - print usage help]\n"
            "\n"

            "Email only arguments:\n"
            "\n"
            "\t-project     - project name\n"
            "\n"

            "Command line only arguments:\n"
            "\n"
            "\t-obody      - output email body file name (should be first argument)\n"
            "\t-sender     - email sender\n"
            "\t-do         - output attachment file name\n"
            "\t-log        - project audit log file name\n"

            "\n"
            "Email example: -project getpubkey -signproject athena\n"
            "\n"
            "Extracts the public key from the CCA key token in the key file\n"
            "The resulting public key modulus is returned as binary or compilable\n"
            "C code\n"
            );
    fprintf(messageFile, "\n");
    return;
}
