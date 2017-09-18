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

/* local */
#include "ossl_functions.h"
#include "cca_structures.h"
#include "cca_structures_ecc.h"
#include "utils.h"
#include "debug.h"

#include "eccutils.h"

/* global variables */

FILE *messageFile = NULL;	/* needed for utilities */
int verbose = FALSE;
int debug = FALSE;

/* local prototypes */

int GetArgs(const char **outputBodyFilename,
            const char **outputAttachmentFileName,
            const char **projectLogFileName,
            const char **sender,
            const char **project,
            const char **type,
            const char **auxcfgFilename,
            int *verbose,
            int argc,
            char **argv);
int GetKeyFilename(char **keyFileName,
                   char *projectConfigFilename);

void PrintUsage(void);

/* see printUsage() for the program description */

int main(int argc, char** argv)
{
    int			rc = 0;		/* general return code */
    size_t		i;

    /* command line argument defaults */
    const char 		*outputBodyFilename = NULL;
    const char 		*outputAttachmentFileName = NULL;
    const char 		*projectLogFileName = NULL;	/* project audit log */
    FILE		*projectLogFile = NULL;		/* closed @1 */
    const char 		*sender = NULL;
    const char 		*project = NULL;
    const char 		*type = NULL;
    const char		*auxcfgFilename = NULL;	/* project auxiliary configuration file name */

    /* parameters from project auxiliary configuration file */
    char 		*signAlgorithm = NULL;			/* freed @2 */
    char 		*digestAlgorithm = NULL;		/* freed @3 */
    int 		checkUnique;
    int                 rawHeaderInput;
    unsigned int 	numberOfProjectFiles = 0;
    char 		**projectConfigFilenames = NULL;	/* freed @4 */

    char 		*keyFileName = NULL;		/* signing CCA key token file, freed @5 */
    unsigned char 	*keyToken = NULL;		/* CCA key token, freed @6 */
    size_t	 	keyTokenLength;
    EccKeyTokenPublic 	eccKeyTokenPublic;		/* CCA public key structure */
    unsigned char 	*publicKeyArray = NULL;		/* freed @7 */
    size_t		publicKeyArrayLength = 0;	/* is the currently used area */
    messageFile = stdout;

    /* command line argument defaults */
    verbose = FALSE;
    debug = FALSE;

    /* get command line arguments */
    if (rc == 0) {
        rc = GetArgs(&outputBodyFilename,		/* closed @1 */
                     &outputAttachmentFileName,
                     &projectLogFileName,
                     &sender,
                     &project,
                     &type,
                     &auxcfgFilename,
                     &verbose,
                     argc, argv);
    }
    /* project audit log */
    if (rc == 0) {
        if (verbose) fprintf(messageFile, "Opening audit log %s\n", projectLogFileName);
        projectLogFile = fopen(projectLogFileName, "a");		/* closed @1 */
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
    }
    /* get additional parameters from the project auxiliary configuration file */
    if (rc == 0) {
        rc = GetAuxArgs(&signAlgorithm,			/* freed @2 */
                        &digestAlgorithm,		/* freed @3 */
                        &checkUnique,
                        &rawHeaderInput,                /* Raw Prefix Header or hash provided? */
                        &numberOfProjectFiles,
                        &projectConfigFilenames,	/* array of file names, freed @4 */
                        auxcfgFilename);
    }
    if (rc == 0) {
        fprintf(projectLogFile, "\tType: %s\n", type);
    }
    /* for each signing project file */
    for (i = 0 ; (rc == 0) && (i < numberOfProjectFiles) ; i++) {

        /* get the signing key file name from the project configuration file */
        keyFileName = NULL;
        if (rc == 0) {
            rc = GetKeyFilename(&keyFileName, 		/* freed @5 */
                                projectConfigFilenames[i]);
        }
        /* audit logging */
        if (rc == 0) {
            fprintf(projectLogFile, "\tProject configuration file name: %s\n",
                    projectConfigFilenames[i]);
            fprintf(projectLogFile, "\tSigning key file name: %s\n", keyFileName);
        }
        /* read the key token file */
        if (rc == 0) {
            if (verbose) fprintf(messageFile, "Key token %u at %s\n",
                                 (uint)i+1, keyFileName);
            rc = File_ReadBinaryFile(&keyToken, &keyTokenLength, 4000, keyFileName); /* freed @6 */
        }
        if (rc == 0) {
            if (verbose) fprintf(messageFile, "Key token %u length %lu\n",
                                 (uint)i+1, (unsigned long)keyTokenLength);
        }
        /* extract the public key from the key token */
        if (rc == 0) {
            if (verbose) fprintf(messageFile, "Extracting the public key from the key token\n");
            rc = getPKA96EccPublicKey(&eccKeyTokenPublic,	/* output: CCA structure */
                                      keyTokenLength,
                                      keyToken);		/* input: PKA96 key token */
        }
        if (rc == 0) {
            if (verbose) PrintAll(messageFile,
                                  "Public key",
                                  eccKeyTokenPublic.qLen, eccKeyTokenPublic.publicKey);
        }
        if (rc == 0) {
            if (verbose) fprintf(messageFile, "Growing the array for the public key to %u\n",
                                 (uint)publicKeyArrayLength + eccKeyTokenPublic.qLen);
            rc = Realloc_Safe(&publicKeyArray,		/* freed @7 */
                              publicKeyArrayLength + eccKeyTokenPublic.qLen);
        }
        /* append the public key to the public keys array */
        if (rc == 0) {
            if (verbose) fprintf(messageFile, "Appending the public key to the array\n");
            memcpy(publicKeyArray + publicKeyArrayLength,
                   eccKeyTokenPublic.publicKey,
                   eccKeyTokenPublic.qLen);
            publicKeyArrayLength += eccKeyTokenPublic.qLen;
        }

        /* close stuff */
        free(keyFileName);		/* @5 */
        keyFileName = NULL;		/* for next time through the loop */
        free(keyToken);			/* @6 */
        keyToken = NULL;		/* for next time through the loop */
    }
    if (rc == 0) {
        if (verbose) fprintf(messageFile, "Type of response: %s\n", type);
        unsigned char digest[SHA512_SIZE];
        /* if a digest is to be returned, today only supports SHA-512, in the future, strcmp() on
           digestAlgorithm here */
        if (strcmp(type, "digest") == 0) {
            if (verbose) fprintf(messageFile, "Digesting the public key array\n");
            Ossl_SHA512(digest,
                        publicKeyArrayLength, publicKeyArray,
                        0L, NULL);
            if (verbose) PrintAll(messageFile,
                                  "Digest of public key array",
                                  SHA512_SIZE, digest);
            /* write the public keys digest to the output attachment  */
            if (verbose) fprintf(messageFile, "Writing binary to output file %s\n",
                                 outputAttachmentFileName);
            rc = File_WriteBinaryFile(digest, SHA512_SIZE,
                                      outputAttachmentFileName);
        }
        /* if the array of public keys is to be returned */
        else {
            /* write the public keys array to the output attachment  */
            if (verbose) fprintf(messageFile, "Writing binary to output file %s\n",
                                 outputAttachmentFileName);
            rc = File_WriteBinaryFile(publicKeyArray, publicKeyArrayLength,
                                      outputAttachmentFileName);
        }
    }
    /* cleanup */
    File_Printf(projectLogFile, messageFile, "Return code: %u\n", rc);

    if (projectLogFile != NULL) {
        fclose(projectLogFile);			/* @1 */
    }
    free(signAlgorithm);			/* @2 */
    free(digestAlgorithm);			/* @3 */
    if (projectConfigFilenames != NULL) {
        for (i = 0 ; i < numberOfProjectFiles ; i++) {
            free(projectConfigFilenames[i]);
        }
        free(projectConfigFilenames);		/* @4 */
    }
    free(keyFileName);				/* @5 */
    free(keyToken);				/* @6 */
    free(publicKeyArray);			/* @7 */
    if (messageFile != stdout) {
        fflush(messageFile);
        fclose(messageFile);
        messageFile = stdout;
    }
    return rc;
}

int GetKeyFilename(char **keyFileName, 		/* freed by caller */
                   char *projectConfigFilename)
{
    int		rc = 0;				/* general return code */
    char	*lineBuffer = NULL;		/* freed @2 */
    size_t	lineBufferLength = 4000;	/* hard code for the project */
    FILE 	*projectConfigFile = NULL;	/* closed @1 */

    /* open project configuration file */
    if (rc == 0) {
        if (verbose) fprintf(messageFile,
                             "Opening project configuration file %s\n",
                             projectConfigFilename);
        projectConfigFile = fopen(projectConfigFilename, "r");	/* closed @1 */
        if (projectConfigFile == NULL) {
            fprintf(messageFile,
                    "ERROR1016: Cannot open project configuration file %s, %s\n",
                    projectConfigFilename, strerror(errno));
            rc = ERROR_CODE;
        }
    }
    /* allocate a line buffer, used when parsing the configuration file */
    if (rc == 0) {
        rc = Malloc_Safe((unsigned char **)&lineBuffer,	/* freed @2 */
                         lineBufferLength,
                         lineBufferLength);		/* hard code for the project */
    }
    /* digest algorithm */
    if (rc == 0) {
        rc = File_MapNameToValue(keyFileName,		/* freed by caller */
                                 "key",
                                 lineBuffer,
                                 lineBufferLength,
                                 projectConfigFile);
    }
    if (rc == 0) {
        if (verbose) fprintf(messageFile,
                             "Key file name %s\n",
                             *keyFileName);
    }
    if (projectConfigFile != NULL) {
        fclose(projectConfigFile);	/* @1 */
    }
    free(lineBuffer);			/* @2 */
    return rc;
}

int GetArgs(const char **outputBodyFilename,		/* close as messageFile */
            const char **outputAttachmentFileName,
            const char **projectLogFileName,
            const char **sender,
            const char **project,
            const char **type,
            const char **auxcfgFilename,
            int *verbose,
            int argc,
            char **argv)
{
    int rc = 0;
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
                        "ERROR1001: -obody option (output email body) needs a value\n");
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
                        "ERROR1002: -log option (audit log file name) needs a value\n");
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
                        "ERROR1003: -sender option needs a value\n");
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
                        "ERROR1004: -project option needs a value\n");
                rc = ERROR_CODE;
            }
        }
        else if (strcmp(argv[i],"-type") == 0) {
            i++;
            if (i < argc) {
                *type = argv[i];
            }
            else {
                fprintf(messageFile,
                        "ERROR1005: -type option needs a value\n");
                rc = ERROR_CODE;
            }
        }
        else if (strcmp(argv[i],"-auxcfg") == 0) {
            i++;
            if (i < argc) {
                *auxcfgFilename = argv[i];
            }
            else {
                fprintf(messageFile,
                        "ERROR1006: -auxcfg option needs a value\n");
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
                        "ERROR1007: -do option needs a value\n");
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
                    "ERROR1008: -do option missing\n");
            rc = ERROR_CODE;
        }
    }
    if (rc == 0) {
        if (*projectLogFileName == NULL) {
            fprintf(messageFile,
                    "ERROR1009: -log option missing\n");
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
                    "ERROR1011: -project option missing\n");
            rc = ERROR_CODE;
        }
    }
    if (rc == 0) {
        if (*type == NULL) {
            fprintf(messageFile,
                    "ERROR1012: -type option missing\n");
            rc = ERROR_CODE;
        }
    }
    if (rc == 0) {
        if ((strcmp(*type, "keys") != 0) &&
            (strcmp(*type, "digest") != 0)) {
            fprintf(messageFile,
                    "ERROR1013: -type %s illegal value\n", *type);
            rc = ERROR_CODE;
        }
    }
    if (rc == 0) {
        if (*auxcfgFilename == NULL) {
            fprintf(messageFile,
                    "ERROR1014: -auxcfg option missing\n");
            rc = ERROR_CODE;
        }
    }
    return rc;
}

void PrintUsage()
{
    fprintf(messageFile, "\n");
    fprintf(messageFile,
            "\tgekeysecc usage:\n"
            "\n"
            "Common arguments:\n"
            "\n"
            "\t[-v          - verbose logging]\n"
            "\t[-h          - print usage help]\n"
            "\t-type        - response type\n"
            "\t\tkeys       - return an array of public keys\n"
            "\t\tdigest     - return a digest of an array of public keys\n"
            "\n"

            "Email only arguments:\n"
            "\n"
            "\t-project     - project name\n"
            "\n"

            "Command line only arguments:\n"
            "\n"
            "\t-obody       - output email body file name (should be first argument)\n"
            "\t-sender      - email sender\n"
            "\t-do          - output attachment file name\n"
            "\t-log         - project audit log file name\n"
            "\t-auxcfg      - project auxiliary configuration file name\n"

            "\n"
            "Email example: -project getkeysp8hw\n"
            "\n"
            "Extracts the public keys from the CCA ECC key tokens in the key files\n"
            "Returns either an array of keys or a digest of the array\n"
            );
    fprintf(messageFile, "\n");
    return;
}
