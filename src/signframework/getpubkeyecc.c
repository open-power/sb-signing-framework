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
#include "framework_utils.h"
#include "cca_structures_ecc.h"
#include "utils.h"
#include "debug.h"

/* global variables */

FILE *messageFile = NULL;		/* needed for utilities */
int verbose = FALSE;
int debug = FALSE;

/* local prototypes */

int GetArgs(const char **outputBodyFilename,
            const char **outputAttachmentFileName,
            const char **projectLogFileName,
            const char **sender,
            const char **project,
            const char **signproject,
            int *verbose,
            int argc,
            char **argv);

void PrintUsage(void);

/* see printUsage() for the program description */

int main(int argc, char** argv)
{
    int			rc = 0;		/* general return code */

    /* command line argument defaults */
    const char 		*outputBodyFilename = NULL;
    const char 		*outputAttachmentFileName = NULL;
    const char 		*projectLogFileName = NULL;	/* project audit log */
    FILE		*projectLogFile = NULL;		/* closed @1 */
    const char 		*sender = NULL;
    const char 		*project = NULL;
    const char 		*signproject = NULL;

    unsigned char 	*keyToken = NULL;	/* CCA key token, freed @2 */
    size_t	 	keyTokenLength;
    EccKeyTokenPublic 	eccKeyTokenPublic;	/* CCA public key structure */

    const char		*frameworkConfigFileName = NULL;
    FILE		*frameworkConfigFile = NULL;	/* freed @3 */
    char		*projectConfigFilename = NULL;	/* freed @4 */
    FILE 		*projectConfigFile = NULL;	/* closed @5 */
    ProjectConfig 	projectConfig;
    char 		*keyFileName = NULL;	/* signing CCA key token file, freed @6 */

    char		lineBuffer[MAX_LINE_SIZE];

    messageFile = stdout;
    ProjectConfig_Init(&projectConfig);		/* freed @7 */

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
        frameworkConfigFile = fopen(frameworkConfigFileName, "r");	/* closed @3 */
        if (frameworkConfigFile == NULL) {
            File_Printf(projectLogFile, messageFile,
                        "ERROR1016, Cannot open %s\n", frameworkConfigFileName);
            rc = ERROR_CODE;
        }
    }
    /* get the file name for project configuration file */
    if (rc == 0) {
        rc = File_MapNameToValue(&projectConfigFilename,	/* freed @4 */
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
        projectConfigFile = fopen(projectConfigFilename, "r");	/* closed @5 */
        if (projectConfigFile == NULL) {
            File_Printf(projectLogFile, messageFile,
                        "ERROR1017, Cannot open %s\n", projectConfigFilename);
            rc = ERROR_CODE;
        }
    }
    /* get the file name for the signing key */
    if (rc == 0) {
        rc = File_MapNameToValue(&keyFileName,	/* freed @6 */
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
    /* get the key token */
    if (rc == 0) {
        if (verbose) fprintf(messageFile, "Key token at %s\n",
                             keyFileName);
        rc = File_ReadBinaryFile(&keyToken, &keyTokenLength, 4000, keyFileName); /* freed @2 */
    }
    if (rc == 0) {
        if (verbose) fprintf(messageFile, "Key token length %lu\n",
                             (unsigned long)keyTokenLength);
    }
    /* extract the public key from the key token */
    if (rc == 0) {
        if (verbose) fprintf(messageFile, "Extract the public key from the key token\n");
        rc = getPKA96EccPublicKey(&eccKeyTokenPublic,	/* output: CCA structure */
                                  keyTokenLength,
                                  keyToken);		/* input: PKA96 key token */
    }
    /* write the public key binary to the output attachment  */
    if (rc == 0) {
        if (verbose) fprintf(messageFile, "Writing binary to output file %s\n",
                             outputAttachmentFileName);
        rc = File_WriteBinaryFile(eccKeyTokenPublic.publicKey, eccKeyTokenPublic.qLen,
                                  outputAttachmentFileName);
    }
    if (rc == 0) {
        PrintAll(projectLogFile, "\tPublic Key", eccKeyTokenPublic.qLen, eccKeyTokenPublic.publicKey);
    }
    /* cleanup */
    File_Printf(projectLogFile, messageFile, "Return code: %u\n", rc);
    /* cleanup */
    /* close the framework configuration file */
    if (frameworkConfigFile != NULL) {
        fclose(frameworkConfigFile);		/* @3 */
    }
    free(projectConfigFilename);		/* @4 */
    /* close the project configuration file */
    if (projectConfigFile != NULL) {
        fclose(projectConfigFile);		/* @5 */
    }
    free(keyFileName);				/* @6 */
    free(keyToken);				/* @2 */
    ProjectConfig_Delete(&projectConfig);	/* @7 */
    if (projectLogFile != NULL) {
        fclose(projectLogFile);			/* @1 */
    }
    if (messageFile != stdout) {
        fflush(messageFile);
        fclose(messageFile);			/* @8 */
        messageFile = stdout;
    }
    return rc;
}

int GetArgs(const char **outputBodyFilename,
            const char **outputAttachmentFileName,
            const char **projectLogFileName,
            const char **sender,
            const char **project,
            const char **signproject,
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
            "\tgetpubkeyecc usage:\n"
            "\n"
            "Common arguments:\n"
            "\n"
            "\t-signproject - signing project name\n"
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
            "Email example: -project getpubkeyecc -signproject athena\n"
            "\n"
            "Extracts the public key from the CCA ECC key token in the key file\n"
            "The resulting public key is returned as binary\n"
            );
    fprintf(messageFile, "\n");
    return;
}
