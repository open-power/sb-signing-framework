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

#include <sys/stat.h>

#include "framework_utils.h"
#include "utils.h"
#include "cca_functions.h"

/* local prototypes */

int GetArgs(int argc,
            char **argv);
void PrintUsage(void);

/* global variables */

FILE *messageFile = NULL;
int verbose = TRUE;
int debug = TRUE;

int main(int argc, char** argv)
{
    int 		rc = 0;
    FrameworkConfig 	frameworkConfig;
    unsigned char 	masterAesKeyToken[CCA_KEY_IDENTIFIER_LENGTH];
    unsigned char 	*masterAesKeyTokenOut = NULL;	/* CCA key token (not the plaintext AES
                                                       key) */
    size_t	 	masterAesKeyTokenLengthOut;
    unsigned char 	eku[AES128_SIZE];		/* password encryption key */
    unsigned char 	aku[AKU_SIZE];		/* password authentication HMAC key */

    messageFile = stdout;	/* trace always goes to stdout */
    FrameworkConfig_Init(&frameworkConfig);	/* freed @1 */

    /* get command line arguments */
    if (rc == 0) {
        rc = GetArgs(argc, argv);
    }
    /* get the framework configuration file object */
    if (rc == 0) {
        rc = FrameworkConfig_Parse(FALSE,	/* do not need master key */
                                   TRUE,	/* validate */
                                   &frameworkConfig);
    }
    /* verify that the file does not exist */
    if (rc == 0) {
        if (verbose) fprintf(messageFile, "Testing for key token file %s\n",
                             frameworkConfig.masterAesKeyTokenFilename);
        if (frameworkConfig.masterAesKeyToken != NULL) {
            fprintf(messageFile, "Error, File %s already exists\n",
                    frameworkConfig.masterAesKeyTokenFilename);
            rc = ERROR_CODE;
        }
    }
    /* generate a master key */
    if (rc == 0) {
        if (verbose) fprintf(messageFile, "Generating key token\n");
        rc = Key_Generate(masterAesKeyToken);
    }
    /* write the AES key token to a file */
    if (rc == 0) {
        if (verbose) fprintf(messageFile, "Writing key token to %s\n",
                             frameworkConfig.masterAesKeyTokenFilename);
        rc = File_WriteBinaryFile(masterAesKeyToken,
                                  sizeof(masterAesKeyToken),
                                  frameworkConfig.masterAesKeyTokenFilename);
    }
    /* validate that the master AES key token file can be read */
    if (rc == 0) {
        if (verbose) fprintf(messageFile, "Reading back key token\n");
        rc = File_ReadBinaryFile(&masterAesKeyTokenOut,		/* freed @5 */
                                 &masterAesKeyTokenLengthOut,
                                 CCA_KEY_IDENTIFIER_LENGTH,
                                 frameworkConfig.masterAesKeyTokenFilename);
    }
    /* sanity check the length */
    if (rc == 0) {
        if (masterAesKeyTokenLengthOut != sizeof(masterAesKeyToken)) {
            fprintf(messageFile, "Error reading %s - length mismatch\n",
                    frameworkConfig.masterAesKeyTokenFilename);
            rc = ERROR_CODE;
        }
    }
    /* sanity check the contents */
    if (rc == 0) {
        rc = memcmp(masterAesKeyToken, masterAesKeyTokenOut, masterAesKeyTokenLengthOut);
        if (rc != 0) {
            fprintf(messageFile, "Error reading %s - data mismatch\n",
                    frameworkConfig.masterAesKeyTokenFilename);
            rc = ERROR_CODE;
        }
    }
    /* validate that the master AES key token can be used */
    if (rc == 0) {
        if (verbose) fprintf(messageFile, "Using key token\n");
        rc = Password_KDF(eku,			/* user encryption key */
                          aku,			/* user authentication HMAC key */
                          frameworkConfig.frameworkAdmins[0],	/* dummy sender */
                          masterAesKeyToken);
    }
    /* cleanup */
    FrameworkConfig_Delete(&frameworkConfig);	/* @1 */
    free(masterAesKeyTokenOut);			/* @5 */
    /* erase the secret keys before exit */
    memset(eku, 0, AES128_SIZE);
    memset(aku, 0, AKU_SIZE);
    fprintf(messageFile, "\nframeworkkey_generate rc %d\n\n", rc);
    return rc;
}

/* GetArgs() gets the command line arguments

   Returns ERROR_CODE on error.
*/

int GetArgs(int argc,
            char **argv)
{
    int		rc = 0;
    int 	i;

    /* command line argument defaults */
    verbose = FALSE;

    /* get the command line arguments */
    for (i=1 ; (i<argc) && (rc == 0) ; i++) {
        if (strcmp(argv[i],"-h") == 0) {
            PrintUsage();
            rc = ERROR_CODE;
        }
        else if (strcmp(argv[i],"-v") == 0) {
            verbose = TRUE;
        }
        else {
            printf("frameworkkey_generate: Error, %s is not a valid option\n", argv[i]);
            PrintUsage();
            rc = ERROR_CODE;
        }
    }
    return rc;
}

void PrintUsage()
{
    printf("\n");
    printf("frameworkkey_generate:\n"
           "\t[-v - verbose tracing]\n"
           "\t[-h - print usage help]\n");
    printf("\n");
    printf("\n");
    return;
}
