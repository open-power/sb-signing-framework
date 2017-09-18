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

#include "debug.h"
#include "utils.h"

#include "eccutils.h"

extern FILE* messageFile;
extern int verbose;

#define CFG_FILES_MAX 100	/* a sufficiently large number of project configuration files */

/* GetAuxArgs() parses an ECC auxiliary configuration file of the form:

   sign_algorithm=
   digest_algorithm=
   check_unique=
   raw_header_input=
   cfg_files=
   project=
   ...
*/

int GetAuxArgs(char **signAlgorithm,			/* freed by caller */
               char **digestAlgorithm,			/* freed by caller */
               int *checkUnique,
               int *rawHeaderInput,
               unsigned int *numberOfProjectFiles,
               char ***projectConfigFilenames,		/* array freed by caller */
               const char *projectAuxConfigFileName)
{
    int		rc = 0;		/* general return code */
    size_t	i;
    char	*lineBuffer = NULL;		/* freed @2 */
    size_t	lineBufferLength = 4000;	/* hard code for the project */
    FILE 	*projectAuxConfigFile = NULL;	/* closed @1 */


    /* open project auxiliary configuration file */
    if (rc == 0) {
        if (verbose) fprintf(messageFile,
                             "Opening auxiliary configuration file %s\n",
                             projectAuxConfigFileName);
        projectAuxConfigFile = fopen(projectAuxConfigFileName, "r");	/* closed @1 */
        if (projectAuxConfigFile == NULL) {
            fprintf(messageFile,
                    "ERROR2001: Cannot open auxiliary configuration file %s, %s\n",
                    projectAuxConfigFileName, strerror(errno));
            rc = ERROR_CODE;
        }
    }
    /* allocate a line buffer, used when parsing the configuration file */
    if (rc == 0) {
        rc = Malloc_Safe((unsigned char **)&lineBuffer,	/* freed @2 */
                         lineBufferLength,
                         lineBufferLength);		/* hard code for the project */
    }
    /* signing algorithm */
    if (rc == 0) {
        rc = File_MapNameToValue(signAlgorithm,		/* freed by caller */
                                 "sign_algorithm",
                                 lineBuffer,
                                 lineBufferLength,
                                 projectAuxConfigFile);
        if (rc != 0) {
            fprintf(messageFile,
                    "ERROR2002: Signing algorithm is not specified in "
                    "auxiliary configuration file\n");
        }
    }
    if (rc == 0) {
        if (verbose) fprintf(messageFile,
                             "Signing algorithm %s\n",
                             *signAlgorithm);
    }
    /* digest algorithm */
    if (rc == 0) {
        rc = File_MapNameToValue(digestAlgorithm,	/* freed by caller */
                                 "digest_algorithm",
                                 lineBuffer,
                                 lineBufferLength,
                                 projectAuxConfigFile);
        if (rc != 0) {
            fprintf(messageFile,
                    "ERROR2004: Digest algorithm is not "
                    "specified in auxiliary configuration file\n");
        }
    }
    if (rc == 0) {
        if (verbose) fprintf(messageFile,
                             "Digest algorithm %s\n",
                             *digestAlgorithm);
    }
    /* checkUnique boolean */
    if (rc == 0) {
        rc = File_MapNameToBool(checkUnique,
                                "check_unique",
                                lineBuffer,
                                lineBufferLength,
                                projectAuxConfigFile);
        if (rc != 0) {
            fprintf(messageFile,
                    "ERROR2005: Check_unique has an illegal value\n");
        }
    }
    if (rc == 0) {
        if (verbose) fprintf(messageFile, "ProjectConfig_Parse: Check unique: %d\n",
                             *checkUnique);
    }
    /* rawHeaderInput boolean */
    if (rc == 0) {
        rc = File_MapNameToBool(rawHeaderInput,
                                "raw_header_input",
                                lineBuffer,
                                lineBufferLength,
                                projectAuxConfigFile);
        if (rc != 0) {
            fprintf(messageFile,
                    "ERROR2005a: raw_header_input has an illegal value\n");
        }
    }
    if (rc == 0) {
        if (verbose) fprintf(messageFile, "ProjectConfig_Parse: Raw Header Input: %d\n",
                             *rawHeaderInput);
    }
    /* get the number of project configuration files */
    if (rc == 0) {
        rc = File_MapNameToUint(numberOfProjectFiles,
                                "cfg_files",
                                lineBuffer,
                                lineBufferLength,
                                projectAuxConfigFile);
        if (rc != 0) {
            fprintf(messageFile,
                    "ERROR2006: Number of project configuration files "
                    "is not specified in auxiliary configuration file\n");
        }
    }
    if (rc == 0) {
        if (verbose) fprintf(messageFile,
                             "Number of project configuration files: %u\n",
                             *numberOfProjectFiles);
    }
    if (rc == 0) {
        if (*numberOfProjectFiles > CFG_FILES_MAX) {
            fprintf(messageFile,
                    "ERROR2007: Number of project configuration files %u is > %u\n",
                    *numberOfProjectFiles, CFG_FILES_MAX);
            rc = ERROR_CODE;
        }
        if (*numberOfProjectFiles == 0) {
            fprintf(messageFile,
                    "ERROR2008: Number of project configuration files is zero\n");
            rc = ERROR_CODE;
        }
    }
    /* allocate the array of project file names */
    if (rc == 0) {
        rc = Malloc_Safe((unsigned char **)projectConfigFilenames,
                         sizeof(char *) * (*numberOfProjectFiles),	/* freed by caller */
                         CFG_FILES_MAX * sizeof(char *));	/* hard code for the project */
    }
    /* immediately NULL so that free is safe */
    for (i = 0 ; (rc == 0) && (i < *numberOfProjectFiles) ; i++) {
        (*projectConfigFilenames)[i] = NULL;
    }
    /* get the project file names */
    for (i = 0 ; (rc == 0) && (i < *numberOfProjectFiles) ; i++) {
        if (rc == 0) {
            rc = File_MapNameToValue(&((*projectConfigFilenames)[i]), /* freed by caller */
                                     "project",
                                     lineBuffer,
                                     lineBufferLength,
                                     projectAuxConfigFile);
            if (rc != 0) {
                fprintf(messageFile,
                        "ERROR2009: Insufficient number of project configuration files\n");
            }
        }
        if (rc == 0) {
            if (verbose) fprintf(messageFile,
                                 "Project config file name %d: %s\n",
                                 (int)i+1, (*projectConfigFilenames)[i]);
        }
    }
    if (projectAuxConfigFile != NULL) {
        fclose(projectAuxConfigFile);	/* @1 */
    }
    free(lineBuffer);			/* @2 */
    return rc;
}

/* GetSendersArray() gets an array of senders per project.  It allocates the ***senders array of
   projects.

   Pointers:

   senders - pointer to array of projects

   (*senders) - array of project arrays, allocated here

   (*senders)[i] - project array, allocated by each File_GetValueArray()

   (*senders)[i][j] - project array entry, pointer to sender string, allocated within
   File_GetValueArray()

*/

int GetSendersArray(char 	****senders,		/* array of senders per project,
                                                   freed by caller */
                    unsigned int **numberOfSenders,	/* array of number of senders per
                                                       project, freed by caller */
                    unsigned int numberOfProjectFiles,
                    char 	**projectConfigFilenames) /* array of file names, freed @4 */
{
    int			rc = 0;					/* general return code */
    FILE 		*projectConfigFile = NULL;		/* closed @1 */

    size_t	i;	/* iterate through project configuration files */
    size_t 	j;	/* interate through senders in a file */
    char	*lineBuffer = NULL;		/* freed @1 */
    size_t	lineBufferLength = 4000;	/* hard code for the project */

    /* allocate arrays for the number of senders and senders list in each */
    /* allocate a line buffer, used when parsing the configuration file */
    if (rc == 0) {
        rc = Malloc_Safe((unsigned char **)&lineBuffer,	/* freed @1 */
                         lineBufferLength,
                         lineBufferLength);		/* hard code for the project */
    }
    if (rc == 0) {
        rc = Malloc_Safe((unsigned char **)numberOfSenders,	/* freed by caller */
                         numberOfProjectFiles * sizeof(size_t),
                         MAX_PROJECT_FILES * sizeof(size_t));	/* hard code for the project */

    }
    if (rc == 0) {
        rc = Malloc_Safe((unsigned char **)senders,		/* freed by caller */
                         numberOfProjectFiles * sizeof(char *),
                         MAX_PROJECT_FILES * sizeof(char *));	/* hard code for the project */

    }
    /* immediately NULL the array so it can be freed */
    for (i = 0 ; (rc == 0) && (i < numberOfProjectFiles) ; i++) {
        (*senders)[i] = NULL;
    }
    /* iterate through the project configuration files, building arrays of authorized senders */
    for (i = 0 ; (rc == 0) && (i < numberOfProjectFiles) ; i++) {
        /* open project configuration file */
        if (rc == 0) {
            if (verbose) fprintf(messageFile,
                                 "GetSendersArray: Processing project configuration file %s\n",
                                 projectConfigFilenames[i]);
            projectConfigFile = fopen(projectConfigFilenames[i], "r");		/* closed @1 */
            if (projectConfigFile == NULL) {
                fprintf(messageFile,
                        "ERROR2010: Could not open project configuration file: %s\n",
                        projectConfigFilenames[i]);
                rc = ERROR_CODE;
            }
        }
        /* determine whether senders are needed */
        int needSenders = 0;
        if (rc == 0) {
            rc = File_MapNameToBool(&needSenders,
                                    "needsenders",
                                    lineBuffer,
                                    lineBufferLength,
                                    projectConfigFile);
        }
        if (rc == 0) {
            if (verbose) fprintf(messageFile,
                                 "Signing project needs senders: %d\n", needSenders);
        }
        /* read the list of authorized senders */
        if (rc == 0) {
            char ** emails = NULL;
            rc = File_GetNameValueArray(&((*senders)[i]),	/* freed by caller */
                                        &emails,	/* freed below */
                                        (size_t*)&((*numberOfSenders)[i]), /* number of authorized senders */
                                        lineBuffer,
                                        lineBufferLength,
                                        projectConfigFile);
            // We don't use the emails so delete right away
            for (j = 0; j < (*numberOfSenders)[i]; j ++) {
                free(emails[j]);
            }
            free(emails);
            emails = NULL;
        }
        if (rc == 0) {
            rc = File_GetValueArray(&((*senders)[i]),
                                    (size_t*)&((*numberOfSenders)[i]),
                                    "senders",
                                    lineBuffer,
                                    lineBufferLength,
                                    projectConfigFile);
        }
        if (rc == 0) {
            if (verbose) fprintf(messageFile,
                                 "GetSendersArray: Found %u authorized senders\n",
                                 (*numberOfSenders)[i]);
            for (j = 0 ; j < (*numberOfSenders)[i] ; j++) {
                if (verbose) fprintf(messageFile,
                                     "GetSendersArray: Sender %d: %s\n",
                                     (int)j+1, (*senders)[i][j]);
            }
        }
        if (projectConfigFile != NULL) {
            fclose(projectConfigFile);			/* @7 */
            projectConfigFile = NULL;
        }
    }
    free(lineBuffer);		/* @1 */
    return rc;
}

/* CheckSenders() verifies that all senders in the arrays are unique. */

int CheckSenders(unsigned int 	numberOfProjectFiles,
                 char 		**projectConfigFilenames,
                 unsigned int *numberOfSenders,
                 char 		***senders)			/* array of senders per project */
{
    int 	rc = 0;
    size_t	i;	/* iterate through project configuration files */
    size_t 	j;	/* interate through senders in a file */
    size_t 	k;	/* interate through senders in a file */
    size_t 	l;	/* interate through senders in a file */
    char 	*senderToCheck;

    /* iterate through all files */
    for (i = 0 ; (rc == 0) && (i < numberOfProjectFiles) ; i++) {
        /* iterate through all senders in the file */
        for (j = 0 ; (rc == 0) && (j < numberOfSenders[i]) ; j++) {
            senderToCheck = senders[i][j];

            if (verbose) fprintf(messageFile,
                                 "CheckSenders: Check sender %d %d\n",
                                 (int)i, (int)j);


            /* first check that the sender is not duplicated in this file */
            for (k = j+1 ; (rc == 0) && (k < numberOfSenders[i]) ; k++) {
                if (verbose) fprintf(messageFile,
                                     "CheckSenders: Check against %d %d\n",
                                     (int)i, (int)k);
                if (strcmp(senderToCheck, senders[i][k]) == 0) {
                    fprintf(messageFile,
                            "ERROR2003: Duplicate sender %s in file %s\n",
                            senderToCheck, projectConfigFilenames[i]);
                    rc = ERROR_CODE;
                }
            }
            /* then check that it's not duplicated in any other file */
            for (k = i+1 ; (rc == 0) && (k < numberOfProjectFiles) ; k++) {
                for (l = 0 ; (rc == 0) && (l < numberOfSenders[k]) ; l++) {
                    if (verbose) fprintf(messageFile,
                                         "CheckSenders: Check against %d %d\n",
                                         (int)k, (int)l);
                    if (strcmp(senderToCheck, senders[k][l]) == 0) {
                        fprintf(messageFile,
                                "ERROR2004: Duplicate sender %s in files %s and %s\n",
                                senderToCheck,
                                projectConfigFilenames[i],
                                projectConfigFilenames[k]);
                        rc = ERROR_CODE;
                    }
                }
            }
        }
    }
    return rc;
}
