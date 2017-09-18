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

/* This program iterates through all the project configuration files, getting the project
   administrator and all authorized users.  It sends a validation email the the administrator with
   the user list.

   The intent is to run this as a periodic cron job, authough it can be run at any time from the
   command line.
*/

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

#include "framework_utils.h"
#include "mail.h"
#include "utils.h"
#include "debug.h"

/* local prototypes */

int SenderValidate_Parse(char **outputBodyFilename,
                         char *configFilename);
int GetArgs(int argc,
            char **argv,
            char **configFilename);
void PrintUsage(void);

/* global variables */

FILE *messageFile = NULL;		/* needed for utilities */
int verbose = TRUE;
int debug = FALSE;

int main(int argc, char** argv)
{
    int 		rc = 0;
    size_t		i, j;
    char		*subject = NULL;		/* freed @2 */
    char 		*configFilename = NULL;
    FrameworkConfig 	frameworkConfig;
    char 		*outputBodyFilename = NULL;	/* freed @5 */
    FILE 		*outputBodyFile = NULL;		/* closed @4 */
    const char		projectSubject1[] = "Signing server ";
    const char		projectSubject2[] = " periodic validation for project: ";
    const char		*hostname = NULL;

    /* this is a stand alone program, so trace always goes to stdout */
    messageFile = stdout;

    FrameworkConfig_Init(&frameworkConfig);	/* freed @1 */
    /*
      get the command line arguments
    */
    if (rc == 0) {
        rc = GetArgs(argc, argv,
                     &configFilename);
    }
    if (rc == 0) {
        hostname = getenv("HOSTNAME");
        if (hostname == NULL) {
            fprintf(messageFile, "Error getting environment variable HOSTNAME\n");
            rc = ERROR_CODE;
        }
    }
    if (rc == 0) {
        if (verbose) fprintf(messageFile,
                             "\nsender_validate: hostname %s\n", hostname);
    }
    /*
      get parameters from the framework configuration file
    */
    if (rc == 0) {
        rc = FrameworkConfig_Parse(TRUE,	/* need master key */
                                   FALSE,	/* do not validate */
                                   &frameworkConfig);
    }
    /* get parameters from the audit archive configuration file */
    if (rc == 0) {
        rc = SenderValidate_Parse(&outputBodyFilename, 		/* freed @5 */
                                  configFilename);
    }
    /* for each project */
    for (i = 0 ; (rc == 0) && (i < frameworkConfig.projectLength) ; i++) {

        if (verbose) fprintf(messageFile,
                             "\nsender_validate: Loading project configuration file %s\n\n",
                             frameworkConfig.projectConfigFilenames[i]);
        /* get parameters from the project configuration file */
        if (rc == 0) {
            rc = ProjectConfig_Parse(frameworkConfig.projectConfigFiles[i],
                                     FALSE,		/* do not validate */
                                     frameworkConfig.projectConfigFilenames[i],
                                     &frameworkConfig);
        }

        /* only send the email if the project requires authorization */
        if (frameworkConfig.projectConfigFiles[i]->needSenders) {

            /* open the email response file */
            if (rc == 0) {
                outputBodyFile = fopen(outputBodyFilename, "w");
                if (outputBodyFile == NULL) {
                    fprintf(messageFile, "Error opening %s, %s\n",
                            outputBodyFilename, strerror(errno));
                    rc = ERROR_CODE;
                }
            }
            /* construct the email body */
            if (rc == 0) {
                fprintf(outputBodyFile,
                        "This is a validation message from the signing server.\n\n");
                fprintf(outputBodyFile,
                        "You are the project administrator for project: %s\n\n",
                        frameworkConfig.projectNames[i]);

                fprintf(outputBodyFile,
                        "Please validate that the following %d users should be authorized "
                        "for this project.\n",
                        (int)frameworkConfig.projectConfigFiles[i]->sendersCount);
                fprintf(outputBodyFile, "\n");
                for (j = 0 ; j < frameworkConfig.projectConfigFiles[i]->sendersCount ; j++) {
                    fprintf(outputBodyFile,
                            "\t%s\n",
                            frameworkConfig.projectConfigFiles[i]->senders[j]);
                }
                fprintf(outputBodyFile, "\n");

                fprintf(outputBodyFile,
                        "If a sender should not be authorized, contact a signing "
                        "server administrator at:\n");
                for (j = 0 ; j < frameworkConfig.frameworkAdminCount ; j++) {
                    fprintf(outputBodyFile,
                            "\t%s\n",
                            frameworkConfig.frameworkAdmins[j]);
                }
                fprintf(outputBodyFile, "\n");
            }
            /* close the email response file */
            if (outputBodyFile != NULL) {
                fclose(outputBodyFile);
                outputBodyFile = NULL;
            }
            /* construct the subject */
            if (rc == 0) {
                subject = realloc(subject,
                                  sizeof(projectSubject1) +
                                  strlen(hostname) +
                                  sizeof(projectSubject2) +
                                  strlen(frameworkConfig.projectNames[i]));
                strcpy(subject, projectSubject1);
                strcat(subject, hostname);
                strcat(subject, projectSubject2);
                strcat(subject, frameworkConfig.projectNames[i]);
            }
            /* send the email response */
            if (rc == 0) {
                /* send the message to the project administrator */
                rc = SendMailFile(&frameworkConfig,
                                  frameworkConfig.projectConfigFiles[i]->emailProject,
                                  subject, outputBodyFilename);
                if (rc != 0) {
                    fprintf(messageFile, "SendMail failed, status %u\n", rc);
                    rc = ERROR_CODE;
                }
            }
        }
    }
    /* cleanup */
    FrameworkConfig_Delete(&frameworkConfig);	/* @1 */
    free(subject);				/* @2 */
    free(outputBodyFilename);			/* @5 */
    return rc;
}

int SenderValidate_Parse(char **outputBodyFilename, 	/* freed by caller */
                         char *configFilename)
{
    int		rc = 0;
    FILE 	*configFile = NULL;
    char 	lineBuffer[4000];

    if (rc == 0) {
        rc = File_Open(&configFile, configFilename, "r");	/* closed @1 */
    }
    /* output body file name */
    if (rc == 0) {
        rc = File_MapNameToValue(outputBodyFilename, /* freed by caller */
                                 "out_body",
                                 lineBuffer,
                                 sizeof(lineBuffer),
                                 configFile);
    }
    if (rc == 0) {
        if (verbose) fprintf(messageFile,
                             "sender_validate: Output body file name: %s\n",
                             *outputBodyFilename);
    }
    if (configFile != NULL) {
        fclose(configFile);	/* @1 */
    }
    if (rc != 0) {
        fprintf(messageFile,
                "sender_validate: Error, rc %d\n", rc);
    }
    return rc;
}

/* GetArgs() gets the command line arguments

   Returns ERROR_CODE on error.
*/

int GetArgs(int argc,
            char **argv,
            char **configFilename)
{
    int		rc = 0;
    int 	i;

    /* command line argument defaults */

    verbose = FALSE;
    *configFilename = NULL;

    /* get the command line arguments */
    for (i=1 ; (i<argc) && (rc == 0) ; i++) {
        if (strcmp(argv[i],"-cfg") == 0) {
            i++;
            if (i < argc) {
                *configFilename = argv[i];
            }
            else {
                fprintf(messageFile,
                        "sender_validate: Error, -cfg option needs a value\n");
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
            fprintf(messageFile, "sender_validate: Error, %s is not a valid option\n", argv[i]);
            PrintUsage();
            rc = ERROR_CODE;
        }
    }
    /* check for missing connand line parameters */
    if (*configFilename == NULL) {
        fprintf(messageFile, "sender_validate: Error, missing -cfg option\n");
    }
    return rc;
}

void PrintUsage()
{
    fprintf(messageFile, "\n");
    fprintf(messageFile, "sender_validate:\n"
            "\t-cfg  - configuration file\n"
            "\t[-v   - verbose tracing]\n"
            "\t[-h   - print usage help]\n");
    fprintf(messageFile, "\n");
    fprintf(messageFile, "Sends a validation message for each project\n"
            "to confirm that a sender should be authorized for the project\n");
    fprintf(messageFile, "\n");
    return;
}
