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

/* This program sends the framework audit log to the framework administrators.

   It iterates through all the project configuration files, sending the audit log to the project
   administrator.

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

int AuditArchive_Parse(char **outputBodyFilename,
                       char **outputAttachmentFilename,
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
    size_t		i;
    char		*subject = NULL;			/* freed @1 */
    char 		*configFilename = NULL;
    FrameworkConfig 	frameworkConfig;			/* freed @2 */
    char 		*outputBodyFilename = NULL;		/* freed @5 */
    FILE 		*outputBodyFile = NULL;			/* closed @4 */
    char 		*outputAttachmentFilename = NULL;	/* freed @6 */
    const char		projectSubject1[] = "Signing server ";
    const char		projectSubject2[] = " framework audit log";
    const char		projectSubject3[] = " audit log for project: ";
    const char		*hostname = NULL;

    /* this is a stand alone program, so trace always goes to stdout */
    messageFile = stdout;

    FrameworkConfig_Init(&frameworkConfig);	/* freed @2 */
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
                             "\naudit_archive: hostname %s\n", hostname);
    }
    /*
      get parameters from the framework configuration file
    */
    if (rc == 0) {
        rc = FrameworkConfig_Parse(TRUE,	/* need master key */
                                   FALSE,	/* do not validate */
                                   &frameworkConfig);	/* freed @2 */
    }
    /* get parameters from the audit archive configuration file */
    if (rc == 0) {
        rc = AuditArchive_Parse(&outputBodyFilename, 		/* freed @5 */
                                &outputAttachmentFilename,	/* freed @6 */
                                configFilename);
    }
    /*
      for each framework administrator
    */
    for (i = 0 ; (rc == 0) && (i < frameworkConfig.frameworkAdminCount) ; i++) {
        if (verbose) fprintf(messageFile,
                             "\naudit_archive: Sending framework audit log %s to %s\n\n",
                             frameworkConfig.frameworkLogFilename,
                             frameworkConfig.frameworkAdmins[i]);
        /* open the email body file */
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
                    "This is a validation message from the signing server.\n\n"
                    "You are the framework administrator\n\n"
                    "Attached is a copy of the audit log for your archives.\n\n"
                    );
        }
        /* close the email response body file */
        if (outputBodyFile != NULL) {
            fclose(outputBodyFile);	/* @4 */
            outputBodyFile = NULL;
        }
        /* construct the attachment.  Copy because Notes needs a full path name. */
        if (rc == 0) {
            rc = File_Copy(outputAttachmentFilename,
                           frameworkConfig.frameworkLogFilename);
        }
        /* construct the subject */
        if (rc == 0) {
            subject = realloc(subject,
                              sizeof(projectSubject1) +
                              strlen(hostname) +
                              sizeof(projectSubject2));
            strcpy(subject, projectSubject1);
            strcat(subject, hostname);
            strcat(subject, projectSubject2);
        }
        /* send the email response */
        if (rc == 0) {
            /* send the message to the framework administrator */
            rc = SendMailFileWithAttachment(&frameworkConfig,
                                            frameworkConfig.frameworkAdmins[i],
                                            subject,
                                            outputBodyFilename,
                                            outputAttachmentFilename);
            if (rc != 0) {
                fprintf(messageFile, "SendMail failed, status %u\n", rc);
                rc = ERROR_CODE;
            }
        }
    }
    /* for each project */
    for (i = 0 ; (rc == 0) && (i < frameworkConfig.projectLength) ; i++) {

        if (verbose) fprintf(messageFile,
                             "\naudit_archive: Loading project configuration file %s\n\n",
                             frameworkConfig.projectConfigFilenames[i]);
        /* get parameters from the project configuration file */
        if (rc == 0) {
            rc = ProjectConfig_Parse(frameworkConfig.projectConfigFiles[i],
                                     FALSE,	/* do not validate */
                                     frameworkConfig.projectConfigFilenames[i],
                                     &frameworkConfig);
        }
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
                    "This is a validation message from the signing server.\n\n"
                    "You are the project administrator for project: %s\n\n"
                    "Attached is a copy of the audit log for your archives.\n\n",
                    frameworkConfig.projectNames[i]
                    );
        }
        /* close the email response file */
        if (outputBodyFile != NULL) {
            fclose(outputBodyFile);
            outputBodyFile = NULL;
        }
        /* construct the attachment.  Copy because Notes needs a full path name. */
        if (rc == 0) {
            rc = File_Copy(outputAttachmentFilename,
                           frameworkConfig.projectConfigFiles[i]->projectLogFilename);
        }
        /* construct the subject */
        if (rc == 0) {
            subject = realloc(subject,
                              sizeof(projectSubject1) +
                              strlen(hostname) +
                              sizeof(projectSubject3) +
                              strlen(frameworkConfig.projectNames[i]));
            strcpy(subject, projectSubject1);
            strcat(subject, hostname);
            strcat(subject, projectSubject3);
            strcat(subject, frameworkConfig.projectNames[i]);
        }
        /* send the email response */
        if (rc == 0) {
            /* send the message to the project administrator */
            rc = SendMailFileWithAttachment(&frameworkConfig,
                                            frameworkConfig.projectConfigFiles[i]->emailProject,
                                            subject,
                                            outputBodyFilename,
                                            outputAttachmentFilename);
            if (rc != 0) {
                fprintf(messageFile, "SendMail failed, status %u\n", rc);
                rc = ERROR_CODE;
            }
        }
    }
    /* cleanup */
    free(subject);				/* @1 */
    FrameworkConfig_Delete(&frameworkConfig);	/* @2 */
    free(outputBodyFilename);			/* @5 */
    free(outputAttachmentFilename);		/* @6 */
    return rc;
}

int AuditArchive_Parse(char **outputBodyFilename, 	/* freed by caller */
                       char **outputAttachmentFilename,	/* freed by caller */
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
                             "audit_archive: Output body file name: %s\n",
                             *outputBodyFilename);
    }
    /* output attachment file name */
    if (rc == 0) {
        rc = File_MapNameToValue(outputAttachmentFilename, /* freed by caller */
                                 "out_attachment",
                                 lineBuffer,
                                 sizeof(lineBuffer),
                                 configFile);
    }
    if (rc == 0) {
        if (verbose) fprintf(messageFile,
                             "audit_archive: Output body file name: %s\n",
                             *outputBodyFilename);
    }
    if (configFile != NULL) {
        fclose(configFile);	/* @1 */
    }
    if (rc != 0) {
        fprintf(messageFile,
                "audit_archive: Error, rc %d\n", rc);
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
                        "audit_archive: Error, -cfg option needs a value\n");
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
            fprintf(messageFile, "audit_archive: Error, %s is not a valid option\n", argv[i]);
            PrintUsage();
            rc = ERROR_CODE;
        }
    }
    /* check for missing connand line parameters */
    if (*configFilename == NULL) {
        fprintf(messageFile, "audit_archive: Error, missing -cfg option\n");
    }
    return rc;
}

void PrintUsage()
{
    fprintf(messageFile, "\n");
    fprintf(messageFile, "audit_archive:\n"
            "\t-cfg  - configuration file\n"
            "\t[-v   - verbose tracing]\n"
            "\t[-h   - print usage help]\n");
    fprintf(messageFile, "\n");
    fprintf(messageFile, "Sends the audit log to the administrators\n");
    fprintf(messageFile, "\n");
    return;
}
