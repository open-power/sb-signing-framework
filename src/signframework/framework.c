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

#include <unistd.h>
#include <sys/inotify.h>

#include "utils.h"
#include "debug.h"
#include "framework_utils.h"
#include "dropbox_utils.h"
#include "mail.h"

/* local prototypes */

int GetArgs(int 	argc,
            char 	**argv);
void PrintUsage(void);
int Main_Loop(void);

void Framework_GetControlFlags(int *stop,
                               int *restart,
                               FrameworkConfig *frameworkConfig);
void Framework_Init(FrameworkConfig *frameworkConfig);
int Framework_Load(FrameworkConfig *frameworkConfig,
                   int transientError);
void Framework_Delete(FrameworkConfig *frameworkConfig);

/* global variables */

/* At startup, messageFile points to stdout.  This allows the person starting the program to see
   startup errors.

   In the main loop, messageFile will point to the output body file.  It is opened for write on each
   new email request.  It is closed when the project specific program is called, so it can be opened
   for append by that program.  That program will then close it, so that the framework can reopen it
   for append to add any final text.
*/

FILE *messageFile = NULL;
int verbose = FALSE;
int debug = FALSE;

int main(int argc, char **argv)
{
    int			rc = 0;

    messageFile = stdout;

    printf("Starting initialization\n");
    /* get framework command line argument */
    if (rc == 0) {
        rc = GetArgs(argc, argv);
    }
    /* run the framework */
    if (rc == 0) {
        rc = Main_Loop();
    }
    return rc;
}

/* framework main loop */

int Main_Loop(void)
{
    int 		rc = 0;
    int 		stop = FALSE;
    int 		restart = FALSE;
    int			transientError = FALSE;	/* boolean */
    FrameworkConfig 	frameworkConfig;
    char            eventBuf[1024];
    char*           eventPtr = NULL;
    struct inotify_event* event = NULL;

    /* outer loop runs until stop or fatal error */
    while ((rc == 0) && !stop) {

        /* outer loop rereads the framework configuration files on each restart */
        Framework_Init(&frameworkConfig);

        /* read the configuration files, start the framework log */
        if (rc == 0) {
            rc = Framework_Load(&frameworkConfig, transientError);	/* freed @1 */
        }

        /* Setup the signer dropbox watchers */
        if (rc == 0) {
            rc = dropboxInit(&frameworkConfig);
        }

        if (rc == 0) {
            printf("\nStarting Main Loop\n");
            printf("Create file \'%s/%s\' to stop\n", 
                   frameworkConfig.dropboxDir, frameworkConfig.stopFile);
            printf("Create file \'%s/%s\' to restart\n\n",
                   frameworkConfig.dropboxDir, frameworkConfig.restartFile);
        }
        /* inner loop runs until restart or stop or fatal error */
        while ((rc == 0) && !stop && !restart) {


            /// Do a blocking read on the dropbox waiting for next event
            ssize_t numRead = read(frameworkConfig.inotifyFd, eventBuf, sizeof(eventBuf));
            if (numRead <= 0) {
                fprintf(messageFile, "read() from inotify fd returned <= 0 : %d", (int)numRead);
                //rc = 1;
                continue;
            }

            /* Process all of the events in buffer returned by read() */
            /* A single read can return multiple inotify events */
            for (eventPtr = eventBuf; eventPtr < eventBuf + numRead; ) {
                event = (struct inotify_event *) eventPtr;

                processEvent(&frameworkConfig, event, &stop, &restart);

                eventPtr += sizeof(struct inotify_event) + event->len;
            }


        }
        /* Log the error, stop or restart event to the framework log */
        File_LogTime(frameworkConfig.frameworkLogFile);
        if (stop) {
            File_Printf(frameworkConfig.frameworkLogFile, stdout, "Stopping\n");
        }
        else if (restart) {
            File_Printf(frameworkConfig.frameworkLogFile, stdout, "Restarting\n");
            restart = FALSE;
        }
        else {
            File_Printf(frameworkConfig.frameworkLogFile, stdout, "Stopping because of error\n");
        }
        /* cleanup */
        dropboxShutdown(&frameworkConfig);
        Framework_Delete(&frameworkConfig);	/* @1 */
    }
    return rc;
}

/* The framework is stopped by creating stopFile.  If the file exists here, set a flag so a loop
   exits.

   NOTE: Crtl-C will not terminate the program.  It just signals the sleep to return.
*/

void Framework_GetControlFlags(int *stop,
                               int *restart,
                               FrameworkConfig *frameworkConfig)
{
    int	rc;
    int verboseSave;

    /* Save and restore 'verbose' so the validate doesn't trace the expected failure. */
    verboseSave = verbose;
    verbose=FALSE;

    /* check for a stop file */
    rc = File_ValidateOpen(frameworkConfig->stopFile, "r");
    if (rc == 0) {
        remove(frameworkConfig->stopFile);
        *stop = 1;
    }
    /* check for a restart file */
    rc = File_ValidateOpen(frameworkConfig->restartFile, "r");
    if (rc == 0) {
        remove(frameworkConfig->restartFile);
        *restart = 1;
    }
    verbose = verboseSave;
    return;
}

/* Framework_Init() does basic program initialization before calling the main loop.

   NOTE: Since this is called at startup, messages should go to stdout.
*/

void Framework_Init(FrameworkConfig *frameworkConfig)
{
    FrameworkConfig_Init(frameworkConfig);
    return;
}

/* Framework_Load()

   - loads the FrameworkConfig structure members from the configuration file
   - opend the framework audit log
   - loads the ProjectConfig structure members from the configuration files
   - starts the audit log
   - emails the startup message

   transientError indicates the reason for the load:
   FALSE: a normal start or restart
   TRUE: a restart due to a transient error
*/

int Framework_Load(FrameworkConfig *frameworkConfig,
                   int transientError)
{
    int			rc = 0;
    size_t		i;

    /* read the signer framework configuration file and get basic parameters */
    if (rc == 0) {
        if (verbose) fprintf(messageFile,
                             "\nFramework_Load: Loading framework configuration file\n\n");
        rc = FrameworkConfig_Parse(TRUE, 	/* need master key */
                                   TRUE,	/* validate */
                                   frameworkConfig);
    }
    /* open framework audit log file for append */
    if (rc == 0) {
        frameworkConfig->frameworkLogFile = fopen(frameworkConfig->frameworkLogFilename, "a");
        if (frameworkConfig->frameworkLogFile == NULL) {
            fprintf(messageFile,
                    "ERROR0003: Opening: %s\n", frameworkConfig->frameworkLogFilename);
            frameworkConfig->frameworkLogFile = stdout;
            rc = ERROR_CODE;
        }
        else {
            /* no buffering, so log can be monitored while the framework is running */
            setvbuf(frameworkConfig->frameworkLogFile, 0, _IONBF, 0);
        }
    }
    /* Walk the project configuration files and validate them.  Cache the results in the
       frameworkConfig structure */
    /* for each project */
    for (i = 0 ; (rc == 0) && (i < frameworkConfig->projectLength) ; i++) {

        if (verbose) fprintf(messageFile,
                             "\nFramework_Load: Loading project configuration file %s\n\n",
                             frameworkConfig->projectConfigFilenames[i]);
        if (rc == 0) {
            rc = ProjectConfig_Parse(frameworkConfig->projectConfigFiles[i],
                                     TRUE,	/* validate */
                                     frameworkConfig->projectConfigFilenames[i],
                                     frameworkConfig);
        }
    }
    /* log the framework startup event */
    if (rc == 0) {
        FrameworkConfig_LogStart(frameworkConfig);
    }
    if (rc == 0) {
        rc = FrameworkConfig_SendStartupMessage(frameworkConfig, transientError);
    }
    return rc;
}

/* Framework_Delete() closes the framework audit log and frees the structure members */

void Framework_Delete(FrameworkConfig *frameworkConfig)
{
    /* close the framework audit log */
    if (frameworkConfig->frameworkLogFile != stdout) {
        fclose(frameworkConfig->frameworkLogFile);
    }
    FrameworkConfig_Delete(frameworkConfig);
    return;
}

/* GetArgs() gets the main program command line arguments */

int GetArgs(int 	argc,
            char 	**argv)
{
    int rc = 0;
    int i;

    /* command line argument defaults */
    verbose = FALSE;

    /* get the command line arguments */
    for (i=1 ; (i<argc) && (rc == 0) ; i++) {
        if (strcmp(argv[i],"-v") == 0) {
            verbose = TRUE;
        }
        else if (strcmp(argv[i],"-h") == 0) {
            PrintUsage();
            rc = ERROR_CODE;
        }
        else {
            printf("\nframework: Error, %s is not a valid option\n",argv[i]);
            PrintUsage();
            rc = ERROR_CODE;
        }
    }
    return rc;
}

void PrintUsage()
{
    printf("\n");
    printf("\tframework:\n"
           "\t[-v - verbose tracing]\n"
           "\t[-h - print usage help]\n");
    printf("\n");
    return;
}
