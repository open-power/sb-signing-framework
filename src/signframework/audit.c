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

/* This program implements the signer framework audit functions.  They permit a remote user
   to retrieve configuration and log files.  */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <dirent.h>

#include "utils.h"

/* local prototypes */

long GetArgs(const char **sender,
             const char **outputBodyFilename,
             const char **outputAttachmentFilename,
             const char **projectLogFileName,
             int *frameworkConfig,
             int *frameworkLog,
             int *projectConfig,
             int *projectAuxConfig,
             int *projectLog,
             int *useridConfig,
             const char **project,
             int *verbose,
             int argc,
             char **argv);

void PrintUsage(void);
int processFrameworkConfig(const char 	*outputAttachmentFilename,
			   const char 	*frameworkConfigFileName,
			   FILE		*projectLogFile);

int processFrameworkLog(const char 	*outputAttachmentFilename,
			const char 	*frameworkConfigFileName,
			FILE		*projectLogFile);

int processProjectConfig(const char 	*outputAttachmentFilename,
			 const char 	*project,
			 const char	*frameworkConfigFileName,
			 FILE		*projectLogFile);

int processProjectAuxConfig(const char 	*outputAttachmentFilename,
			    const char 	*project,
			    const char	*frameworkConfigFileName,
			    FILE	*projectLogFile);

int processProjectLog(const char 	*outputAttachmentFilename,
		      const char 	*project,
		      const char	*frameworkConfigFileName,
		      FILE		*projectLogFile);

int processUseridConfig(void);

int printDirectory(const char* directory);

/* This hard coded line size is safe because it is only used to parse configuration files, not
   arbitrary user input */

#define MAX_LINE_SIZE	1024

/* messages are traced here */
FILE *messageFile = NULL;
int verbose = FALSE;

int main(int argc, char** argv)
{
    int 	rc = 0;
    /* command line argument defaults */
    const char 	*outputBodyFilename = NULL;
    const char 	*outputAttachmentFilename = NULL;
    const char 	*sender = NULL;
    const char 	*projectLogFileName = NULL;
    FILE	*projectLogFile = NULL;
    time_t      log_time;
    int 	frameworkConfig = FALSE;
    int 	frameworkLog = FALSE;
    int 	projectConfig = FALSE;
    int 	projectAuxConfig = FALSE;
    int 	projectLog = FALSE;
    int     useridConfig = FALSE;
    const char 	*project = NULL;
    const char	*frameworkConfigFileName = NULL;

    messageFile = stdout;	/* default when running locally */

    /* get caller's command line arguments */
    if (rc == 0) {
        rc = GetArgs(&sender,
                     &outputBodyFilename,
                     &outputAttachmentFilename,
                     &projectLogFileName,
                     &frameworkConfig,
                     &frameworkLog,
                     &projectConfig,
                     &projectAuxConfig,
                     &projectLog,
                     &useridConfig,
                     &project,
                     &verbose,
                     argc, argv);
    }
    if (rc == 0) {
        if (verbose) fprintf(messageFile, "audit: Running audit program\n");
    }
    /* open the project audit logging */
    if (rc == 0) {
        if (verbose) fprintf(messageFile, "Opening audit log %s\n", projectLogFileName);
        projectLogFile = fopen(projectLogFileName, "a");
        if (projectLogFile == NULL) {
            fprintf(messageFile, "ERROR0000: Cannot open audit log %s, %s\n",
                    projectLogFileName, strerror(errno));
            rc = ERROR_CODE;
        }
    }
    /* update the project audit log, begin this entry */
    if (projectLogFile != NULL) {
        if (verbose) fprintf(messageFile, "Updating audit log\n");
        log_time = time(NULL);
        fprintf(projectLogFile, "\n%s", ctime(&log_time));
        fprintf(projectLogFile, "\tSender: %s\n", sender);
        fprintf(projectLogFile, "\tProject: %s\n", project);
        fprintf(projectLogFile, "\tProgram: %s\n", argv[0]);
    }
    /* get the file name of the framework configuration file from an environment variable */
    if (rc == 0) {
        frameworkConfigFileName = getenv("FRAMEWORK_CONFIG_FILE");
        if (frameworkConfigFileName == NULL) {
            fprintf(messageFile,
                    "audit: Error, FRAMEWORK_CONFIG_FILE environment variable not set\n");
            rc = ERROR_CODE;
        }
    }
    /* branch based on the input command flag that is set */
    if (rc == 0) {
        /* return the framework configuration file */
        if (frameworkConfig) {
            fprintf(projectLogFile, "\tOption: Framework configuration file\n");
            rc = processFrameworkConfig(outputAttachmentFilename,
                                        frameworkConfigFileName,
                                        projectLogFile);
        }
        /* return the framework log file */
        else if (frameworkLog) {
            fprintf(projectLogFile, "\tOption: Framework log file\n");
            rc = processFrameworkLog(outputAttachmentFilename,
                                     frameworkConfigFileName,
                                     projectLogFile);
        }
        /* return the project configuration file */
        else if (projectConfig) {
            fprintf(projectLogFile, "\tOption: Project configuration file: %s\n", project);
            rc = processProjectConfig(outputAttachmentFilename, project,
                                      frameworkConfigFileName,
                                      projectLogFile);
        }
        /* return the project auxiliary configuration file */
        else if (projectAuxConfig) {
            fprintf(projectLogFile, "\tOption: Project auxiliary configuration file: %s\n", project);
            rc = processProjectAuxConfig(outputAttachmentFilename, project,
                                         frameworkConfigFileName,
                                         projectLogFile);
        }
        /* return the project log file */
        else if (projectLog) {
            fprintf(projectLogFile, "\tOption: Project log file: %s\n", project);
            rc = processProjectLog(outputAttachmentFilename, project,
                                   frameworkConfigFileName,
                                   projectLogFile);
        }
        /* return the userid configuration */
        else if (useridConfig) {
            rc = processUseridConfig();
        }
        /* this should never occur */
        else {
            fprintf(projectLogFile, "\tError: Missing option\n");
            PrintUsage();
            rc = ERROR_CODE;
        }
    }
    fprintf(messageFile, "Return code: %u\n", rc);
    if (messageFile != stdout) {
        fflush(messageFile);
        fclose(messageFile);
    }
    messageFile = stdout;
    return rc;
}

/* return the framework configuration file */

int processFrameworkConfig(const char *outputAttachmentFilename,
                           const char *frameworkConfigFileName,
                           FILE *projectLogFile)
{
    int 	rc = 0;

    projectLogFile = projectLogFile;
    if (verbose) fprintf(messageFile, "audit: Returning framework config file: %s\n",
                         frameworkConfigFileName);
    if (rc == 0) {
        rc = File_Copy(outputAttachmentFilename, frameworkConfigFileName);
    }
    return rc;
}

/* return the framework log file */

int processFrameworkLog(const char *outputAttachmentFilename,
                        const char *frameworkConfigFileName,
                        FILE *projectLogFile)
{
    int 	rc = 0;
    FILE	*frameworkConfigFile = NULL;		/* freed @1 */
    char	*auditLogFilename = NULL;		/* freed @2 */
    char	lineBuffer[MAX_LINE_SIZE];

    /* open the framework configuration file */
    if (rc == 0) {
        frameworkConfigFile = fopen(frameworkConfigFileName, "r");	/* freed @2 */
        if (frameworkConfigFile == NULL) {
            File_Printf(projectLogFile, messageFile,
                        "Error, Cannot open %s\n", frameworkConfigFileName);
            rc = ERROR_CODE;
        }
    }
    /* get the file name for the framework audit log */
    if (rc == 0) {
        rc = File_MapNameToValue(&auditLogFilename,	/* freed @1 */
                                 "log",
                                 lineBuffer,
                                 MAX_LINE_SIZE,
                                 frameworkConfigFile);
        if (rc != 0) {
            File_Printf(projectLogFile, messageFile,
                        "Error, Cannot find framework audit log file name\n");
        }
    }
    if (rc == 0) {
        if (verbose) fprintf(messageFile, "audit: Returning framework audit log file: %s\n",
                             auditLogFilename);
        rc = File_Copy(outputAttachmentFilename, auditLogFilename);
    }
    /* close the framework configuration file */
    if (frameworkConfigFile != NULL) {
        fclose(frameworkConfigFile);	/* @1 */
    }
    free(auditLogFilename);		/* @2 */
    return rc;
}

/* return the project configuration file */

int processProjectConfig(const char 	*outputAttachmentFilename,
                         const char 	*project,
                         const char	*frameworkConfigFileName,
                         FILE		*projectLogFile)
{
    int 	rc = 0;
    FILE	*frameworkConfigFile = NULL;	/* freed @1 */
    char	*projectFilename = NULL;	/* freed @2 */
    char	lineBuffer[MAX_LINE_SIZE];

    if (verbose) fprintf(messageFile, "audit: Returning configuration file for project: %s\n",
                         project);
    /* open the framework configuration file */
    if (rc == 0) {
        frameworkConfigFile = fopen(frameworkConfigFileName, "r");	/* freed @1 */
        if (frameworkConfigFile == NULL) {
            File_Printf(projectLogFile, messageFile,
                        "Error, Cannot open %s\n", frameworkConfigFileName);
            rc = ERROR_CODE;
        }
    }
    /* get the file name for project configuration file */
    if (rc == 0) {
        rc = File_MapNameToValue(&projectFilename,	/* freed @2 */
                                 project,
                                 lineBuffer,
                                 MAX_LINE_SIZE,
                                 frameworkConfigFile);
        if (rc != 0) {
            File_Printf(projectLogFile, messageFile,
                        "Error, Cannot find project %s\n", project);
        }
    }
    if (rc == 0) {
        if (verbose) fprintf(messageFile, "audit: Project configuration file: %s\n",
                             projectFilename);
        rc = File_Copy(outputAttachmentFilename, projectFilename);
    }
    /* close the framework configuration file */
    if (frameworkConfigFile != NULL) {
        fclose(frameworkConfigFile);	/* @1 */
    }
    free(projectFilename);	/* @2 */
    return rc;
}

/* return the project auxiliary configuration file */

int processProjectAuxConfig(const char 	*outputAttachmentFilename,
                            const char 	*project,
                            const char	*frameworkConfigFileName,
                            FILE		*projectLogFile)
{
    int 	rc = 0;
    FILE	*frameworkConfigFile = NULL;		/* closed @1 */
    FILE 	*projectConfigFile = NULL;		/* closed @2 */
    char	*projectConfigFilename = NULL;		/* freed @3 */
    char	*projectAuxConfigFilename = NULL;	/* freed @4 */
    char	lineBuffer[MAX_LINE_SIZE];

    if (verbose) fprintf(messageFile,
                         "audit: Returning auxiliary configuration file for project: %s\n",
                         project);
    /* open the framework configuration file */
    if (rc == 0) {
        frameworkConfigFile = fopen(frameworkConfigFileName, "r");	/* closed @1 */
        if (frameworkConfigFile == NULL) {
            File_Printf(projectLogFile, messageFile,
                        "Error, Cannot open %s\n", frameworkConfigFileName);
            rc = ERROR_CODE;
        }
    }
    /* get the file name for project configuration file */
    if (rc == 0) {
        rc = File_MapNameToValue(&projectConfigFilename,	/* freed @3 */
                                 project,
                                 lineBuffer,
                                 MAX_LINE_SIZE,
                                 frameworkConfigFile);
        if (rc != 0) {
            File_Printf(projectLogFile, messageFile,
                        "Error, Cannot find project %s\n", project);
        }
    }
    /* open the project configuration file */
    if (rc == 0) {
        projectConfigFile = fopen(projectConfigFilename, "r");	/* closed @2 */
        if (projectConfigFile == NULL) {
            File_Printf(projectLogFile, messageFile,
                        "Error, Cannot open %s\n", projectConfigFilename);
            rc = ERROR_CODE;
        }
    }
    /* get the file name for the project auxiliary configuration file */
    if (rc == 0) {
        rc = File_MapNameToValue(&projectAuxConfigFilename,	/* freed @4 */
                                 "auxcfg",
                                 lineBuffer,
                                 MAX_LINE_SIZE,
                                 projectConfigFile);
        /* the project auxiliary configuration file is optional */
        if (rc == 0) {
            /* File_Copy() copies the source file to the destination */
            if (verbose) fprintf(messageFile, "audit: Project auxiliary configuration file: %s\n",
                                 projectAuxConfigFilename);
            rc = File_Copy(outputAttachmentFilename, projectAuxConfigFilename);
        }
        else {
            File_Printf(projectLogFile, messageFile,
                        "Error, Project does not include an auxiliary configuration file: %s\n",
                        project);
        }
    }
    /* close the framework configuration file */
    if (frameworkConfigFile != NULL) {
        fclose(frameworkConfigFile );	/* @1 */
    }
    /* close the project configuration file */
    if (projectConfigFile != NULL) {
        fclose(projectConfigFile);	/* @2 */
    }
    free(projectConfigFilename);	/* @3 */
    free(projectAuxConfigFilename);	/* @4 */
    return rc;
}

/* return the project log file */

int processProjectLog(const char 	*outputAttachmentFilename,
                      const char 	*project,
                      const char	*configFileName,
                      FILE		*projectLogFile)
{
    int 	rc = 0;
    FILE	*configFile = NULL;		/* freed @1 */
    char	*projectFilename = NULL;	/* freed @2 */
    FILE	*projectFile = NULL;		/* freed @3 */
    char	*auditLogFilename = NULL;	/* freed @4 */
    char	lineBuffer[MAX_LINE_SIZE];

    if (verbose) fprintf(messageFile, "audit: Returning audit log file for project: %s\n",
                         project);
    /* open the framework configuration file */
    if (rc == 0) {
        configFile = fopen(configFileName, "r");	/* freed @1 */
        if (configFile == NULL) {
            File_Printf(projectLogFile, messageFile,
                        "Error, Cannot open %s\n", configFileName);
            rc = ERROR_CODE;
        }
    }
    /* get the file name for project configuration file */
    if (rc == 0) {
        rc = File_MapNameToValue(&projectFilename,	/* freed @2 */
                                 project,
                                 lineBuffer,
                                 MAX_LINE_SIZE,
                                 configFile);
        if (rc != 0) {
            File_Printf(projectLogFile, messageFile,
                        "Error, Cannot find project %s\n", project);
        }
    }
    /* open the project configuration file */
    if (rc == 0) {
        projectFile = fopen(projectFilename, "r");	/* freed @3 */
        if (projectFile == NULL) {
            File_Printf(projectLogFile, messageFile,
                        "Error opening project configuration file: %s\n",
                        projectFilename);
            rc = ERROR_CODE;
        }
    }
    /* get the file name for the project audit log */
    if (rc == 0) {
        rc = File_MapNameToValue(&auditLogFilename,	/* freed @4 */
                                 "log",
                                 lineBuffer,
                                 MAX_LINE_SIZE,
                                 projectFile);
    }
    if (rc == 0) {
        if (verbose) fprintf(messageFile, "audit: Project audit log file: %s\n",
                             auditLogFilename);
        rc = File_Copy(outputAttachmentFilename, auditLogFilename);
    }
    /* close the framework configuration file */
    if (configFile != NULL) {
        fclose(configFile);	/* @1 */
    }
    free(projectFilename);	/* @2 */
    if (projectFile != NULL) {
        fclose(projectFile);	/* @3 */
    }
    free(auditLogFilename);	/* @4 */
    return rc;
}

int processUseridConfig(void)
{
    int 	rc = 0;

    fprintf(messageFile, "audit: Displaying home directories existing: \n");
    rc = printDirectory("/home/");

    if (rc == 0) {
        fprintf(messageFile, "\naudit: Displaying dropbox directories existing: \n");
        rc = printDirectory ("/home/dropbox/");
    }

    if (rc == 0) {
        fprintf(messageFile, "\naudit: Displaying ssh public keys installed: \n");
        rc = printDirectory ("/etc/ssh/authorized_keys");
    }

    return rc;
}

int printDirectory(const char* directory)
{
    int rc = 0;

    DIR *dir;
    struct dirent *dire;
    dir = opendir (directory);

    if (NULL != dir)
    {
        while (NULL != (dire = readdir(dir))) {
            if (strcmp(dire->d_name,".") &&
                strcmp(dire->d_name,"..")) {
                fprintf(messageFile,"\t%s\n",dire->d_name);
            }
        }
        closedir (dir);
    }
    else
    {
        fprintf (messageFile, "Couldn't open the directory : %s\n",directory);
        rc = 1;
    }
    return rc;
}

/* GetArgs() gets the command line arguments from the framework caller

 */

long GetArgs(const char **sender,
             const char **outputBodyFilename,
             const char **outputAttachmentFilename,
             const char **projectLogFileName,
             int *frameworkConfig,
             int *frameworkLog,
             int *projectConfig,
             int *projectAuxConfig,
             int *projectLog,
             int *useridConfig,
             const char **project,
             int *verbose,
             int argc,
             char **argv)
{
    long		rc = 0;
    int 		i;
    FILE		*tmpFile;
    unsigned int	paramCount;	/* only one of -fc, -pc, -paux, -fl, -pl must be
                                   specified */

    /* command line argument defaults */
    *sender = NULL;
    *outputBodyFilename = NULL;
    *outputAttachmentFilename = NULL;
    *project = NULL;
    *verbose = FALSE;
    /* command flags */
    *frameworkConfig = FALSE;
    *frameworkLog = FALSE;
    *projectConfig = FALSE;
    *projectAuxConfig = FALSE;
    *projectLog = FALSE;
    *useridConfig = FALSE;

    paramCount = 0;	/* count of received command flags */

    /* get the command line arguments */
    for (i = 1 ; (i < argc) && (rc == 0) ; i++) {
        if (strcmp(argv[i],"-obody") == 0) {
            i++;
            if (i < argc) {
                *outputBodyFilename = argv[i];
                /* since audit is partly for debugging, open the output body for append.  If verbose
                   tracing is on, both the framework and audit tracing will be returned. */
                rc = File_Open(&tmpFile, *outputBodyFilename, "a");
                /* switch messageFile from stdout ASAP */
                if (rc == 0) {
                    messageFile = tmpFile;
                }
            }
            else {
                fprintf(messageFile,
                        "audit: Error, -obody option (output email body) needs a value\n");
                rc = ERROR_CODE;
            }
        }
        else if (strcmp(argv[i],"-sender") == 0) {
            i++;
            if (i < argc) {
                *sender = argv[i];
            }
            else {
                fprintf(messageFile, "audit: Error, -sender option (sender) needs a value\n");
                rc = ERROR_CODE;
            }
        }
        else if (strcmp(argv[i],"-do") == 0) {
            i++;
            if (i < argc) {
                *outputAttachmentFilename = argv[i];
            }
            else {
                fprintf(messageFile,
                        "audit: Error, -do option (output attachment) needs a value\n");
                rc = ERROR_CODE;
            }
        }
        else if (strcmp(argv[i],"-fc") == 0) {
            *frameworkConfig = TRUE;
            paramCount++;
        }
        else if (strcmp(argv[i],"-pc") == 0) {
            i++;
            if (i < argc) {
                *projectConfig = TRUE;
                *project = argv[i];
                paramCount++;
            }
            else {
                fprintf(messageFile, "audit: Error, -pc option (project name) needs a value\n");
                rc = ERROR_CODE;
            }
        }
        else if (strcmp(argv[i],"-paux") == 0) {
            i++;
            if (i < argc) {
                *projectAuxConfig = TRUE;
                *project = argv[i];
                paramCount++;
            }
            else {
                fprintf(messageFile, "audit: Error, -paux option (project name) needs a value\n");
                rc = ERROR_CODE;
            }
        }
        else if (strcmp(argv[i],"-fl") == 0) {
            *frameworkLog = TRUE;
            paramCount++;
        }
        else if (strcmp(argv[i],"-pl") == 0) {
            i++;
            if (i < argc) {
                *projectLog = TRUE;
                *project = argv[i];
                paramCount++;
            }
            else {
                fprintf(messageFile, "audit: Error, -pl option (project name) needs a value\n");
                rc = ERROR_CODE;
            }
        }
        else if (strcmp(argv[i],"-userc") == 0) {
            *useridConfig = TRUE;
            paramCount++;
        }
        else if (strcmp(argv[i],"-project") == 0) {
            i++;
            if (i < argc) {
                /* project name, unused */
            }
            else {
                fprintf(messageFile,
                        "audit: Error, -project option (project name) needs a value\n");
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
                        "audit: Error, -log option (audit log name) needs a value\n");
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
    if (rc == 0) {
        if (*outputAttachmentFilename == NULL) {
            fprintf(messageFile, "audit: Error, -do option must be specified\n");
            rc = ERROR_CODE;
        }
    }
    if (rc == 0) {
        if (paramCount != 1) {
            fprintf(messageFile,
                    "audit: Error, only one of -fc, -fl, -pc, -pl, -paux must be specified\n");
            rc = ERROR_CODE;
        }
    }
    return rc;
}

void PrintUsage()
{
    fprintf(messageFile,
            "\n"
            "\taudit usage:\n"
            "\n"
            "Common arguments:\n"
            "\n"
            "\t-fc             - return framework configuration file\n"
            "\t-fl             - return framework audit log file\n"
            "\t-pc <project>   - return project configuration file\n"
            "\t-paux <project> - return project auxiliary configuration file\n"
            "\t-pl <project>   - return project audit log file\n"
            "\t-userc          - Display userid configuration\n"
            "\t[-v]            - verbose logging\n"
            "\t[-h]            - print usage help\n"
            "\n"
            "Request only arguments:\n"
            "\n"
            "\t-project    - project name\n"
            "\n"
            "Command line only arguments:\n"
            "\n"
            "\t-obody      - output email body file name (should be first argument)\n"
            "\t-sender     - email sender\n"
            "\t-do         - output attachment file name\n"
            "\t-log        - audit log file name\n"
            "\n"
            );
    return;
}
