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
#include <ctype.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "utils.h"
#include "framework_utils.h"
#include "cca_functions.h"
#include "cca_structures.h"
#ifdef ADD_ECC
#include "cca_structures_ecc.h"
#include "cca_functions_ecc.h"
#endif
#include "ossl_functions.h"
#include "debug.h"
#include "mail.h"
#include "errorcodes.h"
#include "dropbox_utils.h"
#ifdef LDAP_VERIFY
#include "ldap_lookup.h"
#endif

extern FILE* messageFile;
extern int verbose;

/* This table describes command line arguments added to the Arguments array by the framework.  They
   cannot be in the input body, as an attacker could then try to override the framework values.

   Use this table to screen the user input.  Do not rely on the called program to detect duplicates.
*/

static const char *claTable[] = {
    "-di",
    "-do",
    "-key",
    "-log",
    "-auxcfg",
    "-obody",
    "-sender",
    "-pwd"
};

/* This hard coded line size is used for the first few lines of the framework configuration file.
   Once the actual maximum line size is read from the configuration file, a buffer is allocated for
   the rest of the file. */

#define MAX_LINE_SIZE	1024

/* local function prototypes */

int FrameworkConfig_Validate(FrameworkConfig *frameworkConfig);
int ProjectConfig_Validate(ProjectConfig *projectConfig,
                           FrameworkConfig *frameworkConfig);
int ProjectConfig_ValidateKey(ProjectConfig *projectConfig);
int ProjectConfig_ValidateKeyRSA(size_t	keyTokenLength,
                                 unsigned char *keyToken);
int ProjectConfig_ValidateKeyECC(size_t keyTokenLength,
                                 unsigned char *keyToken);


/* FrameworkConfig_Init() initializes the FrameworkConfig object members
 */

void FrameworkConfig_Init(FrameworkConfig *frameworkConfig)
{
    memset(frameworkConfig, 0, sizeof(FrameworkConfig));

    /* frameworkLogFile starts as stdout.  Once the framework starts, it is switched to the actual
       framework audit log.
    */
    frameworkConfig->frameworkLogFile = stdout;
    return;
}

/* FrameworkConfig_Delete() frees and reinitializes the FrameworkConfig object members
 */

void FrameworkConfig_Delete(FrameworkConfig *frameworkConfig)
{
    size_t i;

    /* do not free frameworkConfigFilename, it comes from getenv */
    free(frameworkConfig->frameworkName);
    free(frameworkConfig->frameworkLogFilename);
    free(frameworkConfig->dropboxDir);
    free(frameworkConfig->stopFile);
    free(frameworkConfig->restartFile);
    free(frameworkConfig->outputBodyFilename);
    free(frameworkConfig->notificationFilename);
    free(frameworkConfig->emailFilename);
    free(frameworkConfig->inputAttachmentFilename);
    free(frameworkConfig->outputAttachmentFilename);
    free(frameworkConfig->masterAesKeyTokenFilename);
    free(frameworkConfig->masterAesKeyToken);
    free(frameworkConfig->ldapUrl);
    free(frameworkConfig->ldapBase);
    for (i = 0 ; i < frameworkConfig->frameworkAdminCount ; i++) {
        free(frameworkConfig->frameworkAdmins[i]);
    }
    free(frameworkConfig->frameworkAdmins);
    /* free and reinitialize each ProjectConfig object member, then free the members in the
       FrameworkConfig object project arrays */
    for (i = 0 ; i < frameworkConfig->projectLength ; i++) {
        free(frameworkConfig->projectNames[i]);
        free(frameworkConfig->projectConfigFilenames[i]);
        if (frameworkConfig->projectConfigFiles != NULL) {
            ProjectConfig_Delete(frameworkConfig->projectConfigFiles[i]);
            free(frameworkConfig->projectConfigFiles[i]);
            frameworkConfig->projectConfigFiles[i] = NULL;
        }
    }
    /* then free the project arrays themselves */
    free(frameworkConfig->projectNames);
    free(frameworkConfig->projectConfigFilenames);
    free(frameworkConfig->projectConfigFiles);
    /* initialize so the next delete is safe */
    FrameworkConfig_Init(frameworkConfig);
    return;
}

/* FrameworkConfig_Parse() parses the framework configuration file into the FrameworkConfig object.

   NOTE: Since this is called at startup, messages should go to stdout.  All calls that set an error
   code must print as well.

   needMasterKey flags whether the framework AES master key must exist.  It's usually true, but is
   false when the calling program is generating that key.

   validate flags whether the validation, which writes files, should be done.  The main framework
   should perform validation.  Ancillary programs should not, so as not to interfere with a running
   framework.

*/

int FrameworkConfig_Parse(int needMasterKey,
                          int validate,
                          FrameworkConfig *frameworkConfig)
{
    int		rc = 0;
    size_t	i;
    FILE 	*configFile = NULL;			/* closed @2 */
    /* temporary, to hold lines when parsing the configuration file */
    char	firstLineBuffer[MAX_LINE_SIZE];
    char	*lineBuffer = NULL;			/* freed @3 */
    size_t 	masterAesKeyTokenLength;

    /* validate that all required environment variables are set */
    if (rc == 0) {
        rc = Env_Validate();
    }
    /* framework configuration file name from environment variable */
    if (rc == 0) {
        frameworkConfig->frameworkConfigFilename = getenv("FRAMEWORK_CONFIG_FILE");
        if (frameworkConfig->frameworkConfigFilename == NULL) {
            fprintf(messageFile,
                    "ERROR0001: "
                    "FRAMEWORK_CONFIG_FILE environment variable is not set\n");
            rc = ERROR_CODE;
        }
    }
    if (rc == 0) {
        if (verbose) fprintf(messageFile,
                             "FrameworkConfig_Parse: Framework configuration file name: %s\n",
                             frameworkConfig->frameworkConfigFilename);
        if (verbose) fprintf(messageFile,
                             "FrameworkConfig_Parse: Max args %u, max args length %u\n",
                             MAX_ARGV_BODY, ARG_MAX);
    }
    /* save a hash of the framework configuration file for the framework audit log */
    if (rc == 0) {
        rc = Ossl_HashBinaryFile(frameworkConfig->digest,
                                 MAX_CONFIG,
                                 frameworkConfig->frameworkConfigFilename);
    }
    if (rc == 0) {
        if (verbose) PrintAll(messageFile,
                              "FrameworkConfig_Parse: Framework configuration file digest",
                              DIGEST_SIZE,
                              frameworkConfig->digest);
    }
    /* open framework configuration file */
    if (rc == 0) {
        configFile = fopen(frameworkConfig->frameworkConfigFilename , "r");	/* closed @2 */
        if (configFile == NULL) {
            fprintf(messageFile,
                    "ERROR0002: Opening %s\n",
                    frameworkConfig->frameworkConfigFilename);
            rc = ERROR_CODE;
        }
    }

    /* line_max */
    if (rc == 0) {
        frameworkConfig->lineMax = 0;
        rc = File_MapNameToUint((unsigned int *)&(frameworkConfig->lineMax),
                                "line_max",
                                firstLineBuffer,
                                MAX_LINE_SIZE,
                                configFile);
    }
    if (rc == 0) {
        if (verbose) fprintf(messageFile,
                             "FrameworkConfig_Parse: Line maximum length: %u bytes\n",
                             (unsigned int)frameworkConfig->lineMax);
    }
    if (rc == 0) {
        if (frameworkConfig->lineMax == 0) {
            fprintf(messageFile, "ERROR0008: line max has illegal value\n");
            rc = ERROR_CODE;
        }
    }
    /* allocate a line buffer, used when parsing the rest of the framework configuration file */
    if (rc == 0) {
        rc = Malloc_Safe((unsigned char **)&lineBuffer,	/* freed @3 */
                         frameworkConfig->lineMax,
                         frameworkConfig->lineMax);	/* trust the framework config file */
    }

    /* file_max */
    if (rc == 0) {
        rc = File_MapNameToUint((unsigned int *)&(frameworkConfig->fileMax),
                                "file_max",
                                lineBuffer,
                                frameworkConfig->lineMax,
                                configFile);
    }
    if (rc == 0) {
        if (verbose) fprintf(messageFile,
                             "FrameworkConfig_Parse: File maximum size: %hu bytes\n",
                             (int)frameworkConfig->fileMax);
    }
    if (rc == 0) {
        if (frameworkConfig->fileMax == 0) {
            fprintf(messageFile, "ERROR0008: file max has illegal value\n");
            rc = ERROR_CODE;
        }
    }

    /* framework name */
    if (rc == 0) {
        rc = File_MapNameToValue(&(frameworkConfig->frameworkName),
                                 "framework_name",
                                 lineBuffer,
                                 frameworkConfig->lineMax,
                                 configFile);
    }
    if (rc == 0) {
        if (verbose) fprintf(messageFile,
                             "FrameworkConfig_Parse: Framework name: %s\n",
                             frameworkConfig->frameworkName);
    }

    /* password expiration period */
    if (rc == 0) {
        rc = File_MapNameToUint(&(frameworkConfig->passwordExpire),
                                "password_expire",
                                lineBuffer,
                                frameworkConfig->lineMax,
                                configFile);
    }
    if (rc == 0) {
        if (verbose) fprintf(messageFile,
                             "FrameworkConfig_Parse: Password expiration: %u months\n",
                             frameworkConfig->passwordExpire);
    }
    /* framework audit log file name */
    if (rc == 0) {
        rc = File_MapNameToValue(&(frameworkConfig->frameworkLogFilename),
                                 "log",
                                 lineBuffer,
                                 frameworkConfig->lineMax,
                                 configFile);
    }
    if (rc == 0) {
        if (verbose) fprintf(messageFile,
                             "FrameworkConfig_Parse: Framework log file name: %s\n",
                             frameworkConfig->frameworkLogFilename);
    }
    /* dropbox dir */
    if (rc == 0) {
        rc = File_MapNameToValue(&(frameworkConfig->dropboxDir),	/* freed by
                                                                                   caller */
                                 "dropbox",
                                 lineBuffer,
                                 frameworkConfig->lineMax,
                                 configFile);
    }
    if (rc == 0) {
        if (verbose) fprintf(messageFile,
                             "FrameworkConfig_Parse: Dropbox root dir: %s\n",
                             frameworkConfig->dropboxDir);
    }
    /* stop file name */
    if (rc == 0) {
        rc = File_MapNameToValue(&(frameworkConfig->stopFile),	/* freed by caller */
                                 "stop_file",
                                 lineBuffer,
                                 frameworkConfig->lineMax,
                                 configFile);
    }
    if (rc == 0) {
        if (verbose) fprintf(messageFile,
                             "FrameworkConfig_Parse: Stop file name: %s\n",
                             frameworkConfig->stopFile);
    }
    /* restart file name */
    if (rc == 0) {
        rc = File_MapNameToValue(&(frameworkConfig->restartFile),	/* freed by caller */
                                 "restart_file",
                                 lineBuffer,
                                 frameworkConfig->lineMax,
                                 configFile);
    }
    if (rc == 0) {
        if (verbose) fprintf(messageFile,
                             "FrameworkConfig_Parse: Restart file name: %s\n",
                             frameworkConfig->restartFile);
    }
    /* output body file name */
    if (rc == 0) {
        rc = File_MapNameToValue(&(frameworkConfig->outputBodyFilename), /* freed by caller */
                                 "out_body",
                                 lineBuffer,
                                 frameworkConfig->lineMax,
                                 configFile);
    }
    if (rc == 0) {
        if (verbose) fprintf(messageFile,
                             "FrameworkConfig_Parse: Output body file name: %s\n",
                             frameworkConfig->outputBodyFilename);
    }
    /* output notification file name */
    if (rc == 0) {
        rc = File_MapNameToValue(&(frameworkConfig->notificationFilename), /* freed by caller */
                                 "notif_log",
                                 lineBuffer,
                                 frameworkConfig->lineMax,
                                 configFile);
    }
    if (rc == 0) {
        if (verbose) fprintf(messageFile,
                             "FrameworkConfig_Parse: Notification file name: %s\n",
                             frameworkConfig->notificationFilename);
    }
    /* email file name */
    if (rc == 0) {
        rc = File_MapNameToValue(&(frameworkConfig->emailFilename), /* freed by caller */
                                 "full_email",
                                 lineBuffer,
                                 frameworkConfig->lineMax,
                                 configFile);
    }
    if (rc == 0) {
        if (verbose) fprintf(messageFile,
                             "FrameworkConfig_Parse: Email file name: %s\n",
                             frameworkConfig->emailFilename);
    }
    /* input attachment file name */
    if (rc == 0) {
        rc = File_MapNameToValue(&(frameworkConfig->inputAttachmentFilename),	/* freed by
                                                                                   caller */
                                 "in_attachment",
                                 lineBuffer,
                                 frameworkConfig->lineMax,
                                 configFile);
    }
    if (rc == 0) {
        if (verbose) fprintf(messageFile,
                             "FrameworkConfig_Parse: Input attachment file name: %s\n",
                             frameworkConfig->inputAttachmentFilename);
    }
    /* output attachment file name */
    if (rc == 0) {
        rc = File_MapNameToValue(&(frameworkConfig->outputAttachmentFilename),	/* freed by
                                                                                   caller */
                                 "out_attachment",
                                 lineBuffer,
                                 frameworkConfig->lineMax,
                                 configFile);
    }
    if (rc == 0) {
        if (verbose) fprintf(messageFile,
                             "FrameworkConfig_Parse: Output attachment file name: %s\n",
                             frameworkConfig->outputAttachmentFilename);
    }

    /* master AES key token file */
    if (rc == 0) {
        rc = File_MapNameToValue(&(frameworkConfig->masterAesKeyTokenFilename),
                                 "key",
                                 lineBuffer,
                                 frameworkConfig->lineMax,
                                 configFile);
    }
    if (rc == 0) {
        if (verbose) fprintf(messageFile,
                             "FrameworkConfig_Parse: master AES key token file name: %s\n",
                             frameworkConfig->masterAesKeyTokenFilename);
    }
    /* The master AES key token was saved on disk as a one time operation during framework
       installation. */
    if (rc == 0) {
        if (verbose) fprintf(messageFile,
                             "FrameworkConfig_Parse: Reading master AES key token\n");
        rc = File_ReadBinaryFile(&(frameworkConfig->masterAesKeyToken),	/* freed by caller */
                                 &masterAesKeyTokenLength,
                                 CCA_KEY_IDENTIFIER_LENGTH,
                                 frameworkConfig->masterAesKeyTokenFilename);
        /* sanity check, the CCA key token is a fixed length */
        if (rc == 0) {
            if (masterAesKeyTokenLength != CCA_KEY_IDENTIFIER_LENGTH) {
                fprintf(messageFile,
                        "ERROR0004: Master AES key token length is invalid\n");
                rc = ERROR_CODE;
            }
        }
        else {
            /* at installation, the AES master key does not exist yet */
            if (!needMasterKey) {
                rc = 0;
            }
        }
    }
    /* LDAP URL */
    if (rc == 0) {
        rc = File_MapNameToValue(&(frameworkConfig->ldapUrl),
                                 "ldapurl",
                                 lineBuffer,
                                 frameworkConfig->lineMax,
                                 configFile);
    }
    if (rc == 0) {
        if (verbose) fprintf(messageFile,
                             "FrameworkConfig_Parse: LDAP URL: %s\n",
                             frameworkConfig->ldapUrl);
    }
    /* LDAP BASEDN */
    if (rc == 0) {
        rc = File_MapNameToValue(&(frameworkConfig->ldapBase),
                                 "ldapbase",
                                 lineBuffer,
                                 frameworkConfig->lineMax,
                                 configFile);
    }
    if (rc == 0) {
        if (verbose) fprintf(messageFile,
                             "FrameworkConfig_Parse: LDAP BASEDN: %s\n",
                             frameworkConfig->ldapBase);
    }

    /* read the list of framework admin email addresses */
    if (rc == 0) {
        rc = File_GetValueArray(&(frameworkConfig->frameworkAdmins),	/* freed by caller */
                                &(frameworkConfig->frameworkAdminCount), /* number framework
                                                                            admins */
                                "admins",
                                lineBuffer,
                                frameworkConfig->lineMax,
                                configFile);
    }
    if (rc == 0) {
        if (verbose) fprintf(messageFile,
                             "FrameworkConfig_Parse: "
                             "Framework administrators, %u entries\n",
                             (unsigned int)frameworkConfig->frameworkAdminCount);
        for (i = 0 ; i < frameworkConfig->frameworkAdminCount ; i++) {
            if (verbose) fprintf(messageFile,
                                 "FrameworkConfig_Parse: Framework administrator: %s\n",
                                 frameworkConfig->frameworkAdmins[i]);
        }
    }
    /* read the project to project configuration file mapping */
    if (rc == 0) {
        rc = File_GetNameValueArray(&(frameworkConfig->projectNames),	/* freed by caller */
                                    &(frameworkConfig->projectConfigFilenames),	/* freed  caller */
                                    &(frameworkConfig->projectLength),
                                    lineBuffer,
                                    frameworkConfig->lineMax,
                                    configFile);
    }
    if (rc == 0) {
        if (verbose) fprintf(messageFile,
                             "FrameworkConfig_Parse: "
                             "Project name to configuration file map, %u entries\n",
                             (unsigned int)frameworkConfig->projectLength);
        for (i = 0 ; i < frameworkConfig->projectLength ; i++) {
            if (verbose) fprintf(messageFile,
                                 "FrameworkConfig_Parse: Project name: %s Configuration file: %s\n",
                                 frameworkConfig->projectNames[i],
                                 frameworkConfig->projectConfigFilenames[i]);
        }
    }
    /* Once the number of projects is determined, allocate an array for the project configuration
       file structures.  The max size is the same because we trust the framework administrator not
       to attack itself. */
    if (rc == 0) {
        rc = Malloc_Safe((unsigned char **)&(frameworkConfig->projectConfigFiles),
                         frameworkConfig->projectLength * sizeof(unsigned char *),
                         frameworkConfig->projectLength * sizeof(unsigned char *));
    }
    /* NULL the elements immediately so the free() is valid on error */
    for (i = 0 ; (rc == 0) && (i < frameworkConfig->projectLength) ; i++) {
        frameworkConfig->projectConfigFiles[i] = NULL;
    }
    /* next malloc the project configuration file structures */
    for (i = 0 ; (rc == 0) && (i < frameworkConfig->projectLength) ; i++) {
        rc = Malloc_Safe((unsigned char **)&(frameworkConfig->projectConfigFiles[i]),
                         sizeof(ProjectConfig),
                         sizeof(ProjectConfig));	/* max size, trust the compiler */
        /* if the malloc is successful, _Init each one immediately so the delete is safe */
        if (rc == 0) {
            ProjectConfig_Init(frameworkConfig->projectConfigFiles[i]);
        }
    }
    /* validate the signer framework configuration file */
    if ((rc == 0) && validate) {
        if (verbose) fprintf(messageFile,
                             "FrameworkConfig_Parse: Validating framework configuration file\n");
        rc = FrameworkConfig_Validate(frameworkConfig);
    }
    if (rc != 0) {
        fprintf(messageFile,
                "ERROR0005: processing framework configuration file: %s\n",
                frameworkConfig->frameworkConfigFilename);
    }
    if (configFile != NULL) {
        fclose(configFile);				/* @2 */
    }
    free(lineBuffer);					/* @3 */
    return rc;
}

/* FrameworkConfig_Validate() checks that the object has valid values.
 */

int FrameworkConfig_Validate(FrameworkConfig *frameworkConfig)
{
    int			rc = 0;
    unsigned char 	eku[AES128_SIZE];	/* password encryption key */
    unsigned char 	aku[AKU_SIZE];		/* password authentication HMAC key */

    if (rc == 0) {
        if (frameworkConfig->passwordExpire == 0) {
            fprintf(messageFile, "ERROR0011: password expire has illegal value\n");
            rc = ERROR_CODE;
        }
    }
    /* validate that the output body can be opened */
    if (rc == 0) {
        rc = File_ValidateOpen(frameworkConfig->outputBodyFilename, "a");
    }
    /* validate that the notification output body can be opened */
    if (rc == 0) {
        rc = File_ValidateOpen(frameworkConfig->notificationFilename, "a");
    }
    /* validate that the full_email file can be opened */
    if (rc == 0) {
        rc = File_ValidateOpen(frameworkConfig->emailFilename, "a");
    }
    /* validate that the input attachment file can be written, try to create it */
    if (rc == 0) {
        rc = File_ValidateOpen(frameworkConfig->inputAttachmentFilename, "w");
        if (rc != 0) {
            fprintf(messageFile,
                    "ERROR0013: opening: %s for write\n", frameworkConfig->inputAttachmentFilename);
        }
    }
    /* then validate the open for read */
    if (rc == 0) {
        rc = File_ValidateOpen(frameworkConfig->inputAttachmentFilename, "r");
        if (rc != 0) {
            fprintf(messageFile,
                    "ERROR0013: opening: %s for read\n", frameworkConfig->inputAttachmentFilename);
        }
    }
    /* validate that the output attachment file can be written and read */
    if (rc == 0) {
        rc = File_ValidateOpen(frameworkConfig->outputAttachmentFilename, "w");
        if (rc != 0) {
            fprintf(messageFile,
                    "ERROR0013: opening: %s for write\n", frameworkConfig->outputAttachmentFilename);
        }
    }
    if (rc == 0) {
        rc = File_ValidateOpen(frameworkConfig->outputAttachmentFilename, "r");
        if (rc != 0) {
            fprintf(messageFile,
                    "ERROR0013: opening: %s for read\n", frameworkConfig->outputAttachmentFilename);
        }
    }
    /* Validate that the master AES key token can be used.  At first start up, the key may not
       exist.  Otherwise, the error is reported earlier and this code is not executed.  */
    if ((rc == 0) && (frameworkConfig->masterAesKeyToken != NULL)) {
        if (verbose) fprintf(messageFile,
                             "FrameworkConfig_Validate: Testing AES master key: %s\n",
                             frameworkConfig->masterAesKeyTokenFilename);
        rc = Password_KDF(eku,			/* user encryption key */
                          aku,			/* user authentication HMAC key */
                          frameworkConfig->frameworkAdmins[0],	/* dummy sender */
                          frameworkConfig->masterAesKeyToken);
    }
    /* there must be at least one project */
    if (rc == 0) {
        if (frameworkConfig->projectNames == 0) {
            fprintf(messageFile, "ERROR0014: Framework configuration file has no projects\n");
            rc = ERROR_CODE;
        }
    }
    /* erase the secret keys */
    memset(eku, 0, AES128_SIZE);
    memset(aku, 0, AKU_SIZE);
    return rc;
}

/* FrameworkConfig_LogStart() logs the framework startup event */

int FrameworkConfig_LogStart(FrameworkConfig *frameworkConfig)
{
    int		rc = 0;
    size_t	i;

    if (rc == 0) {
        /* log the startup time */
        File_LogTime(frameworkConfig->frameworkLogFile);
        /* log the framework configuration file and its digest */
        fprintf(frameworkConfig->frameworkLogFile,
                "\tStartup, framework configuration file: %s\n",
                frameworkConfig->frameworkConfigFilename);
        PrintAll(frameworkConfig->frameworkLogFile,
                 "\tFramework configuration file digest",
                 DIGEST_SIZE,
                 frameworkConfig->digest);
    }
    /* log each project configuration file and its digest */
    for (i = 0 ; (rc == 0) && (i < frameworkConfig->projectLength) ; i++) {
        fprintf(frameworkConfig->frameworkLogFile,
                "\tProject: %s, Configuration file: %s\n",
                frameworkConfig->projectNames[i],
                frameworkConfig->projectConfigFilenames[i]);
        PrintAll(frameworkConfig->frameworkLogFile,
                 "\tProject configuration file digest",
                 DIGEST_SIZE,
                 frameworkConfig->projectConfigFiles[i]->digest);
    }
    return rc;
}

/* FrameworkConfig_SendStartupMessage() sends the frameworkConfig->outputBodyFileName to
   frameworkConfig->frameworkAdmins as a startup notification.

   This has these useful side effects:

   - it displays the Notes password prompt while the administrator is still at the framework start
   up terminal, and validates the password

   - it validates the Notes client install, the Notes API install, and the ability to send email

   - it validates the framework administrator email address

   Returns ERR_FATAL on any error
*/

int FrameworkConfig_SendStartupMessage(FrameworkConfig *frameworkConfig,
                                       int transientError)
{
    int		rc = 0;
    size_t	i;
    FILE	*outputBodyFile = NULL;

    /* do not change the message file here, let trace messages go to stdout */
    if (verbose) fprintf(messageFile,
                         "FrameworkConfig_SendStartupMessage: Sending framework startup message\n");
    /* open the output email body file */
    if (rc == 0) {
        rc = File_Open(&outputBodyFile, frameworkConfig->outputBodyFilename, "w");
    }
    /* construct the startup message */
    if (rc == 0) {
        fprintf(outputBodyFile, "Starting signer framework\n");
        /* let the administrators know if this was a restart due to a transient error */
        if (transientError) {
            fprintf(outputBodyFile, "\n\n");
            fprintf(outputBodyFile, "Restarting after transient error.\n");
            fprintf(outputBodyFile, "Check signer framework log file for details\n");
        }
    }
    /* close the output email body file */
    if (outputBodyFile != NULL) {
        fclose(outputBodyFile);
    }

    /* send the startup message to each framework administrator */
    for (i = 0 ; (rc == 0) && (i < frameworkConfig->frameworkAdminCount) ; i++) {
        rc = SendMailFile(frameworkConfig, frameworkConfig->frameworkAdmins[i],
                          "Signer Framework Startup", frameworkConfig->outputBodyFilename);
    }
    remove(frameworkConfig->outputBodyFilename);
    /* If the startup can't be sent, even non-fatal errors terminate the program. */
    if (rc != 0) {
        rc = ERR_FATAL;
    }

    return rc;
}


/* FrameworkProcess_Process() is called to process one received email.

   It does common setup, and then branches based on the received email requestParms->status.

   NOTE: Each error return must log to the messageFile and frameworkLogFile.

   The return codes are:

   non-zero for transient error that will cause a Notes restart
   except, ERR_FATAL indicates a fatal error that should terminate the program
*/

int FrameworkProcess_Process(DropboxRequest *requestParms)
{
    int		rc = requestParms->status; /* for errors that get passed back to the caller */
    int 	processRc = 0;		/* for errors that indicate no response to sender */
    int 	responseType = 0;	/* response type to sender */
    size_t	i;

    /* validate the comments, sanitize the input so that use is safe below */
    if ((rc == 0) && (processRc == 0)) {
        if (verbose) fprintf(messageFile,
                             "FrameworkProcess_Process: validate comment\n");
        processRc = Comment_Validate(requestParms);
        /* on error, Comment_Validate() writes the framework log */
        if (processRc != 0) {
            /* error response back to sender */
            requestParms->status = ERR_SUBJECT_BAD;
            processRc = 0;
        }
    }
    /* basic logging and email response, sender and subject */
    if ((rc == 0) && (processRc == 0)) {
        File_LogTime(requestParms->frameworkConfig->frameworkLogFile);
        File_Printf(requestParms->frameworkConfig->frameworkLogFile, NULL,
                    "Sender: %s\n", requestParms->dbConfig->sender);
        File_Printf(requestParms->frameworkConfig->frameworkLogFile, NULL,
                    "Request User: %s\n", requestParms->user);
        File_Printf(requestParms->frameworkConfig->frameworkLogFile, NULL,
                    "Comment: %s\n", requestParms->comment);
        fprintf(messageFile, "Signer framework administrators are:\n");
        for (i = 0 ; i < requestParms->frameworkConfig->frameworkAdminCount ; i++) {
            fprintf(messageFile, "\t%s\n", requestParms->frameworkConfig->frameworkAdmins[i]);
        }
    }
    /* zero the output attachment file, just to prevent a bug from sending a previous attachment */
    if ((rc == 0) && (processRc == 0)) {
        rc = File_ValidateOpen(requestParms->frameworkConfig->outputAttachmentFilename, "w");
        /* fatal error */
        if (rc != 0) {
            fprintf(requestParms->frameworkConfig->frameworkLogFile,
                    "\tFatal error opening %s\n",
                    requestParms->frameworkConfig->outputAttachmentFilename);
            rc = ERR_FATAL;
        }
    }
    if (rc == 0) {		/* if no error */
        if (processRc == 0) {	/* if should respond to sender */

            responseType = FrameworkProcess_ProcessOK(requestParms);

            /* FrameworkProcess_SendResponse() sends a response to the original email sender.

               It will return 0 unless there is an error that should cause the main loop to
               restart or exit. */
            rc = FrameworkProcess_SendResponse(responseType, requestParms);
        }
        /* processRc != 0 -> no response to sender.  Errors must be logged to the framework log */
    } else {
        // Error path send a response back
        FrameworkProcess_SendResponse(responseType, requestParms);
    }

    /* close the messages file here if some error path (e.g., no response to sender ) kept it
       open */
    File_CloseMessageFile();

    return rc;
}

/* FrameworkProcess_ProcessOK() processes a received email that has passed initial validation tests.

   - the email signature is present and valid
   - the sender is validated
   - the subject is validated

   It

   - forms the argv array for the signer program from the email header and body
   - adds project specific arguments to argv
   - validates the sender authority for the project
   - decrypts the password
   - calls the signer program
   - sends notification messages

   NOTE: Each error return must log to the messageFile and frameworkLogFile.

   On error, returns responseType RESPONSE_BODY_ONLY
*/

int FrameworkProcess_ProcessOK(DropboxRequest *requestParms)
{
    int		rc = 0;
    size_t	i;
    Arguments	arguments;

    /* project configuration file */
    const char 		*projectConfigFilename = NULL;
    ProjectConfig 	*projectConfig = NULL;

    /* create the project command line arguments */
    Arguments_Init(&arguments);			/* freed @1 */
    arguments.argc = 1;		/* start with 1, the first argument is the program name */

    /* append output body file name to argv.  This should remain the first argument so the project
       program can immediately switch from stdout to the output body when tracing.  */
    if (rc == 0) {
        rc = Arguments_AddPairTo(&arguments, "-obody",
                                 requestParms->frameworkConfig->outputBodyFilename);
    }
    /* append the sender to argv */
    if (rc == 0) {
        rc = Arguments_AddPairTo(&arguments, "-sender", requestParms->dbConfig->sender);
    }
    // Add the epwd
    if (rc == 0 && requestParms->epwd != NULL) {
        rc = Arguments_AddPairTo(&arguments, "-epwd", requestParms->epwd);
    }
    // Add the project
    if (rc == 0 && requestParms->project != NULL) {
        rc = Arguments_AddPairTo(&arguments, "-project", requestParms->project);
    }
    /* process the input request, append to argv */
    if (rc == 0) {
        rc = ProjectProcess_ProcessInputParameters(&arguments,
                                                   requestParms);
        if (rc != 0) {
            File_Printf(requestParms->frameworkConfig->frameworkLogFile, messageFile,
                        "ERROR0018: processing input request parameters\n");
        }
    }
    /* index into the frameworkConfig array and retrieve the ProjectConfig structure */
    if (rc == 0) {
        int found = FALSE;
        for (i = 0 ; (i < requestParms->frameworkConfig->projectLength) && !found ; i++) {
            if (strcmp(requestParms->project, requestParms->frameworkConfig->projectNames[i]) == 0) {
                projectConfig = requestParms->frameworkConfig->projectConfigFiles[i];
                projectConfigFilename = requestParms->frameworkConfig->projectConfigFilenames[i];
                found = TRUE;
            }
        }
        if (!found) {
            File_Printf(requestParms->frameworkConfig->frameworkLogFile, messageFile,
                        "ERROR0020: Could not map project: %s\n",
                        requestParms->project);
            fprintf(messageFile,
                    "Contact framework administrator\n");
            rc = RESPONSE_BODY_ONLY;
        }
    }
    /* add project email address to output body */
    if (rc == 0) {
        fprintf(messageFile, "Project administrator is %s\n\n", projectConfig->emailProject);
    }
    /* process the project specific configuration file, add command line arguments to argv */
    if (rc == 0) {
        rc = ProjectConfig_Process(&arguments,
                                   projectConfig,
                                   requestParms);
        if (rc != 0) {
            File_Printf(requestParms->frameworkConfig->frameworkLogFile, messageFile,
                        "ERROR0021: Error while processing the project configuration file: %s\n",
                        projectConfigFilename);
            fprintf(messageFile,
                    "Contact framework administrator\n");
        }
    }
    /* validate that the sender is authorized for the project, that the sender email address is in
       the project file */
    if (rc == 0) {
        if (verbose) fprintf(messageFile,
                             "FrameworkProcess_ProcessOK: "
                             "Validate sender %s authorization for project %s\n",
                             requestParms->dbConfig->sender, requestParms->project);
        rc = ProjectConfig_ValidateSender(requestParms->dbConfig->sender,
                                          projectConfig,
                                          requestParms->frameworkConfig);
        if (rc != 0) {
            File_Printf(requestParms->frameworkConfig->frameworkLogFile, messageFile,
                        "ERROR0022: %s is not authorized for project: %s\n",
                        requestParms->dbConfig->sender, requestParms->project);
            fprintf(messageFile,
                    "Contact framework administrator\n");
        }
    }
    /* if needed, decrypt and append the password.

                      Since there are several errors, Password_Decrypt does the error logging. */
    if ((rc == 0) && projectConfig->needPassword) {
        rc = Password_Decrypt(&arguments,
                              requestParms->dbConfig->sender,
                              requestParms->frameworkConfig->masterAesKeyToken,
                              requestParms->frameworkConfig->frameworkLogFile);
    }

    /* NOTE Traces the command line arguments.  This is a security hole and should not be compiled
       into the final product. */
#if 0
    if (rc == 0) {
        printf("\nargc = %u\n", arguments.argc);

        for (i = 0 ; i < (size_t)arguments.argc ; i++) {
            printf("%u: %s\n", (unsigned int)i, arguments.argv[i]);
        }
    }
#endif

    /* call the project specific program */
    if (rc == 0) {
        if (verbose) fprintf(messageFile, "FrameworkProcess_ProcessOK: calling program: %s\n",
                             arguments.argv[0]);
        rc = CallSigner(&arguments,
                        TRUE,			/* useOutputBody */
                        requestParms->frameworkConfig->outputBodyFilename);
        if (rc != 0) {
            if (verbose) fprintf(messageFile,
                                 "FrameworkProcess_ProcessOK: Error from %s\n",
                                 arguments.argv[0]);
        }
        /* update framework audit log */
        fprintf(requestParms->frameworkConfig->frameworkLogFile, "\tProject: %s\n", requestParms->project);
        fprintf(requestParms->frameworkConfig->frameworkLogFile, "\tProgram: %s\n", arguments.argv[0]);
        fprintf(requestParms->frameworkConfig->frameworkLogFile, "\tReturn code: %d\n", rc);
    }
    /* notification recipient logging */
    if (rc == 0) {
        /* a notification failure does not prevent a response to the sender, although it probably
           won't work either */
        FrameworkProcess_SendNotificationMessage(requestParms->project,
                                                 projectConfig,
                                                 requestParms);
    }
    requestParms->status = rc;
    /* indicates that the body is valid but there is no attachment */
    if (rc != 0) {
        rc = RESPONSE_BODY_ONLY;
    }
    /* cleanup */
    /* remove input attachment, if any.  This is likely unnecessary, since it's also removed before
       each new email is processed. */
    remove(requestParms->frameworkConfig->inputAttachmentFilename);
    Arguments_Delete(&arguments);			/* @1 */
    return rc;
}


/* FrameworkProcess_SendResponse() sends a response to the original sender.  It is called
   upon success or non-fatal error conditions.

   responseType

   0 success - send response and attachment to sender
   RESPONSE_BODY_ONLY - send response to sender
   RESPONSE_BODY_TO_ADMIN - send response to admin rather than sender
   RESPONSE_NO_EMAIL - don't send any response

   Returns: non-zero on an error that should cause the main loop to restart or exit
*/

int FrameworkProcess_SendResponse(int responseType,
                                  DropboxRequest* requestParms)
{
    int 	rc = 0;
    int     i = 0;

    /* this is the last email to be sent.  close the messageFile before sending */
    requestParms->closeMessageFile = TRUE;

    if (rc == 0) {
        switch (responseType) {
        case 0:
            /* send reply to sender: sendto, body, attachment */
            requestParms->hasResult=1;
            rc = sendResult(requestParms);
            /* send audit message to notification receivers */
            break;
        case RESPONSE_BODY_ONLY:
            /* send reply to sender: sendto, body */
            rc = sendResult(requestParms);
            /* send audit message to notification receivers */
            break;
        case RESPONSE_BODY_TO_ADMIN:
            /* send reply to admin: sendto, body */
            for (i = 0 ; (rc == 0) && (i < (int)requestParms->frameworkConfig->frameworkAdminCount) ; i++) {
                rc = SendMailFile(requestParms->frameworkConfig,
                                  requestParms->frameworkConfig->frameworkAdmins[i],
                                  "Result Response", requestParms->frameworkConfig->outputBodyFilename);
            }
            break;
        case RESPONSE_NO_EMAIL:
            /* already logged, just continue in loop */
            break;
        default:
            fprintf(requestParms->frameworkConfig->frameworkLogFile,
                    "\tERROR0056: Error, unexpected response type %u\n",
                    responseType);
            rc = ERR_BAD_ARG;
            break;
        }
    }
    /* The message file is typically closed by the function that sends the email.  This call catches
       error cases that abort before sending the email. */
    File_CloseMessageFile();
    return rc;
}

/* FrameworkProcess_SendNotificationMessage() forms the notification message and sends it to the
   notification recipients.
*/

int FrameworkProcess_SendNotificationMessage(const char *project,
                                             ProjectConfig *projectConfig,
                                             DropboxRequest* requestParms)
{
    int 	rc = 0;
    size_t	i;
    char 	*subjectRe = NULL;		/* freed @1 */
    FILE	*notificationFile = NULL;	/* email body back to notification receivers */

    /* open the output notification body log file */
    if (rc == 0) {
        rc = File_Open(&notificationFile,
                       requestParms->frameworkConfig->notificationFilename,
                       "w");
        if (rc != 0) {
            fprintf(requestParms->frameworkConfig->frameworkLogFile,
                    "\tERROR0057: Error opening notification message file %s\n",
                    requestParms->frameworkConfig->notificationFilename);
        }
    }
    /* construct the notification message */
    if (rc == 0) {
        /* time stamp */
        File_LogTime(notificationFile);
        /* project */
        fprintf(notificationFile,
                "Project         : %s\n", project);
        /* sender */
        fprintf(notificationFile,
                "Dropbox sender  : %s\n", requestParms->dbConfig->sender);
        fprintf(notificationFile,
                "Request Comments: %s\n", requestParms->comment);
        /* people copied */
        fprintf(notificationFile,
                "\nNotification recipients:\n");
        for (i = 0 ; i < projectConfig->notificationListCount ; i++) {
            fprintf(notificationFile,
                    "    %s\n",
                    projectConfig->notificationList[i]);
        }
        fprintf(notificationFile,
                "\nSigner framework administrators are:\n");
        for (i = 0 ; i < requestParms->frameworkConfig->frameworkAdminCount ; i++) {
            fprintf(notificationFile,
                    "    %s\n", requestParms->frameworkConfig->frameworkAdmins[i]);
        }
        fprintf(notificationFile,
                "\nSigner project administrator is %s\n",
                projectConfig->emailProject);
    }
    /* close early, before sending the emails */
    if (notificationFile != NULL) {
        fclose(notificationFile);
        notificationFile = NULL;
    }
    /* form a notification subject, e.g. Re: Subject */
    if (rc == 0) {
        rc = Malloc_Safe((unsigned char**)&subjectRe, strlen("Request for : ") + strlen(project) + 5,
                         requestParms->frameworkConfig->lineMax); /* freed @1 */
        if (rc != 0) {
            fprintf(requestParms->frameworkConfig->frameworkLogFile,
                    "\tERROR0058: Error forming response subject\n");
        } else {
            sprintf(subjectRe, "Request for : %s", project);
        }
    }
    if (rc == 0) {
        /* iterate through the notification recipients, sending the notification message.  Don't
           check the return code here.  Try to send as many notifications as will succeed */
        for (i = 0 ; i < projectConfig->notificationListCount ; i++) {

            rc = SendMailFile(requestParms->frameworkConfig, projectConfig->notificationList[i],
                              subjectRe, requestParms->frameworkConfig->notificationFilename);
            if (rc == 0) {
                fprintf(requestParms->frameworkConfig->frameworkLogFile,
                        "\tSent notification to %s\n", projectConfig->notificationList[i]);
            }
            /* log notification failures in the framework audit log, but keep trying the other
               notification recipients */
            else {
                fprintf(requestParms->frameworkConfig->frameworkLogFile,
                        "\tERROR0059 sending notification to %s\n",
                        projectConfig->notificationList[i]);
            }
        }
    }
    remove(requestParms->frameworkConfig->notificationFilename);
    /* cleanup */
    free(subjectRe);		/* @1 */
    return rc;
}

/* ProjectConfig_Init() initializes the ProjectConfig object members
 */

void ProjectConfig_Init(ProjectConfig *projectConfig)
{
    memset(projectConfig, 0, sizeof(ProjectConfig));
    return;
}

/* ProjectConfig_Delete() frees and reinitializes the ProjectConfig object members
 */

void ProjectConfig_Delete(ProjectConfig *projectConfig)
{
    size_t i;

    if (projectConfig != NULL) {
        free(projectConfig->program);
        free(projectConfig->projectLogFilename);
        free(projectConfig->keyFilename);
        free(projectConfig->auxCfgFilename);
        free(projectConfig->emailProject);
        /* free array members before freeing the array */
        for (i = 0 ; i < projectConfig->sendersCount ; i++) {
            free(projectConfig->senders[i]);
            free(projectConfig->senderemails[i]);
        }
        free(projectConfig->senders);
        free(projectConfig->senderemails);
        /* free array members before freeing the array */
        for (i = 0 ; i < projectConfig->notificationListCount ; i++) {
            free(projectConfig->notificationList[i]);
        }
        free(projectConfig->notificationList);
        /* initialize so the next delete is safe */
        ProjectConfig_Init(projectConfig);
    }
    return;
}

/* ProjectConfig_Parse() parses a project configuration file into the ProjectConfig object.

   NOTE: Since this is called at startup, messages should go to stdout.  All calls that set an error
   code must print as well.

   validate flags whether the validation, which writes files, should be done.  The main framework
   should perform validation.  Ancillary programs should not, so as not to interfere with a running
   framework.
*/

int ProjectConfig_Parse(ProjectConfig *projectConfig,
                        int validate,
                        const char *projectConfigFilename,
                        FrameworkConfig *frameworkConfig)
{
    int		rc = 0;
    size_t	i;
    FILE 	*projectConfigFile = NULL;	/* closed @1 */
    char	*lineBuffer = NULL;		/* freed @2 */

    /* allocate a line buffer, used when parsing the configuration file */
    if (rc == 0) {
        rc = Malloc_Safe((unsigned char **)&lineBuffer,
                         frameworkConfig->lineMax,
                         frameworkConfig->lineMax);	/* trust the framework config file */
    }
    /* save a hash of the project configuration file for the framework audit log */
    if (rc == 0) {
        rc = Ossl_HashBinaryFile(projectConfig->digest,
                                 MAX_CONFIG,
                                 projectConfigFilename);
    }
    if (rc == 0) {
        if (verbose) PrintAll(messageFile,
                              "ProjectConfig_Parse: Project configuration file digest",
                              DIGEST_SIZE,
                              projectConfig->digest);
    }
    /* open project configuration file */
    if (rc == 0) {
        projectConfigFile = fopen(projectConfigFilename, "r");		/* closed @1 */
        if (projectConfigFile == NULL) {
            rc = ERROR_CODE;
        }
    }
    /* program */
    if (rc == 0) {
        rc = File_MapNameToValue(&(projectConfig->program), 	/* freed by caller */
                                 "program",
                                 lineBuffer,
                                 frameworkConfig->lineMax,
                                 projectConfigFile);
    }
    if (rc == 0) {
        if (verbose) fprintf(messageFile,
                             "ProjectConfig_Parse: Program filename: %s\n",
                             projectConfig->program);
    }
    /* projectLogFilename */
    if (rc == 0) {
        rc = File_MapNameToValue(&(projectConfig->projectLogFilename), /* freed by caller */
                                 "log",
                                 lineBuffer,
                                 frameworkConfig->lineMax,
                                 projectConfigFile);
    }
    if (rc == 0) {
        if (verbose) fprintf(messageFile,
                             "ProjectConfig_Parse: Project log file name: %s\n",
                             projectConfig->projectLogFilename);
    }
    /* determine whether a signing key is needed */
    if (rc == 0) {
        rc = File_MapNameToBool(&(projectConfig->needKey),
                                "needkey",
                                lineBuffer,
                                frameworkConfig->lineMax,
                                projectConfigFile);
    }
    if (rc == 0) {
        if (verbose) fprintf(messageFile, "ProjectConfig_Parse: project needs key: %d\n",
                             projectConfig->needKey);
    }
    /* keyFilename */
    if ((rc == 0) && projectConfig->needKey) {
        rc = File_MapNameToValue(&(projectConfig->keyFilename), /* freed by caller */
                                 "key",
                                 lineBuffer,
                                 frameworkConfig->lineMax,
                                 projectConfigFile);
    }
    if ((rc == 0) && projectConfig->needKey) {
        if (verbose) fprintf(messageFile,
                             "ProjectConfig_Parse: Project key file name: %s\n",
                             projectConfig->keyFilename );
    }
    /* determine whether an auxiliary project configuration file is needed */
    if (rc == 0) {
        rc = File_MapNameToBool(&(projectConfig->needAuxCfg),
                                "needauxcfg",
                                lineBuffer,
                                frameworkConfig->lineMax,
                                projectConfigFile);
    }
    if (rc == 0) {
        if (verbose) fprintf(messageFile,
                             "ProjectConfig_Parse: "
                             "project needs auxiliary project configuration file: %d\n",
                             projectConfig->needAuxCfg);
    }
    /* auxCfgFilename */
    if ((rc == 0) && projectConfig->needAuxCfg) {
        rc = File_MapNameToValue(&(projectConfig->auxCfgFilename), /* freed by caller */
                                 "auxcfg",
                                 lineBuffer,
                                 frameworkConfig->lineMax,
                                 projectConfigFile);
    }
    if ((rc == 0) && projectConfig->needAuxCfg) {
        if (verbose) fprintf(messageFile,
                             "ProjectConfig_Parse: "
                             "Project auxiliary project configuration file name: %s\n",
                             projectConfig->auxCfgFilename);
    }
    /* determine whether an input attachment is needed */
    if (rc == 0) {
        rc = File_MapNameToBool(&(projectConfig->needInputAttachment),
                                "neediatt",
                                lineBuffer,
                                frameworkConfig->lineMax,
                                projectConfigFile);
    }
    if (rc == 0) {
        if (verbose) fprintf(messageFile,
                             "ProjectConfig_Parse: project needs input attachment: %d\n",
                             projectConfig->needInputAttachment);
    }
    /* determine whether an output attachment is needed */
    if (rc == 0) {
        rc = File_MapNameToBool(&(projectConfig->needOutputAttachment),
                                "needoatt",
                                lineBuffer,
                                frameworkConfig->lineMax,
                                projectConfigFile);
    }
    if (rc == 0) {
        if (verbose) fprintf(messageFile,
                             "ProjectConfig_Parse: project needs output attachment: %d\n",
                             projectConfig->needOutputAttachment);
    }
    /* determine whether a CCA password is needed */
    if (rc == 0) {
        rc = File_MapNameToBool(&(projectConfig->needPassword),
                                "needpwd",
                                lineBuffer,
                                frameworkConfig->lineMax,
                                projectConfigFile);
    }
    if (rc == 0) {
        if (verbose) fprintf(messageFile,
                             "ProjectConfig_Parse: project needs password: %d\n",
                             projectConfig->needPassword);
    }
    /* emailProject */
    if (rc == 0) {
        rc = File_MapNameToValue(&(projectConfig->emailProject), /* freed by caller */
                                 "email",
                                 lineBuffer,
                                 frameworkConfig->lineMax,
                                 projectConfigFile);
    }
    if (rc == 0) {
        if (verbose) fprintf(messageFile,
                             "ProjectConfig_Parse: Project administrator email: %s\n",
                             projectConfig->emailProject);
    }
    /* read the list of notification receivers */
    if (rc == 0) {
        rc = File_GetValueArray(&(projectConfig->notificationList),	/* freed by caller */
                                &(projectConfig->notificationListCount),
                                "notifs",
                                lineBuffer,
                                frameworkConfig->lineMax,
                                projectConfigFile);
    }
    /* determine whether senders are needed */
    if (rc == 0) {
        rc = File_MapNameToBool(&(projectConfig->needSenders),
                                "needsenders",
                                lineBuffer,
                                frameworkConfig->lineMax,
                                projectConfigFile);
    }
    if (rc == 0) {
        if (verbose) fprintf(messageFile,
                             "ProjectConfig_Parse: project needs senders: %d\n",
                             projectConfig->needSenders);
    }
    /* read the list of authorized senders */
    if (rc == 0) {
        rc = File_GetNameValueArray(&(projectConfig->senders),	/* freed by caller */
                                    &(projectConfig->senderemails),	/* freed by caller */
                                    &(projectConfig->sendersCount), /* number of authorized senders */
                                    lineBuffer,
                                    frameworkConfig->lineMax,
                                    projectConfigFile);
    }
    /* validate the project configuration file */
    if ((rc == 0) && validate) {
        if (verbose) fprintf(messageFile,
                             "ProjectConfig_Parse: Validating project configuration file\n");
        rc = ProjectConfig_Validate(projectConfig,
                                    frameworkConfig);
    }
    if (rc != 0) {
        fprintf(messageFile,
                "ERROR0023: processing project configuration file: %s\n",
                projectConfigFilename);
    }
    if (rc == 0) {
        if (verbose) fprintf(messageFile,
                             "ProjectConfig_Parse: "
                             "Authorized senders, %u entries\n",
                             (unsigned int)projectConfig->sendersCount);
        for (i = 0 ; i < projectConfig->sendersCount ; i++) {
            if (verbose) fprintf(messageFile,
                                 "ProjectConfig_Parse: Authorized sender: %s\n",
                                 projectConfig->senders[i]);
        }
        if (verbose) fprintf(messageFile,
                             "ProjectConfig_Parse: "
                             "Notification receivers, %u entries\n",
                             (unsigned int)projectConfig->notificationListCount);
        for (i = 0 ; i < projectConfig->notificationListCount; i++) {
            if (verbose) fprintf(messageFile,
                                 "ProjectConfig_Parse: Notification receiver: %s\n",
                                 projectConfig->notificationList[i]);
        }
    }
    if (projectConfigFile != NULL) {
        fclose(projectConfigFile);	/* @1 */
    }
    free(lineBuffer);			/* @2 */
    return rc;
}

/* ProjectConfig_Validate() checks that the project configuration file object has valid values.
 */

int ProjectConfig_Validate(ProjectConfig *projectConfig,
                           FrameworkConfig *frameworkConfig)
{
    int		rc = 0;
    Arguments	arguments;

    /* create the project command line arguments */
    Arguments_Init(&arguments);			/* freed @1 */
    arguments.argc = 1;		/* start with 1, the first argument is the program name */

    /* validate that the project log file can be opened for append */
    if (rc == 0) {
        if (verbose) fprintf(messageFile, "ProjectConfig_Validate: "
                             "Validating project log file %s\n",
                             projectConfig->projectLogFilename);
        rc = File_ValidateOpen(projectConfig->projectLogFilename, "a");
    }
    /* validate that the project key file can be opened for read */
    if ((rc == 0) && projectConfig->needKey) {
        rc = File_ValidateOpen(projectConfig->keyFilename, "r");
    }
    /* validate that the project key can be used to sign */
    if ((rc == 0) && projectConfig->needKey) {
        rc = ProjectConfig_ValidateKey(projectConfig);
    }
    /* validate that the auxiliary project configuration file can be opened for read */
    if ((rc == 0) && projectConfig->needAuxCfg) {
        rc = File_ValidateOpen(projectConfig->auxCfgFilename, "r");
    }
    /* validate the sender count */
    if (rc == 0) {
        if (projectConfig->needSenders) {
            if (projectConfig->sendersCount == 0) {
                fprintf(messageFile,
                        "ERROR0024: Project configuration file has no authorized senders\n");
                rc = ERROR_CODE;
            }
        }
        else {
            if (projectConfig->sendersCount != 0) {
                fprintf(messageFile,
                        "ERROR0024: Project configuration file has authorized senders\n");
                rc = ERROR_CODE;
            }
        }
    }
    /*
      validate that the project file can be called, use -h
    */
    /* add the program name for the project */
    if (rc == 0) {
        /* create the project command line arguments */
        rc = Arguments_AddTo(&arguments,
                             projectConfig->program,
                             TRUE);		/* add at index 0 */
    }
    /* append output body file name to argv so the -h usage text goes to a file rather than to
       stdout */
    if (rc == 0) {
        rc = Arguments_AddPairTo(&arguments, "-obody", frameworkConfig->outputBodyFilename);
    }
    /* add -h flag, trick to probe if the program can be called */
    if (rc == 0) {
        rc = Arguments_AddTo(&arguments, "-h", FALSE);
    }
    if (rc == 0) {
        if (verbose) fprintf(messageFile, "ProjectConfig_Validate: calling program: %s\n",
                             arguments.argv[0]);
        rc = CallSigner(&arguments,
                        FALSE,			/* useOutputBody */
                        frameworkConfig->outputBodyFilename);
    }
    /* cleanup */
    Arguments_Delete(&arguments);	/* @1 */
    return rc;
}

int ProjectConfig_ValidateKey(ProjectConfig *projectConfig)
{
    int			rc = 0;

    int			typeFound = FALSE;
    unsigned char 	*keyToken = NULL;	/* CCA signing key token, freed @1 */
    size_t		keyTokenLength;
    RsaKeyTokenPublic 	rsaKeyTokenPublic;	/* signing key CCA public key structure */
#ifdef ADD_ECC
    EccKeyTokenPublic 	eccKeyTokenPublic;	/* CCA public key structure */
#endif

    /* get the CCA signing key token */
    if (rc == 0) {
        if (verbose) fprintf(messageFile,
                             "ProjectConfig_ValidateKey: Reading CCA key token file %s\n",
                             projectConfig->keyFilename);
        rc = File_ReadBinaryFile(&keyToken, &keyTokenLength, 2000,
                                 projectConfig->keyFilename); /* freed @1 */
        if (rc != 0) {
            fprintf(messageFile,
                    "ERROR0012: Could not open key file: %s\n", projectConfig->keyFilename);
        }
    }
    /* determine if the key is RSA or ECC */
    if ((rc == 0) && !typeFound) {
        rc = getPKA96PublicKey(&rsaKeyTokenPublic,	/* output: structure */
                               keyTokenLength,
                               keyToken,
                               0);			/* input: PKA96 key token */
        if (rc == 0) {
            if (verbose) fprintf(messageFile,
                                 "ProjectConfig_ValidateKey: CCA key token is RSA\n");
            typeFound = TRUE;
#if 0	/* NOTE Not run, since it requires a CCA login.  This can be added in the future */
            rc = ProjectConfig_ValidateKeyRSA(keyTokenLength,
                                              keyToken);
#endif
        }
        else {
            rc = 0;	/* try next type */
        }
    }
#ifdef ADD_ECC
    if ((rc == 0) && !typeFound) {
        rc = getPKA96EccPublicKey(&eccKeyTokenPublic,	/* output: structure */
                                  keyTokenLength,
                                  keyToken);		/* input: PKA96 key token */
        if (rc == 0) {
            if (verbose) fprintf(messageFile,
                                 "ProjectConfig_ValidateKey: CCA key token is ECC\n");
            typeFound = TRUE;
#if 0	/* NOTE Not run, since it requires a CCA login.  This can be added in the future */
            rc = ProjectConfig_ValidateKeyECC(keyTokenLength,
                                              keyToken);
#endif
        }
        else {
            rc = 0;	/* try next type */
        }
    }
#endif
    if ((rc == 0) && !typeFound) {
        fprintf(messageFile,
                "ERROR0015: CCA key token is unknown type %s\n", projectConfig->keyFilename);
        rc = ERROR_CODE;
    }
    /* clean up */
    free(keyToken);	/* @1 */

    return rc;
}

/* ProjectConfig_ValidateKeyRSA() validates that a null digest can be signed with the CCA RSA key
   token

   NOTE Not tested
*/

int ProjectConfig_ValidateKeyRSA(size_t	keyTokenLength,
                                 unsigned char *keyToken)
{
    int			rc = 0;

    unsigned char	signature[N_SIZE];
    unsigned long	signatureLength = sizeof(signature);
    unsigned long 	signatureBitLength;	/* unused */
    unsigned char 	digest[SHA1_SIZE];

    memset(digest, 0, sizeof(digest));
    if (rc == 0) {
        if (verbose) fprintf (messageFile,
                              "ProjectConfig_ValidateKeyRSA: Signing");
        rc = Digital_Signature_Generate(&signatureLength,	/* i/o */
                                        &signatureBitLength,	/* output */
                                        signature,		/* output */
                                        keyTokenLength,		/* input */
                                        keyToken,		/* input */
                                        sizeof(digest),		/* input */
                                        digest);		/* input */
    }
    /* clean up */

    return rc;
}

#ifdef ADD_ECC

/* ProjectConfig_ValidateKeyECC() validates that a null digest can be signed with the CCA ECC  key
   token

   NOTE Not tested
*/

int ProjectConfig_ValidateKeyECC(size_t	keyTokenLength,
                                 unsigned char *keyToken)
{
    int			rc = 0;

    unsigned char  	signature[132];		/* NOTE 132 according to CCA, openssl produces
                                           139 */
    unsigned long signatureLength = sizeof(signature);
    unsigned long signatureBitLength;
    unsigned char digest[SHA1_SIZE];

    memset(digest, 0, sizeof(digest));
    if (rc == 0) {
        if (verbose) fprintf (messageFile,
                              "ProjectConfig_ValidateKeyECC: Signing");
        rc = Digital_Signature_Generate_ECC(&signatureLength,		/* i/o */
                                            &signatureBitLength,	/* output */
                                            signature,			/* output */
                                            keyTokenLength,		/* input */
                                            keyToken,			/* input */
                                            sizeof(digest),		/* input */
                                            digest);			/* input */

    }
    /* clean up */

    return rc;
}
#endif


/* ProjectProcess_ProcessInputParameters() takes each line of the input body and assigns it to an argv
   element.

   It rejects certain standard framework command line argument, so that the request cannot
   override them.
*/

int ProjectProcess_ProcessInputParameters(Arguments *arguments,
                                          DropboxRequest *requestParms)
{
    int		rc = 0;
    int     i = 0;
    int     irc = 0;
    char    buf[requestParms->frameworkConfig->lineMax];
    const char*   curpos = requestParms->parameters;
    const char*   nextpos = NULL;

    if (requestParms->parameters != NULL &&
        strlen(requestParms->parameters) != 0) {

        do {
            while (*curpos == ' ') curpos++;

            // Break the parms into words and add as args
            nextpos = strchr(curpos, ' ');
            if (nextpos == NULL) {
                // end of the line
                strcpy(buf, curpos);
                curpos = NULL;
            } else if (nextpos-curpos > (int)requestParms->frameworkConfig->lineMax) {
                rc = 1;
                File_Printf(requestParms->frameworkConfig->frameworkLogFile, messageFile,
                            "Parameter overflow in input parameters\n");
            } else {
                strncpy(buf, curpos, nextpos-curpos);
                buf[(nextpos-curpos)] = '\0';
                curpos = nextpos;
                if (*curpos == '\0') curpos = NULL;
            }

            /* screen out command line arguments that attempt to override the framework values */
            for (i = 0 ; (rc == 0) && (i < (int)(sizeof(claTable)/sizeof(char *))) ; i++) {
                irc = strcmp(claTable[i], buf);
                if (irc == 0) {
                    File_Printf(requestParms->frameworkConfig->frameworkLogFile, messageFile,
                                "%s illegal in input parameters\n", buf);
                    if (verbose) fprintf(messageFile,
                                         "ProjectProcess_ProcessInputBody: %s illegal in input parameters\n",
                                         buf);
                    rc = ERROR_CODE;
                }
            }
            /* add line to argv */
            if (rc == 0) {
                rc = Arguments_AddTo(arguments, buf, FALSE);	/* add to end */
            }
        }
        while (rc == 0 && curpos != NULL);
    }
    return rc;
}

/* ProjectConfig_Process() uses the project configuration file to add command line arguments

   - project specific signer program (put in arguments->argv[0])
   - audit log file name
   - signing key (optional)
   - input attachment file (optional)
   - output attachment file (optional)
*/

int ProjectConfig_Process(Arguments		*arguments,
                          ProjectConfig *projectConfig,
                          DropboxRequest *requestParms)
{
    int		rc = 0;

    /* add the program name for the project */
    if (rc == 0) {
        rc = Arguments_AddTo(arguments,
                             projectConfig->program,
                             TRUE);		/* add at index 0 */
    }
    /* add the project audit log filename */
    if (rc == 0) {
        rc = Arguments_AddPairTo(arguments,
                                 "-log", projectConfig->projectLogFilename);
    }
    /* add the signing key if needed */
    if (rc == 0) {
        if (projectConfig->needKey) {
            rc = Arguments_AddPairTo(arguments,
                                     "-key", projectConfig->keyFilename);
        }
    }
    /* add the auxiliary project configuration file if needed */
    if (rc == 0) {
        if (projectConfig->needAuxCfg) {
            rc = Arguments_AddPairTo(arguments,
                                     "-auxcfg", projectConfig->auxCfgFilename);
        }
    }
    /* add the input attachment if needed */
    if ((rc == 0) && projectConfig->needInputAttachment) {
        if (requestParms->hasPayload) {
            rc = Arguments_AddPairTo(arguments,
                                     "-di", requestParms->frameworkConfig->inputAttachmentFilename);
        }
        else {
            File_Printf(requestParms->frameworkConfig->frameworkLogFile, messageFile,
                        "ERROR0055: Project requires an attachment");
            rc = ERROR_CODE;
        }
    }
    /* add the output attachment if needed */
    if (rc == 0) {
        if (projectConfig->needOutputAttachment) {
            rc = Arguments_AddPairTo(arguments,
                                     "-do", requestParms->frameworkConfig->outputAttachmentFilename);
        }
    }
    return rc;
}

/* ProjectConfig_ValidateSender() validates that the sender is authorized via the project
   configuration file.
*/

int ProjectConfig_ValidateSender(const char *sender,
                                 ProjectConfig *projectConfig,
                                 FrameworkConfig *configParm)
{
    int		rc = 0;
    int		irc;
    int     ldaprc = 0;
    size_t	i;
    int		authorized = FALSE;

    /* if the project doesn't have a senders list, no authorization is required */
    if (!projectConfig->needSenders)
    {
        if (verbose) fprintf(messageFile,
                             "ProjectConfig_ValidateSender: "
                             "Project does not use sender authorization\n");
        authorized = TRUE;
    }
    else
    {
        for (i = 0 ; (i < projectConfig->sendersCount) && !authorized ; i++) {
            irc = strcmp(projectConfig->senders[i], sender);
#ifdef LDAP_VERIFY
            if (NULL != configParm && irc == 0) {		/* found the sender in the list of authorized senders */
                ldaprc = ldapLookupByEmail(configParm, projectConfig->senderemails[i],
                                           NULL, (bool)verbose);
                // Make sure we found at least one matching entry
                if (ldaprc == 0) {
                    irc = 1;
                }
            }
#endif
            if (irc == 0) {
                if (verbose) fprintf(messageFile,
                                     "ProjectConfig_ValidateSender: "
                                     "Sender %s is authorized\n", sender);
                authorized = TRUE;
            }
        }
    }
    if (!authorized) {
        if (verbose) fprintf(messageFile,
                             "ProjectConfig_ValidateSender: "
                             "%u senders, sender %s is not authorized\n",
                             (unsigned int)projectConfig->sendersCount, sender);
        rc = ERROR_CODE;
    }
    return rc;
}

/* Comment_Validate() validates and possibly sanitizes the request comment

   Legal characters are printable

   Illegal characters are replaced with ?

   Returns ERROR_CODE on error and logs to the framework log
*/

int Comment_Validate(DropboxRequest *requestParms)
{
    int		rc = 0;
    size_t	i;
    int		foundError = FALSE;

    /* Do this even if there were previous errors.  Screen the comment for illegal characters,
       sanitize the output */
    for (i = 0 ; i < strlen(requestParms->comment) ; i++) {
        if (!isprint(requestParms->comment[i]))  {	/* non-printable characters */
            requestParms->comment[i] = '?';		/* sanitize with ? character */
            if (!foundError) {		/* log the first error */
                File_Printf(requestParms->frameworkConfig->frameworkLogFile, messageFile,
                            "ERROR0029: comment has invalid character at index %u\n",
                            i);
                foundError = TRUE;
                rc = ERROR_CODE;
            }
        }
    }
    /* on error log the sanitized subject */
    if (rc != 0) {
        File_Printf(requestParms->frameworkConfig->frameworkLogFile, messageFile,
                    "ERROR0030: Sanitized subject is %s\n",
                    requestParms->comment);
    }

    return rc;
}

/* Env_Validate() validates that all required environment variables are set

 */

int Env_Validate()
{
    int		rc = 0;

    return rc;
}

/*
  Password Crypto
*/

/* Password_KDF() uses the master AES key and the user email address to derive the password
   encryption key and authentication key.

   The caller should erase the keys when done.

   The algorithm is:

   encryption key EKU = AES with master key MKC (sender email address || 0)
   encryption key AKU msb = AES with master key MKC (sender email address || 1)
   encryption key AKU lsb = AES with master key MKC (sender email address || 2)

   In each case, take the last 128 bits/ 16 bytes.  That's because sender email addresses could be
   common in the first bytes.  Since the IV is constant, the first bytes of the keys could be the
   same.
*/

int Password_KDF(unsigned char *eku,			/* preallocated 16 bytes, 128 bits */
                 unsigned char *aku,			/* preallocated 32 bytes, 256 bits */
                 const char *sender,
                 const unsigned char *masterAesKeyToken)
{
    int			rc = 0;

    unsigned char 	initialization_vector[IV_SIZE];
    unsigned char 	*cleartext = NULL;	/* freed @1 */
    unsigned char 	*ciphertext = NULL;	/* freed @2 */
    long		cleartext_length;
    long 		ciphertext_length;

    /* cannot modify 'sender', so make a copy.  The NUL terminator will be replaced by the 0,1,2 */
    if (rc == 0) {
        memset(initialization_vector, 0, IV_SIZE);
        cleartext_length = strlen(sender) + 1;
        rc = Malloc_Safe(&cleartext, cleartext_length, cleartext_length);	/* freed @1 */
    }
    if (rc == 0) {
        strcpy((char *)cleartext, sender);
    }
    /* EKU */
    if (rc == 0) {
        cleartext[cleartext_length-1] = 0;
        rc = Symmetric_Algorithm_Encipher(&ciphertext_length,
                                          &ciphertext,		/* freed @2 */
                                          cleartext_length,
                                          cleartext,
                                          initialization_vector,
                                          masterAesKeyToken);
    }
    if (rc == 0) {
        memcpy(eku, ciphertext + ciphertext_length - AES128_SIZE, AES128_SIZE);
        /* ciphertext is part of a secret key, clear before free */
        memset(ciphertext, 0, ciphertext_length);
        free(ciphertext);					/* @2 */
        ciphertext = NULL;
    }
    /* AKU msb */
    if (rc == 0) {
        cleartext[cleartext_length-1] = 1;
        rc = Symmetric_Algorithm_Encipher(&ciphertext_length,
                                          &ciphertext,		/* freed @2 */
                                          cleartext_length,
                                          cleartext,
                                          initialization_vector,
                                          masterAesKeyToken);
    }
    if (rc == 0) {
        memcpy(aku, ciphertext + ciphertext_length - AES128_SIZE, AES128_SIZE);
        /* ciphertext is part of a secret key, clear before free */
        memset(ciphertext, 0, ciphertext_length);
        free(ciphertext);					/* @2 */
        ciphertext = NULL;
    }
    /* AKU lsb */
    if (rc == 0) {
        cleartext[cleartext_length-1] = 2;
        rc = Symmetric_Algorithm_Encipher(&ciphertext_length,
                                          &ciphertext,		/* freed @2 */
                                          cleartext_length,
                                          cleartext,
                                          initialization_vector,
                                          masterAesKeyToken);
    }
    if (rc == 0) {
        memcpy(aku + AES128_SIZE, ciphertext + ciphertext_length - AES128_SIZE, AES128_SIZE);
        /* ciphertext is part of a secret key, clear before free */
        memset(ciphertext, 0, ciphertext_length);
        free(ciphertext);					/* @2 */
        ciphertext = NULL;
    }
    /* cleartext is just the sender, not a secret, so it does not have to be cleared */
    free(cleartext);		/* @1 */
    free(ciphertext);		/* @2 */

    return rc;
}

#define RANDOM_CHUNK 8		/* get 8 bytes from rng at a time */

/* Password_Generate() generates a strong password.  The password is graphic characters with a NUL
   terminator
*/

int Password_Generate(char *password,
                      size_t password_length)	/* including space for NUL terminator */
{
    int			rc = 0;

    size_t		i = 0;		/* password character iterator */
    size_t		j;		/* get 8 bytes from rng at a time */
    unsigned char	random_number[RANDOM_CHUNK ];
    int			rand_int;

    password[password_length-1] = '\0';
    while ((rc == 0) && (i < (password_length-1))) {	/* -1 for NUL terminator */

        /* get a new chunk of random numbers */
        rc =  Random_Number_Generate_Long(random_number, RANDOM_CHUNK);

        /* process the chunk */
        for (j = 0 ; (rc == 0) && (j < RANDOM_CHUNK) ; j++) {

            rand_int = random_number[j];
            if (isgraph(rand_int)) {		/* use only graphic characters, no white space */
                password[i] = random_number[j];
                i++;
                if (i == (password_length-1)) {	/* done, terminate j loop */
                    break;
                }
            }
        }
    }

    return rc;
}

/* Password_ToString() creates the actual password string that the sender puts in the email body.
   It consists of the concatenation of:

   Initialization vector[16] || HMAC[32] || Encrypted Password
*/

int Password_ToString(char 		**passwordString,	/* freed by caller */
                      size_t		*passwordStringLength,	/* not including NUL terminator */
                      unsigned char 	*initialization_vector,
                      unsigned char 	*hmac,
                      unsigned char 	*passwordCiphertext,
                      size_t		passwordCiphertextLength)
{
    int			rc = 0;

    /* allocate the entire string length */
    if (rc == 0) {
        *passwordStringLength = ((IV_SIZE + HMAC_SIZE + passwordCiphertextLength) * 2);
        rc = Malloc_Safe((unsigned char **)passwordString,
                         (*passwordStringLength) + 1,
                         (*passwordStringLength) + 1);
    }
    if (rc == 0) {
        /* Format_ToHexascii() converts binary to hex ascii and appends a NUL terminator.  All but
           the last NUL is overwritten */
        /* Initialization vector */
        Format_ToHexascii(*passwordString,
                          initialization_vector, IV_SIZE);
        /* HMAC */
        Format_ToHexascii((*passwordString) + (IV_SIZE * 2),
                          hmac, HMAC_SIZE);
        /* Encrypted Password */
        Format_ToHexascii((*passwordString) + ((IV_SIZE + HMAC_SIZE) * 2),
                          passwordCiphertext, passwordCiphertextLength);
    }
    return rc;
}

/* Password_FromString() cracks the passwordString of length passwordStringLength (not including NUL
   terminator) and returns

   Initialization vector[16]
   HMAC[32]
   Encrypted Password
*/

int Password_FromString(unsigned char 	*initialization_vector,
                        unsigned char 	*hmac,
                        unsigned char 	**passwordCiphertext,	/* freed by caller */
                        size_t		*passwordCiphertextLength,
                        const char 	*passwordString,
                        size_t		passwordStringLength,
                        FILE 		*logFile)
{
    int			rc = 0;

    /* there must be at least enough characters for the IV and HMAC */
    if (rc == 0) {
        if ((passwordStringLength/2) < (size_t)(IV_SIZE + HMAC_SIZE)) {
            File_Printf(logFile, messageFile,
                        "ERROR0032: Encrypted password is too small\n");
            rc = ERROR_CODE;
        }
    }
    if (rc == 0) {
        /* after the IV and HMAC, the rest are the password characters */
        *passwordCiphertextLength = ((passwordStringLength) / 2) - IV_SIZE - HMAC_SIZE;
        rc = Malloc_Safe(passwordCiphertext, *passwordCiphertextLength, *passwordCiphertextLength);
    }
    /* Initialization vector */
    if (rc == 0) {
        rc = Format_FromHexascii(initialization_vector,
                                 passwordString, IV_SIZE);
    }
    /* HMAC */
    if (rc == 0) {
        rc = Format_FromHexascii(hmac,
                                 passwordString + (IV_SIZE * 2), HMAC_SIZE);
    }
    /* Encrypted Password */
    if (rc == 0) {
        rc = Format_FromHexascii(*passwordCiphertext,
                                 passwordString + ((IV_SIZE + HMAC_SIZE) * 2),
                                 *passwordCiphertextLength);
    }
    return rc;
}

/* Password_Decrypt() adds the decrypted password to argv

   The encrypted password is pulled from the argv.

   The master AES key token was saved on disk as a one time operation during framework installation.
*/

int Password_Decrypt(Arguments			*arguments,
                     const char 		*sender,
                     const unsigned char 	*masterAesKeyToken,
                     FILE			*logFile)
{
    int			rc = 0;
    const char 		*passwordString = NULL;		/* combined IV, HMAC, encrypted pwd */
    size_t		passwordStringLength;
    unsigned char 	initialization_vector[IV_SIZE];
    unsigned char 	hmac[HMAC_SIZE];
    unsigned char 	*ciphertext = NULL;	/* in binary, freed @1 */
    long 		ciphertext_length;
    size_t		cleartext_length;
    unsigned char 	*cleartext = NULL;	/* freed @2 */
    int 		hmac_valid;
    unsigned char 	eku[AES128_SIZE];		/* password encryption key */
    unsigned char 	aku[AKU_SIZE];		/* password authentication HMAC key */

    /* pull the encrypted password from argv, in hex ASCII */
    if (rc == 0) {
        rc = Arguments_GetFrom(&passwordString, "-epwd",
                               arguments);
        if (rc != 0) {
            File_Printf(logFile, messageFile,
                        "ERROR0031: Email missing -epwd\n");
        }
    }
    if (rc == 0) {
        passwordStringLength = strlen(passwordString);
        if (verbose) fprintf(messageFile, "Password_Decrypt: encrypted password length %u\n",
                             (unsigned int)passwordStringLength);
        if (verbose) fprintf(messageFile, "Password_Decrypt: encrypted password %s\n",
                             passwordString);
    }
    /* convert the hex ASCII back to IV, HMAC, and encrypted password in binary */
    if (rc == 0) {
        if (verbose) fprintf(messageFile, "Password_Decrypt: Convert back to binary\n");
        rc = Password_FromString(initialization_vector,
                                 hmac,
                                 &ciphertext,	/* freed @1 */
                                 (size_t *)&ciphertext_length,
                                 passwordString,
                                 passwordStringLength,
                                 logFile);
        if (rc == 0) {
            if (verbose) PrintAll(messageFile,
                                  "initialization_vector",
                                  IV_SIZE, initialization_vector);
            if (verbose) PrintAll(messageFile,
                                  "HMAC", HMAC_SIZE, hmac);
            if (verbose) PrintAll(messageFile,
                                  "Encrypted password", ciphertext_length, ciphertext);
        }
        else {
            File_Printf(logFile, messageFile,
                        "ERROR0032: Encrypted password has an illegal format\n");
        }
    }
    /* derive the encryption key (eku) and authentication HMAC key (aku) from the sender and the
       master AES key */
    if (rc == 0) {
        if (verbose) fprintf(messageFile, "Password_Decrypt: Deriving decryption and HMAC keys\n");
        rc = Password_KDF(eku,		/* user encryption key */
                          aku,		/* user authentication HMAC key */
                          sender,	/* user */
                          masterAesKeyToken);
        if (rc != 0) {
            File_Printf(logFile, messageFile,
                        "ERROR0033: deriving the password decryption and HMAC keys\n");
            fprintf(messageFile,
                    "Contact framework administrator\n");
        }
    }
    /* validate the converted authentication HMAC */
    if (rc == 0) {
        if (verbose) fprintf(messageFile, "Password_Decrypt: Checking HMAC\n");
        Ossl_HMAC_Check(&hmac_valid,
                        hmac,
                        aku,		/* HMAC key */
                        ciphertext_length,
                        ciphertext,
                        0, NULL);
        if (!hmac_valid) {
            File_Printf(logFile, messageFile,
                        "ERROR0034: Password HMAC failed, the password is corrupt\n");
            rc = ERROR_CODE;
        }
    }
    if (rc == 0) {
        if (verbose) fprintf(messageFile, "Password_Decrypt: HMAC is valid\n");
    }
    /* decrypt the password - use the recovered IV and the derived encryption key (eku) */
    if (rc == 0) {
        rc = Ossl_AES_Decrypt(&cleartext,	/* freed @2 */
                              &cleartext_length,
                              ciphertext,
                              ciphertext_length,
                              initialization_vector,
                              eku);
        if (rc != 0) {
            File_Printf(logFile, messageFile,
                        "ERROR0035: decrypting the encrypted password\n");
            fprintf(messageFile,
                    "Contact framework administrator\n");
        }
    }
    /* validate the password */
    if (rc == 0) {
#if 0	/* NOTE:  This trace cannot be in the final product, since it leaks the user password */
        /* trace as text */
        if (verbose) fprintf(messageFile, "Password_Decrypt: Password %.*s\n",
                             cleartext_length, cleartext);
        /* trace as binary */
        if (verbose) PrintAll(messageFile,
                              "Password_Decrypt: Decrypted password",
                              cleartext_length, cleartext);
#endif
        if (strlen((char *)cleartext) != (cleartext_length - 1)) {
            if (verbose) fprintf(messageFile, "strlen %u\n", (unsigned int)strlen((char *)cleartext));
            if (verbose) fprintf(messageFile, "cleartext_length %u\n", (unsigned int)cleartext_length);
            File_Printf(logFile, messageFile,
                        "ERROR0037: Password decrypt failed, length error\n");
            fprintf(messageFile,
                    "Contact framework administrator\n");
            rc = ERROR_CODE;
        }
    }
    /* add the CCA password to the argv  */
    if (rc == 0) {
        rc = Arguments_AddPairTo(arguments,
                                 "-pwd",
                                 (char *)cleartext);
        if (rc != 0) {
            File_Printf(logFile, messageFile,
                        "ERROR0038: adding -pwd to command line arguments\n");
        }
    }
    /* this is encrypted, no need to erase */
    free(ciphertext);		/* @1 */
    /* erase the cleartext password */
    if (cleartext != NULL) {
        memset(cleartext, 0, cleartext_length);
    }
    free(cleartext);		/* @2 */
    /* erase the secret keys */
    memset(eku, 0, AES128_SIZE);
    memset(aku, 0, AKU_SIZE);
    return rc;
}

/* CallSigner() calls the signer program.

   If 'useOutputBody' is TRUE (the normal case), the output body is used as the messageFile once the
   child process returns.  If it is FALSE (the start up probe case), messageFile not changed, and
   will remain pointing to stdout.  This permits start up errors to be displayed to the user.

   The standard command line arguments are:

   0: Name of the program being invoked

   1: -obody
   2: output email body file name

   ...This pair is intentionally the first parameter set.  The called program should open this file
   for append ASAP, so that all errors will be put in the file.  This includes errors in other
   command line arguments.

   3: -sender
   4: email sender

   5-n: These arguments are copied from the input email body

   -log filename: The name of the file used for a program specific audit log.  The parameter pair
   will always be present but may be ignored by the program.

   -key filename: The name of the file containing the project singing key.  This parameter pair will
   not be present if the project configuration file indicates that no key is needed.

   -di filename: The name of the file containing the input attachment.  This parameter pair
   will not be present if the project configuration file indicates that no input attachment is
   needed.

   -do filename: The name of the file to place the output attachment.  This parameter pair
   will not be present if the project configuration file indicates that no output attachment is
   needed.

   -pwd password: The plaintext password as decrypted by the framework.  This parameter pair will
   not be present if the project configuration file indicates that no password is needed.
*/

int CallSigner(Arguments	*arguments,
               int		useOutputBody,
               const char 	*outputBodyFilename)
{
    int		rc = 0;
    pid_t	childPid;	/* pid of signer program */
    pid_t	wrc;
    int		childRc;	/* return code from signer program */

    /* Sanity checks on arguments.  There are most likely fatal errors. */
    if (arguments->argv[0] == NULL) {
        if (verbose) fprintf(messageFile, "CallSigner: Error, calling NULL program\n");
        rc = RESPONSE_BODY_ONLY;
    }
    if (arguments->argv[arguments->argc] != NULL) {
        if (verbose) fprintf(messageFile, "CallSigner: Error, argv and argc inconsistent\n");
        rc = RESPONSE_BODY_ONLY;
    }
    if (rc == 0) {
        if (verbose) fprintf(messageFile, "CallSigner: Calling: %s\n", arguments->argv[0]);
    }
    /* create a child process that will exec() to the signer program */
    /* must fflush the stream before the fork, else get duplicate streams to the output */
    fflush(messageFile);
    childPid = fork();
    /* check that the child process started */
    if (childPid < 0) {
        if (verbose) fprintf(messageFile, "CallSigner: Error, fork failed\n");
        if (verbose) fprintf(messageFile, "CallSigner: Error, %s\n", strerror(errno));
    }
    /*
      child - fork() returns 0 for the child process
    */
    else if (childPid == 0) {
        if (verbose) fprintf(messageFile, "CallSigner: Child\n");
        /* close the message file since the signer specific program may use it */
        File_CloseMessageFile();
        /* NOTE: From here down, no printing to messageFile until unless the exec returns with
           an error.  The child will reopen the file later. */
        /* start the specific signer program for the project */
        /* int execv(const char *path, char *const argv[]); */
        execv(arguments->argv[0], arguments->argv);
        /* The code only gets here if the program cannot be called.  Any return from exec() is an
           error */

        /* reopen the messages file and append child errors */
        if ((rc == 0) && useOutputBody)  {
            rc = File_OpenMessageFile(outputBodyFilename, "a");
        }
        if (rc == 0) {
            fprintf(messageFile, "ERROR0039: child process could not run program: %s\n",
                    arguments->argv[0]);
            fprintf(messageFile, "ERROR0039: %s\n", strerror(errno));
            /* close the message file since the parent may use it */
            File_CloseMessageFile();
        }
        /* if the child exec's, it will not return.  If the exec fails, returning here would cause
           two process to continue.  Therefore, must exit.  This lets the parent (and only the
           parent) continue.  */
        exit(1);
    }
    /*
      parent
    */
    else {
        /* NOTE: From here down, no printing to messageFile until child returns. */
        /* parent waits for the child signer program to complete.  The call to wait() gets the
           return code for the exec'ed child process */
        wrc = wait(&childRc);
        /* once the child is complete, reopen the messages file and append */
        if ((rc == 0) && useOutputBody)  {
            rc = File_OpenMessageFile(outputBodyFilename, "a");
        }
        if (verbose) fprintf(messageFile, "CallSigner: Parent, child is pid %d\n", childPid);
        if (verbose) fprintf(messageFile, "CallSigner: wrc %d childRc %d\n", wrc, childRc);
        if (rc == 0) {
            if (wrc == -1) {
                fprintf(messageFile, "ERROR0041: parent error waiting for child process %s\n",
                        strerror(errno));
                rc = RESPONSE_BODY_ONLY;
            }
        }
        if (rc == 0) {
            /* WIFEXITED returns true if the child terminated normally */
            if (WIFEXITED(childRc)) {
                /* WEXITSTATUS returns the exit status of the child.  This consists of the least
                   significant 16-8 bits of the status argument that the child specified in a call
                   to exit() or _exit() or as the argument for a return statement in main().  This
                   macro should only be employed if WIFEXITED returned true. */
                rc = WEXITSTATUS(childRc);
                if (verbose) fprintf(messageFile, "CallSigner: program return code %d\n", rc);
            }
            else if (WIFSIGNALED(childRc)) {
                fprintf(messageFile, "ERROR0042: Child process %s exited with signal = %d\n",
                        arguments->argv[0], WTERMSIG(childRc));
#ifdef  WCOREDUMP
                if (WCOREDUMP(childRc)) {
                    fprintf(messageFile, "CallSigner: ERROR0043: %s produced core dump\n",
                            arguments->argv[0]);
                }
#endif
                rc = RESPONSE_BODY_ONLY;
            }
            else {
                fprintf(messageFile,
                        "ERROR0044: Child process %s exited abnormally\n", arguments->argv[0]);
                rc = RESPONSE_BODY_ONLY;
            }
        }
    }
    return rc;
}
