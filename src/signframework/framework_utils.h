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

#ifndef FRAMEWORK_UTILS_H
#define FRAMEWORK_UTILS_H
#include <json/json.h>

#include "utils.h"


/* maximum size of a framework configuration file, for the malloc sanity check */
#define MAX_CONFIG 64000
/// Maximum number of dropbox directories to watch (max num of unique signers)
#define MAX_WATCHERS 30
/// Maximum char length of signers userid
#define MAX_USERNAME 30

/* Crypto constants */

/* password encryption key, encryption blocks, uses AES 128 */
#define AES128_SIZE 16
/* password HMAC key, uses SHA-256 */
#define AKU_SIZE 32
/* password HMAC is the same size as the HMAC key, SHA-256 */
#define HMAC_SIZE 32
/* encryption and KDF initialization vector, uses AES 128 */
#define IV_SIZE 16
/* digest for logging, uses SHA-256 */
#define DIGEST_SIZE 32

/*
  ProjectConfig represents a project configuration file.
*/

typedef struct tdProjectConfig {
    unsigned char	digest[DIGEST_SIZE];
    char		*program;
    char		*projectLogFilename;
    int			needKey;
    char 		*keyFilename;
    int			needAuxCfg;
    char 		*auxCfgFilename;
    int			needInputAttachment;
    int 		needOutputAttachment;
    int 		needPassword;
    char		*emailProject;
    int 		needSenders;		/* project uses sender authorization */
    size_t 		sendersCount;		/* number of authorized senders */
    char 		**senders;		/* array of authorized sender dropbox ids */
    char        **senderemails; /* array of associated sender email addresses */
    size_t		notificationListCount;	/* number of notification receivers */
    char		**notificationList;	/* array of notification names */
    Arguments   additionalArgs;     /* Additional sign tool arguments specified in project config */
} ProjectConfig;

/// Status/configuration information for a dropbox
typedef struct tdDropboxWatchConfig
{
    char       sender[MAX_USERNAME];    ///< Sender id
    int        wd;        ///< Watch descriptor
} DropboxWatchConfig;

/*
  FrameworkConfig represents the entire framework, the parsed and validated framework and project
  configuration files.
*/

typedef struct tdFrameworkConfig {
    const char		*frameworkConfigFilename;
    char        *frameworkName;         /* Name to refer to framework */
    char 		*frameworkLogFilename;	/* framework audit log */
    FILE 		*frameworkLogFile;	/* framework audit log */
    unsigned char	digest[DIGEST_SIZE];
    size_t		lineMax;		/* maximum line length in text parsing */
    size_t      fileMax;        ///< Maximum upload file size
    unsigned int 	passwordExpire;		/* CCA password expiration duration in months */
    char        *dropboxDir;    /* Base directory of signer dropboxes */
    char		*stopFile;		/* file used to stop the framework */
    char		*restartFile;		/* file used to restart the framework */
    char		*outputBodyFilename;	/* output body, response to sender */
    char 		*notificationFilename;	/* output notification response */
    char        *emailFilename; /* file to write email to send */
    char		*inputAttachmentFilename;	/* fixed names for the input and output
							   attachments */
    char		*outputAttachmentFilename;
    char		*masterAesKeyTokenFilename;
    unsigned char 	*masterAesKeyToken;	/* the CCA AES master key token used to derive the
						   password encryption and HMAC keys (not the
						   plaintext AES key)*/
    char        *ldapUrl;               /* LDAP url for lookup */
    char        *ldapBase;              /* LDAP BASEDN for search */
    size_t		frameworkAdminCount;	/* number framework administrators */
    char 		**frameworkAdmins;	/* array of framework administrators */
    size_t 		projectLength;		/* number of project to config file mappings */
    char 		**projectNames;			/* array of project names */
    char 		**projectConfigFilenames;	/* array of project config file names */
    ProjectConfig	**projectConfigFiles;		/* array of project config files */
    int         inotifyFd;   ///< inotify file descriptor
    int         controlWd;   ///< Stop/restart file watcher
    DropboxWatchConfig dropboxWatchers[MAX_WATCHERS];  ///< array of dropbox watchers
} FrameworkConfig;

/// Store all relevant info for a unique dropbox request
typedef struct tdDropboxRequest {
    FrameworkConfig*      frameworkConfig;
    int                   status;    ///< Request status

    struct inotify_event* event;     ///< Inotify event
    DropboxWatchConfig*   dbConfig;  ///< Signers dropbox configuration
    char*                 requestId; ///< Unique identifier for request
    char*                 requestJson; ///< Json request from sender
    json_object*          rJsonO;

    // Request fields
    const char*           project;
    char*                 comment;
    const char*           user;
    const char*           epwd;
    int                   hasPayload;
    const char*           parameters;

    json_object*          respJsonO; ///< Response JSON
    int                   hasResult;

    int		closeMessageFile;	/* hack to keep the messageFile (output body) open when
					   sending notifications.  If closed, trace messages would
					   start to go to stdout */

} DropboxRequest;

void FrameworkConfig_Init(FrameworkConfig *frameworkConfig);
void FrameworkConfig_Delete(FrameworkConfig *frameworkConfig);
int  FrameworkConfig_Parse(int needMasterKey,
			   int validate,
			   FrameworkConfig *frameworkConfig);
int  FrameworkConfig_LogStart(FrameworkConfig *frameworkConfig);
int  FrameworkConfig_SendStartupMessage(FrameworkConfig *frameworkConfig,
					int transientError);

/*
  Framework Processing
*/

int  FrameworkProcess_Process(DropboxRequest *requestParms);
int  FrameworkProcess_ProcessOK(DropboxRequest *requestParms);

int  FrameworkProcess_SendResponse(int responseType,
                                   DropboxRequest *requestParms);
int  FrameworkProcess_SendNotificationMessage(const char *project,
                                              ProjectConfig *projectConfig,
                                              DropboxRequest *mailParms);


/*
  Project Configuration
*/

void ProjectConfig_Init(ProjectConfig *projectConfig);
void ProjectConfig_Delete(ProjectConfig *projectConfig);
int  ProjectConfig_Parse(ProjectConfig *projectConfig,
                         int validate,
                         const char *projectConfigFilename,
                         FrameworkConfig *frameworkConfig);
int  ProjectConfig_Process(Arguments	*arguments,
                           ProjectConfig *projectConfig,
                           DropboxRequest *requestParms);
int  ProjectConfig_ValidateSender(const char *sender,
                                  ProjectConfig *projectConfig,
                                  FrameworkConfig *frameworkConfig);
int  ProjectProcess_ProcessInputParameters(Arguments *arguments,
                                           DropboxRequest *requestParms);

int Comment_Validate(DropboxRequest *requestParms);
int Env_Validate(void);


int Password_KDF(unsigned char *eku,
		 unsigned char *aku,
		 const char *sender,
		 const unsigned char *masterAesKeyToken);
int Password_Generate(char *password,
		      size_t password_length);
int Password_ToString(char 		**passwordString,
		      size_t		*passwordStringLength,
		      unsigned char 	*initialization_vector,
		      unsigned char 	*hmac,
		      unsigned char 	*passwordCiphertext,
		      size_t		passwordCiphertextLength);
int Password_FromString(unsigned char 	*initialization_vector,
			unsigned char 	*hmac,
			unsigned char 	**passwordCiphertext,
			size_t		*passwordCiphertextLength,
			const char	*passwordString,
			size_t		passwordStringLength,
			FILE 		*logFile);
int Password_Decrypt(Arguments			*arguments,
		     const char 		*sender,
		     const unsigned char 	*masterAesKeyToken,
		     FILE			*logFile);

int CallSigner(Arguments	*arguments,
	       int		useOutputBody,
	       const char 	*outputBodyFilename);



#endif
