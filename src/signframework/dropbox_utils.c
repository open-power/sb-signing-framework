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

#include <sys/inotify.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/inotify.h>
#include <unistd.h>

#include "dropbox_utils.h"
#include "framework_utils.h"

extern FILE* messageFile;
extern int verbose;

// Local functions
DropboxWatchConfig* getConfigByUserid(FrameworkConfig *frameworkConfig, const char* userid);
DropboxWatchConfig* getConfigByWd(FrameworkConfig *frameworkConfig, int wd);
int addDropboxWatcher(FrameworkConfig *frameworkConfig, const char* userid);
/// Display information about the incoming event
void displayInotifyEvent(struct inotify_event *i);
void dropboxRequestInit(DropboxRequest* request, FrameworkConfig *frameworkConfigParm);
void dropboxRequestClear(DropboxRequest* request);
int readRequest(FrameworkConfig *frameworkConfig, DropboxRequest* request);
int JS_ObjectGetString(const char **string,
                       const char *key,
                       json_object *object);
/* Array_Scan() converts a string to a binary array */
int Array_Scan(unsigned char **data,   /* output binary, freed by caller */
               size_t *len,
               const char *string);    /* input string */
char nibbleToChar(unsigned char nibble);
struct json_object* binaryFileToJsonObject(FILE* fp);


void dropboxRequestInit(DropboxRequest* request, FrameworkConfig *frameworkConfigParm)
{
    memset(request, 0, sizeof(DropboxRequest));
    request->frameworkConfig = frameworkConfigParm;
}
void dropboxRequestClear(DropboxRequest* request)
{
    if (request->requestId != NULL) free(request->requestId);
    if (request->rJsonO != NULL) json_object_put(request->rJsonO);
    if (request->requestJson != NULL) free(request->requestJson);

    if (request->comment != NULL) free(request->comment);
    if (request->respJsonO != NULL) json_object_put(request->respJsonO);

}


DropboxWatchConfig* getConfigByUserid(FrameworkConfig *frameworkConfig, const char* userid)
{
    int i;
    for (i = 0; i < MAX_WATCHERS; i ++) {
        if (frameworkConfig->dropboxWatchers[i].wd != 0 &&
            !strcmp(frameworkConfig->dropboxWatchers[i].sender, userid)) {
            return &(frameworkConfig->dropboxWatchers[i]);
        }
    }
    return NULL;
}

DropboxWatchConfig* getConfigByWd(FrameworkConfig *frameworkConfig, int wd)
{
    int i;
    for (i = 0; i < MAX_WATCHERS; i ++) {
        if (frameworkConfig->dropboxWatchers[i].wd == wd) {
            return &(frameworkConfig->dropboxWatchers[i]);
        }
    }
    return NULL;
}

int addDropboxWatcher(FrameworkConfig *frameworkConfig, const char* userid)
{
    int rc = 0;
    int idx = 0;
    int i;

    if (verbose) fprintf(messageFile,
                         "addDropboxWatcher: Adding new dropbox watcher for user : %s\n", userid);

    // Find an emtpy spot
    idx = MAX_WATCHERS;
    for (i = 0; i < MAX_WATCHERS; i ++) {
        if (frameworkConfig->dropboxWatchers[i].wd == 0) {
            idx = i;
            break;
        }
    }
    if (idx == MAX_WATCHERS) {
        fprintf(messageFile,
                "addDropboxWatcher: Number of signers exceeds max %d\n", MAX_WATCHERS);
        rc = 1;
    }
    if (strlen(userid) > MAX_USERNAME-1) {
        fprintf(messageFile,
                "addDropboxWatcher: String length of signer userid '%s' exceeds max %d\n",
                userid, MAX_USERNAME-1);
        rc = 1;
    }

    if (rc == 0) {
        // Construct the dropbox dir
        char* dir = malloc(strlen(frameworkConfig->dropboxDir) + strlen(userid) + 5);
        sprintf(dir, "%s/%s", frameworkConfig->dropboxDir, userid);

        if (verbose) fprintf(messageFile,
                             "addDropboxWatcher: Dropbox location : %s\n", dir);

        strcpy(frameworkConfig->dropboxWatchers[idx].sender, userid);
        // Setup the notify watcher to look for files created in the dropbox
        frameworkConfig->dropboxWatchers[idx].wd = inotify_add_watch(frameworkConfig->inotifyFd,
                                                                     dir, IN_CREATE);
        if (frameworkConfig->dropboxWatchers[idx].wd < 0) {
            fprintf(messageFile,
                    "addDropboxWatcher: Failed to add inotify watch for : %s\n", userid);
            perror("addDropboxWatcher: Failed to add inotify watch");
            // Ignore this failure as there may be signers listed in
            // configuration that haven't been setup yet
            //rc = 1;
        }
        free(dir);
    }

    return rc;
}

int dropboxInit(FrameworkConfig *frameworkConfig)
{
    int rc = 0;
    size_t p,s;

    frameworkConfig->inotifyFd = inotify_init();
    if (frameworkConfig->inotifyFd < 0) {
        fprintf(messageFile,
                "dropboxInit: Inotify_init failed\n");
        rc = 1;
    }
    if (verbose)
        fprintf(messageFile, "dropboxInit: inotify FD %d\n", frameworkConfig->inotifyFd);

    // Add control file watcher
    if (rc == 0) {
        frameworkConfig->controlWd = inotify_add_watch(frameworkConfig->inotifyFd,
                                                       frameworkConfig->dropboxDir, IN_CREATE);
        if (frameworkConfig->controlWd < 0) {
            fprintf(messageFile,
                    "addDropboxWatcher: Failed to add controlfile inotify watch\n");
            perror("addDropboxWatcher: Failed to add controlfile inotify watch");
            rc = 1;
        }
    }

    if (rc == 0) {
        // Walk through the authorized senders and setup a dropbox
        for (p = 0; p < frameworkConfig->projectLength; p ++) {
            for (s = 0; s < frameworkConfig->projectConfigFiles[p]->sendersCount; s++) {
                // Set one up if there isn't one already
                if (NULL == getConfigByUserid(frameworkConfig, frameworkConfig->projectConfigFiles[p]->senders[s])) {
                    rc = addDropboxWatcher(frameworkConfig, frameworkConfig->projectConfigFiles[p]->senders[s]);
                }
                if (rc != 0) break;
            }
            if (rc != 0) break;
        }
    }

    return rc;
}

int dropboxShutdown(FrameworkConfig *frameworkConfig)
{
    int rc = 0;
    int i;

    if (verbose) {
        fprintf(messageFile, "Shutting down dropbox\n");
    }

    if (frameworkConfig->inotifyFd > 0)
    {
        // Remove the stop/restart watchers
        inotify_rm_watch(frameworkConfig->inotifyFd,frameworkConfig->controlWd);

        // Remove the signer dropbox watchers
        for (i = 0; i < MAX_WATCHERS; i ++) {
            if (frameworkConfig->dropboxWatchers[i].wd != 0) {
                inotify_rm_watch(frameworkConfig->inotifyFd,
                                 frameworkConfig->dropboxWatchers[i].wd);
                frameworkConfig->dropboxWatchers[i].sender[0] = '\0';
                frameworkConfig->dropboxWatchers[i].wd = 0;
            }
        }

        close(frameworkConfig->inotifyFd);
        frameworkConfig->inotifyFd = 0;
    }
    return rc;
}


void displayInotifyEvent(struct inotify_event *i)
{
    fprintf(messageFile, "    wd =%2d; ", i->wd);
    if (i->cookie > 0)
        fprintf(messageFile, "cookie =%4d; ", i->cookie);

    fprintf(messageFile, "mask = ");
    if (i->mask & IN_ACCESS)        fprintf(messageFile, "IN_ACCESS ");
    if (i->mask & IN_ATTRIB)        fprintf(messageFile, "IN_ATTRIB ");
    if (i->mask & IN_CLOSE_NOWRITE) fprintf(messageFile, "IN_CLOSE_NOWRITE ");
    if (i->mask & IN_CLOSE_WRITE)   fprintf(messageFile, "IN_CLOSE_WRITE ");
    if (i->mask & IN_CREATE)        fprintf(messageFile, "IN_CREATE ");
    if (i->mask & IN_DELETE)        fprintf(messageFile, "IN_DELETE ");
    if (i->mask & IN_DELETE_SELF)   fprintf(messageFile, "IN_DELETE_SELF ");
    if (i->mask & IN_IGNORED)       fprintf(messageFile, "IN_IGNORED ");
    if (i->mask & IN_ISDIR)         fprintf(messageFile, "IN_ISDIR ");
    if (i->mask & IN_MODIFY)        fprintf(messageFile, "IN_MODIFY ");
    if (i->mask & IN_MOVE_SELF)     fprintf(messageFile, "IN_MOVE_SELF ");
    if (i->mask & IN_MOVED_FROM)    fprintf(messageFile, "IN_MOVED_FROM ");
    if (i->mask & IN_MOVED_TO)      fprintf(messageFile, "IN_MOVED_TO ");
    if (i->mask & IN_OPEN)          fprintf(messageFile, "IN_OPEN ");
    if (i->mask & IN_Q_OVERFLOW)    fprintf(messageFile, "IN_Q_OVERFLOW ");
    if (i->mask & IN_UNMOUNT)       fprintf(messageFile, "IN_UNMOUNT ");
    fprintf(messageFile, "\n");

    if (i->len > 0)
        fprintf(messageFile, "        name = %s\n", i->name);
}

int processEvent(FrameworkConfig *frameworkConfig, struct inotify_event *i,
                 int* stop, int* restart)
{
    int rc = 0;
    char* pos = NULL;
    char* filename = NULL;
    DropboxRequest request;


    if (verbose) displayInotifyEvent(i);

    DropboxWatchConfig* db = getConfigByWd(frameworkConfig, i->wd);

    if (strlen(i->name) > 100) {
        fprintf(messageFile, "WARNING : Saw large filename dropped in dropbox, len %d\n",
                (int)strlen(i->name));

    // Was the event from a signers dropbox ?
    } else if (db != NULL) {

        // Ignore anything but a request.go file
        pos = strstr(i->name, ".request.go");
        if (pos != NULL) {
            // Open message file here, will be closed after request processing
            File_OpenMessageFile(frameworkConfig->outputBodyFilename, "w");

            dropboxRequestInit(&request, frameworkConfig);
            request.dbConfig = db;
            request.event = i;

            rc = readRequest(frameworkConfig, &request);

            // Process the request
            if (request.requestId != NULL) {
                rc = FrameworkProcess_Process(&request);
            }

            dropboxRequestClear(&request);
        }


    } else if (i->wd == frameworkConfig->controlWd) {
        // Was a stop signaled ?
        if (!strcmp(i->name, frameworkConfig->stopFile)) {
            *stop = 1;
            rc = Malloc_Safe((unsigned char**)(&filename), strlen(frameworkConfig->dropboxDir) +
                             strlen(frameworkConfig->stopFile) + 5,
                             frameworkConfig->lineMax);
            if (rc == 0) {
                sprintf(filename,"%s/%s", frameworkConfig->dropboxDir, frameworkConfig->stopFile);
                remove(filename);
                free(filename);
                filename=NULL;
            }

            // Was a restart signaled
        } else if (!strcmp(i->name, frameworkConfig->restartFile)) {
            *restart = 1;
            rc = Malloc_Safe((unsigned char**)(&filename), strlen(frameworkConfig->dropboxDir) +
                             strlen(frameworkConfig->restartFile) + 5,
                             frameworkConfig->lineMax);
            if (rc == 0) {
                sprintf(filename,"%s/%s", frameworkConfig->dropboxDir, frameworkConfig->restartFile);
                remove(filename);
                free(filename);
                filename=NULL;
            }
        }

    }

    return rc;
}

int readRequest(FrameworkConfig *frameworkConfig, DropboxRequest* request)
{
    int rc = 0;
    char* filename = NULL;
    char* pos = NULL;
    size_t fileSize = 0;

    pos = strstr(request->event->name, ".request.go");
    if (pos != NULL) {
        // Parse out the request id from the go file
        rc = Malloc_Safe((unsigned char**)&request->requestId,
                         (pos - request->event->name) + 1, (pos - request->event->name) + 1);
        if (rc) return rc;
        strncpy(request->requestId, request->event->name, (pos - request->event->name));
        request->requestId[(pos - request->event->name)]='\0';

        if (verbose) {
            fprintf(messageFile, "Saw dropbox event for signer : %s Request : '%s'\n",
                    request->dbConfig->sender, request->requestId);
        }

        // Now we need to read in the request file
        rc = Malloc_Safe((unsigned char**)(&filename), strlen(frameworkConfig->dropboxDir) +
                         strlen(request->dbConfig->sender) + strlen(request->requestId) +
                         strlen(".request") + 5, frameworkConfig->lineMax); /* freed @2 */
        if (rc) return rc;
        sprintf(filename,"%s/%s/%s.request", frameworkConfig->dropboxDir,
                request->dbConfig->sender, request->requestId);
        rc = File_ReadTextFile(&(request->requestJson), /* freed by caller */
                               &fileSize,
                               frameworkConfig->fileMax,
                               filename);


#if 0
        if (rc == 0) {
            printf("REQUEST FILE CONTENTS\n========\n%s\n========\n", request->requestJson);
        }
#endif

        free(filename); /* @2 */

        // Parse the json
        if (rc == 0) {
            request->rJsonO = json_tokener_parse(request->requestJson);
            if (NULL == request->rJsonO) {
                fprintf(messageFile, "ERROR: Unable to parse JSON from request %s\n", request->requestId);
                rc = 1;
            }
        }

        // Now we pull required fields
        if (rc == 0) {
            rc = JS_ObjectGetString(&(request->project), "project", request->rJsonO);
            if (rc == 0 && strlen(request->project) > frameworkConfig->lineMax) {
                rc = 1;
                fprintf(messageFile, "ERROR: Project overflow detected\n");
            }
            if (rc == 0 && verbose) fprintf(messageFile, "Project : %s\n", request->project);
        }
        if (rc == 0) {
            // Make a copy of the comment as we will be scanning for invalid chars later
            const char* cmt = NULL;
            rc = JS_ObjectGetString(&cmt, "comment", request->rJsonO);
            if (rc == 0 && strlen(cmt) > frameworkConfig->lineMax) {
                rc = 1;
                fprintf(messageFile, "ERROR: Comment overflow detected\n");
            } else if (rc == 0) {
                Malloc_Strcpy(&request->comment, cmt);
            } else {
                Malloc_Strcpy(&request->comment, "");
            }
            if (rc == 0 && verbose) fprintf(messageFile, "Comment : %s\n", request->comment);
        }
        if (rc == 0) {
            rc = JS_ObjectGetString(&(request->user), "user", request->rJsonO);
            if (rc == 0 && strlen(request->user) > frameworkConfig->lineMax) {
                rc = 1;
                fprintf(messageFile, "ERROR: User overflow detected\n");
            }
            if (rc == 0 && verbose) fprintf(messageFile, "User : %s\n", request->user);
        }
        if (rc == 0) {
            rc = JS_ObjectGetString(&(request->parameters), "parameters", request->rJsonO);
            if (rc == 0 && strlen(request->parameters) > frameworkConfig->lineMax) {
                rc = 1;
                fprintf(messageFile, "ERROR: Parameters overflow detected\n");
            }
            if (rc == 0 && verbose) fprintf(messageFile, "Parameters : %s\n", request->parameters);
        }
        if (rc == 0) {
            rc = JS_ObjectGetString(&(request->epwd), "epwd", request->rJsonO);
            if (rc == 0 && strlen(request->epwd) > frameworkConfig->lineMax) {
                rc = 1;
                fprintf(messageFile, "ERROR: EPWD overflow detected\n");
            }
        }


        // Pull the payload
        if (rc == 0) {
            const char* payload = NULL;
            rc = JS_ObjectGetString(&payload, "payload", request->rJsonO);
            if (rc == 0 && payload != NULL &&
                strlen(payload) > 0) {
                // Store the payload into the input file

                uint8_t* data = NULL;
                size_t len = 0;
                rc = Array_Scan(&data, &len, payload);

                if (rc == 0) {
                    // Write to the file
                    rc = File_WriteBinaryFile(data, len,
                                              request->frameworkConfig->inputAttachmentFilename);
                }
                if (rc == 0) {
                    request->hasPayload = 1;
                    if (verbose) fprintf(messageFile, "Payload stored to %s\n", request->frameworkConfig->inputAttachmentFilename);
                }

                if (data != NULL) free(data);
            }
            rc = 0; // payload optional
        }
    }
    request->status = rc;

    return rc;
}


int JS_ObjectGetString(const char **string,
                       const char *key,
                       json_object *object)
{
    int rc = 0;
    json_object *keyJson = NULL;

    if (rc == 0) {
        if (!json_object_object_get_ex(object, key, &keyJson)) {
            fprintf(messageFile,
                    "ERROR: JS_ObjectGetString: getting key: %s\n", key);
            rc = 1;
        }
    }
    if (rc == 0) {
        *string = json_object_get_string(keyJson);
        if (verbose) fprintf(messageFile,
                             "JS_ObjectGetString: key: %s string: %s\n",
                             key, *string);
    }
    return rc;
}

/* Array_Scan() converts a string to a binary array */
int Array_Scan(unsigned char **data,   /* output binary, freed by caller */
               size_t *len,
               const char *string)     /* input string */
{
    uint32_t rc = 0;
    size_t strLength;
    if (rc == 0) {
        strLength = strlen(string);
        if ((strLength %2) != 0) {
            fprintf(messageFile,
                    "ERROR: Array_Scan: number of bytes %lu is not even\n",
                   (unsigned long)strLength);
            rc = 1;
        }
    }
    if (rc == 0) {
        *len = strlen(string) / 2;  /* safe because already tested for even number of bytes */
        *data = malloc((*len) + 8); /* add bytes at end because scanf uses int */
        if (*data == NULL) {
            fprintf(messageFile,
                    "ERROR: Array_Scan: could not malloc %u bytes\n", (unsigned int)*len);
            rc = 1;
        }
    }
    if (rc == 0) {
        unsigned int i;
        for (i = 0 ; i < *len ; i++) {
            unsigned int tmpint;
            int irc = sscanf(string + (2*i), "%2x", &tmpint);
            *((*data)+i) = tmpint;
            if (irc != 1) {
                fprintf(messageFile,
                        "ERROR: Array_Scan: invalid hexascii\n");
                rc = 1;
            }
        }
    }
    return rc;
}

char nibbleToChar(unsigned char nibble)
{
    if(nibble > 0xF)
    {
        return 0;
    }
    else
    {
        if(nibble < 10)
        {
            return ('0' + nibble);
        }
        else
        {
            return ('A' + nibble - 10);
        }
    }
}

struct json_object* binaryFileToJsonObject(FILE* fp)
{
    unsigned char hi = 0;
    unsigned char lo = 0;

    fseek(fp, 0, SEEK_END);
    size_t fileSize = ftell(fp);
    rewind(fp);

    unsigned char* hashFile = malloc((fileSize+1));
    char* hashString = malloc((fileSize*2)+1);

    fread(hashFile, fileSize, 1, fp);

    size_t i = 0;
    while(i < fileSize)
    {
        hi = (hashFile[i] >> 4) & 0xF;
        lo = hashFile[i] & 0x0F;
        hashString[2*i] = nibbleToChar(hi);
        hashString[(2*i)+1] = nibbleToChar(lo);
        i++;
    }
    hashString[2*i] = 0;

    struct json_object* json = json_object_new_string(hashString);

    free(hashFile);
    free(hashString);

    return json;
}


int sendResult(DropboxRequest* requestParms)
{
    int rc = 0;
    const char* outputJson = NULL;
    char* output = NULL;
    char* filename = NULL;
    size_t len = 0;
    FILE	*file = NULL;

    // Create the result json and place it back in the senders dropbox

    struct json_object* json = json_object_new_object();

    //fprintf(messageFile, "Sending response\n");

    File_CloseMessageFile();

    if (requestParms->hasResult) {
        FILE * resFile = fopen(requestParms->frameworkConfig->outputAttachmentFilename, "r");
        if (resFile == NULL && requestParms->status == 0) {
            fprintf(requestParms->frameworkConfig->frameworkLogFile,
                    "ERROR: Unable to open output attachment : %s\n",
                    requestParms->frameworkConfig->outputAttachmentFilename);
            requestParms->status = 1;
        } else if (resFile != NULL) {
            json_object_object_add(json, "result" , binaryFileToJsonObject(resFile));
            fclose(resFile);
        }
    }
    remove(requestParms->frameworkConfig->outputAttachmentFilename);

    if (rc == 0) {
        rc = File_ReadTextFile(&output, &len, requestParms->frameworkConfig->fileMax,
                               requestParms->frameworkConfig->outputBodyFilename);
        if (rc == 0) {
            json_object_object_add(json, "stdout", json_object_new_string(output));
            free(output);
        }
    }

    if (rc == 0) {
        json_object_object_add(json, "retval", json_object_new_int(requestParms->status));
    }

    // Get our output json
    if (rc == 0) {
        outputJson = json_object_get_string(json);

        rc = Malloc_Safe((unsigned char**)&filename,
                         strlen(requestParms->frameworkConfig->dropboxDir) +
                         strlen(requestParms->dbConfig->sender) +
                         strlen(requestParms->requestId) + strlen(".response.go") + 10,
                         requestParms->frameworkConfig->lineMax);
    }

    /// TODO REMOVE
#if 0
    if (verbose) {
        File_Printf(requestParms->frameworkConfig->frameworkLogFile, NULL,
                    "Response: %s\n", outputJson);
        fprintf(messageFile, "Response : %s\n", outputJson);
    }
#endif

    // Write the response file
    if (rc == 0) {
        sprintf(filename,"%s/%s/%s.response", requestParms->frameworkConfig->dropboxDir,
                requestParms->dbConfig->sender, requestParms->requestId);

        rc = File_Open(&file, filename, "w");
        if (rc == 0) {
            fprintf(file, "%s\n", outputJson);
            fclose(file);
        }

    }

    // Write the go file
    if (rc == 0) {
        sprintf(filename,"%s/%s/%s.response.go", requestParms->frameworkConfig->dropboxDir,
                requestParms->dbConfig->sender, requestParms->requestId);

        rc = File_Open(&file, filename, "w");
        if (rc == 0) {
            fprintf(file, "GO\n");
            fclose(file);
        }

    }


    if (filename != NULL) free(filename);
    json_object_put(json);
    return rc;
}
