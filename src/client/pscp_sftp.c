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

#include "pscp_sftp.h"

#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <signal.h>

#include <termios.h>
#include <curl/curl.h>

#define PSCP_PKEY_PASSPHRASE_MAX 256
#define PSCP_SFTP_MAX_POLLING_ATTEMPTS 10
#define PSCP_SFTP_POLLING_DURATION 5       
#define PSCP_SSHKEY_GETPW_MAX_RETRIES 2

struct pscp_sftp_session
{
    CURL* curl;
    char* url;
    size_t url_len;
    bool verbose;
};

int GetPassword(char* result, size_t len, bool verbose);

int pscp_sftp_global_init()
{
    return curl_global_init(CURL_GLOBAL_ALL);
}

// Common code to initialize sftp connection to remote server.
struct pscp_sftp_session*  startSftpSession(const char * sftp_url, const char * privateKeyPath, bool verbose)
{
    int status = 0;
    struct pscp_sftp_session* sftp = NULL;

    if(!sftp_url || !privateKeyPath)
    {
        status = -1;
    }

    if(status == 0)
    {
        sftp = calloc(1, sizeof(struct pscp_sftp_session));
        if(!sftp)
        {
            status = -1;
        }
    }
    
    if(status == 0)
    {
        sftp->curl = curl_easy_init();
        if(!sftp->curl)
        {
            status = -1;
        }
    }
    
    if(status == 0 && verbose)
    {
        status = curl_easy_setopt(sftp->curl, CURLOPT_VERBOSE, 1L);
    }

    if(status == 0)
    {
        size_t len = strlen(sftp_url);
        sftp->url_len = len + 2;
        sftp->url = calloc(sftp->url_len, 1);
        if(sftp->url)
        {
            strncpy(sftp->url, sftp_url, len);

            if(sftp_url[len - 1] != '/')
            {
                strncat(sftp->url, "/", sftp->url_len);
            }
        }
    }

    if(status == CURLE_OK) status = curl_easy_setopt(sftp->curl, CURLOPT_PROTOCOLS, CURLPROTO_SFTP);
    if(status == CURLE_OK) status = curl_easy_setopt(sftp->curl, CURLOPT_SSH_PRIVATE_KEYFILE, privateKeyPath);
    if(status == CURLE_OK)
    {
        // Workaround for RedHat bug 1260742 - curl requiring public key
        char pubKeyPath[PATH_MAX];
        snprintf(pubKeyPath, PATH_MAX, "%s.pub", privateKeyPath);
        status = curl_easy_setopt(sftp->curl, CURLOPT_SSH_PUBLIC_KEYFILE, pubKeyPath);
    }
    if(status == CURLE_OK)
    {
        status = curl_easy_setopt(sftp->curl, CURLOPT_URL, sftp_url);
    }
    if(status == CURLE_OK)
    {
        status = curl_easy_setopt(sftp->curl, CURLOPT_CONNECT_ONLY, 1L);
    }
    if(status == CURLE_OK)
    {
        int retry = 0;
        while(retry <= PSCP_SSHKEY_GETPW_MAX_RETRIES) {

            char passphrase[PSCP_PKEY_PASSPHRASE_MAX];
            bzero(passphrase, PSCP_PKEY_PASSPHRASE_MAX);

            status = GetPassword(passphrase, PSCP_PKEY_PASSPHRASE_MAX, verbose);
            if(status != 0)
            {
                fprintf(stderr, "ERROR: unable to get password, error: %d\n", status);
                bzero(passphrase, PSCP_PKEY_PASSPHRASE_MAX);
                break;
            }
            status = curl_easy_setopt(sftp->curl, CURLOPT_KEYPASSWD, passphrase);
            bzero(passphrase, PSCP_PKEY_PASSPHRASE_MAX);
            if(status != CURLE_OK)
            {
                fprintf(stderr, "ERROR: unable to set CURLOPT_KEYPASSWD, curl error: %d\n", status);
                break;
            }
            status = curl_easy_perform(sftp->curl);
            if(status == 0)
            {
                status = curl_easy_setopt(sftp->curl, CURLOPT_CONNECT_ONLY, 0L);
                break;
            }
            if(status != CURLE_LOGIN_DENIED)
            {
                fprintf(stderr, "ERROR: unable to establish session with %s\n", sftp->url);
                break;
            }
            retry++;
        }
        if(status == CURLE_LOGIN_DENIED)
        {
            fprintf(stderr, "ERROR: unable to connect to %s with provided credentials\n", sftp->url);
        }
    }

    if(status != 0 && sftp)
    {
        if(sftp->curl)
        {
            curl_easy_cleanup(sftp->curl);
        }
        if(sftp->url)
        {
            free(sftp->url);
        }
        free(sftp);
        sftp = NULL;
    }
    return sftp;
}


int sendFileToServer(const struct pscp_sftp_session* sftp, const char * local, const char * remote)
{
    int status = 0;
    char* full_url = NULL;
    FILE* fp = NULL;

    if(!sftp || !local || !remote)
    {
        status = -1;
    }
    else if(!sftp->curl || !sftp->url)
    {
        status = -1;
    }

    if(status == 0)
    {
        size_t len = strlen(remote) + strlen(sftp->url) + 1;
        full_url = calloc(len, 1);
        if(full_url)
        {
            snprintf(full_url, len, "%s%s", sftp->url, remote);
        }
        else
        {
            status = -1;
        }
    }

    if(status == 0)
    {
        fp = fopen(local, "r");
        if(!fp)
        {
            status = -1;
        }
    }

    if(status == 0)
    {
        status = curl_easy_setopt(sftp->curl, CURLOPT_UPLOAD, 1L);
    }
    if(status == 0)
    {
        status = curl_easy_setopt(sftp->curl, CURLOPT_READDATA, fp);
    }
    if(status == 0)
    {
        status = curl_easy_setopt(sftp->curl, CURLOPT_URL, full_url);
    }
    if(status == 0)
    {
        status = curl_easy_perform(sftp->curl);
        if(status == CURLE_LOGIN_DENIED)
        {
            fprintf(stderr, "%s rejected the provided credentials\n", sftp->url);
        }
    }

    if(fp)
    {
        fclose(fp);
        fp = NULL;
    }
    if(full_url)
    {
        free(full_url);
        full_url = NULL;
    }

    return status;
}

int getFileFromServer(const struct pscp_sftp_session* sftp, const char * local, const char * remote)
{
    int status = 0;
    char* full_url = NULL;
    FILE* fp = NULL;

    if(!sftp || !local || !remote)
    {
        status = -1;
    }
    else if(!sftp->curl || !sftp->url)
    {
        status = -1;
    }

    if(status == 0)
    {
        size_t len = strlen(remote) + strlen(sftp->url) + 1;
        full_url = calloc(len, 1);
        if(full_url)
        {
            snprintf(full_url, len, "%s%s", sftp->url, remote);
        }
        else
        {
            status = -1;
        }
    }

    if(status == 0)
    {
        fp = fopen(local, "w");
        if(!fp)
        {
            status = -1;
        }
    }

    if(status == 0)
    {
        status = curl_easy_setopt(sftp->curl, CURLOPT_UPLOAD, 0L);
    }
    if(status == 0)
    {
        status = curl_easy_setopt(sftp->curl, CURLOPT_WRITEDATA, fp);
    }
    if(status == 0)
    {
        status = curl_easy_setopt(sftp->curl, CURLOPT_URL, full_url);
    }
    if(status == 0)
    {
        status = curl_easy_perform(sftp->curl);
        if(status == CURLE_LOGIN_DENIED)
        {
            fprintf(stderr, "%s rejected the provided credentials\n", sftp->url);
        }
    }

    if(fp)
    {
        fclose(fp);
        fp = NULL;
    }
    if(full_url)
    {
        free(full_url);
        full_url = NULL;
    }

    return status;
}


int pollOnFileFromServer(const struct pscp_sftp_session* sftp, const char * local, const char * remote)
{
    int status = 0;
    char* full_url = NULL;
    FILE* fp = NULL;

    if(!sftp || !local || !remote)
    {
        status = -1;
    }
    else if(!sftp->curl || !sftp->url)
    {
        status = -1;
    }

    if(status == 0)
    {
        size_t len = strlen(remote) + strlen(sftp->url) + 1;
        full_url = calloc(len, 1);
        if(full_url)
        {
            snprintf(full_url, len, "%s%s", sftp->url, remote);
        }
        else
        {
            status = -1;
        }
    }

    if(status == 0)
    {
        fp = fopen(local, "w");
        if(!fp)
        {
            status = -1;
        }
    }

    if(status == 0)
    {
        status = curl_easy_setopt(sftp->curl, CURLOPT_UPLOAD, 0L);
    }
    if(status == 0)
    {
        status = curl_easy_setopt(sftp->curl, CURLOPT_WRITEDATA, fp);
    }
    if(status == 0)
    {
        status = curl_easy_setopt(sftp->curl, CURLOPT_URL, full_url);
    }
    if(status == 0)
    {
        status = curl_easy_perform(sftp->curl);
        // TODO: have a timeout
        for(int i = 0; (i < PSCP_SFTP_MAX_POLLING_ATTEMPTS) && (status == CURLE_REMOTE_FILE_NOT_FOUND); i++)
        {
            sleep(PSCP_SFTP_POLLING_DURATION);
            status = curl_easy_perform(sftp->curl);
        }
        if(status == CURLE_LOGIN_DENIED)
        {
            fprintf(stderr, "%s rejected the provided credentials\n", sftp->url);
        }
    }

    if(fp)
    {
        fclose(fp);
        fp = NULL;
    }
    if(full_url)
    {
        free(full_url);
        full_url = NULL;
    }

    return status;
}

static void SignalHandler(int val)
{
    struct termios term;
    tcgetattr(fileno(stdin), &term);

    term.c_lflag |= ECHO;
    term.c_lflag &= ~ECHONL;

    tcsetattr(fileno(stdin), TCSAFLUSH, &term);
    exit(-2);
}

int GetPassword(char* result, size_t len, bool verbose)
{
    int status = 0;
    bzero(result, len);

    struct sigaction newSa;
    newSa.sa_handler = SignalHandler;
    sigemptyset(&newSa.sa_mask);
    newSa.sa_flags = SA_RESTART;

    struct sigaction oldSigInt;
    struct sigaction oldSigTerm;
    struct sigaction oldSigQuit;

    if(sigaction(SIGINT, &newSa, &oldSigInt) == -1)
    {
        if(verbose) fprintf(stderr, "ERROR: unable to change SIGINT handler\n");
        return -1;
    }
    if(sigaction(SIGTERM, &newSa, &oldSigTerm) == -1)
    {
        if(verbose) fprintf(stderr, "ERROR: unable to change SIGTERM handler\n");
        return -1;
    }
    if(sigaction(SIGQUIT, &newSa, &oldSigQuit) == -1)
    {
        if(verbose) fprintf(stderr, "ERROR: unable to change SIGQUIT handler\n");
        return -1;
    }

    struct termios oldTerm, newTerm;
    tcgetattr(fileno(stdin), &oldTerm);

    newTerm = oldTerm;

    newTerm.c_lflag &= ~ECHO;
    newTerm.c_lflag |= ECHONL;

    tcsetattr(fileno(stdin), TCSAFLUSH, &newTerm);

    printf("NOTE: Try not to use a backspace...\n");
    printf("Key Passphrase: ");
    fflush(stdout);

    char c = getchar();
    size_t i = 0;

    while(c != '\n' && c != '\f' && c != '\r')
    {
        if(i < len)
        {
            result[i] = c;
            i++;
            c = getchar();
        }
        else
        {
            status = -1;
            break;
        }
    }
    tcsetattr(fileno(stdin), TCSANOW, &oldTerm);

    if(sigaction(SIGINT, &oldSigInt, NULL) == -1)
    {
        if(verbose) fprintf(stderr, "ERROR: unable to change SIGINT handler\n");
        status = -1;
    }
    if(sigaction(SIGTERM, &oldSigTerm, NULL) == -1)
    {
        if(verbose) fprintf(stderr, "ERROR: unable to change SIGTERM handler\n");
        status = -1;
    }
    if(sigaction(SIGQUIT, &oldSigQuit, NULL) == -1)
    {
        if(verbose) fprintf(stderr, "ERROR: unable to change SIGQUIT handler\n");
        status = -1;
    }

    return status;
}

void closeSftpSession(struct pscp_sftp_session* sftp)
{
    if(sftp)
    {
        if(sftp->curl)
        {
            curl_easy_cleanup(sftp->curl);
        }
        if(sftp->url)
        {
            free(sftp->url);
        }
        free(sftp);
    }
}
