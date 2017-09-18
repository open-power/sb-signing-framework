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
#include <stdio.h>
#include <string.h>

#include "mail.h"

extern FILE* messageFile;
extern int verbose;

int SendMailFile(FrameworkConfig* configParm, const char* sendto, const char* subject, const char* mailbodyfile)
{
    int rc = 0;
    char* text = NULL;
    size_t len = 0;

    rc = File_ReadTextFile(&text, &len, configParm->fileMax, mailbodyfile);

    if (rc == 0) {
        rc = SendMail(configParm, sendto, subject, text);
    } else {
        rc = SendMail(configParm, sendto, subject, "INVALID BODY FILE");
    }
    free(text);
    return rc;
}

int SendMail(FrameworkConfig* configParm, const char* sendto, const char* subject, const char* mailbody)
{
    int rc = 0;
    char* cmd = NULL;
    FILE* ofile = NULL;

    if (verbose)
        fprintf(messageFile, "Sending email to %s : %s\n", sendto, subject);

    remove(configParm->emailFilename);

    ofile = fopen(configParm->emailFilename, "w");
    if (ofile != NULL) {
        fprintf(ofile, "Subject: %s: %s\n", configParm->frameworkName, subject);
        fprintf(ofile, "\n%s\n", mailbody);
        fclose(ofile);
    } else {
        fprintf(messageFile, "Unable to open email body file : %s\n", configParm->emailFilename);
        rc = 1;
    }

    if (rc == 0) {
        rc = Malloc_Safe((unsigned char**)&cmd,
                         strlen(configParm->emailFilename)+ strlen(sendto) +
                         strlen("cat  | sendmail  ") + 5,
                         (size_t)configParm->lineMax);
    }
    if (rc == 0) {
        sprintf(cmd, "cat %s | sendmail %s", configParm->emailFilename, sendto);
    }

    if (rc == 0) {
        rc = system(cmd);
    }

    remove(configParm->emailFilename);
    free(cmd);
    return rc;
}


int SendMailFileWithAttachment(FrameworkConfig* configParm,
                               const char* sendto, const char* subject, const char* mailbodyfile,
                               const char* attachmentfile)
{

    int rc = 0;
    char* cmd = NULL;
    char* newSubject = NULL;

    if (rc == 0) {
        rc = Malloc_Safe((unsigned char**)&newSubject,
                         strlen(configParm->frameworkName) +
                         strlen(subject) + 5,
                         (size_t)configParm->lineMax);
    }
    if (rc == 0) {
        sprintf(newSubject, "%s: %s", configParm->frameworkName, subject);
    }
    if (rc == 0) {
        rc = Malloc_Safe((unsigned char**)&cmd,
                         strlen(mailbodyfile)+ strlen(sendto) +
                         strlen(attachmentfile) +
                         strlen(newSubject) +
                         strlen("cat  | mailx -s "" -a  ") + 5,
                         (size_t)configParm->lineMax);
    }
    if (rc == 0) {
        sprintf(cmd, "cat %s | mailx -s \"%s\" -a %s %s", mailbodyfile, newSubject, attachmentfile, sendto);
    }

    if (rc == 0) {
        rc = system(cmd);
    }


    free(cmd);
    free(newSubject);
    return rc;
}
