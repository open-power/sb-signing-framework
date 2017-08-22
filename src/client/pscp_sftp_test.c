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

#include "pscp_sftp.h"


int main(int argc, char** argv)
{
    if((argc == 6) )
    {
        const char* url = argv[1];
        const char* key = argv[2];
        const char* in = argv[3];
        const char* serverFile = argv[4];
        const char* out = argv[5];
        const bool verbose = true;
        struct pscp_sftp_session* sftp = NULL;

        printf("Running SFTP global init\n");
        int status = pscp_sftp_global_init();
        if(status)
        {
            printf("Creating sftp session\n");
            sftp = startSftpSession(url, key, verbose);
        }
        if(sftp)
        {
            printf("Sending File\n");
            status = sendFileToServer(sftp, in, serverFile);
        }
        else
        {
            status = -1;
        }
        if(status == 0)
        {
            printf("Asking for File\n");
            status = getFileFromServer(sftp, out, serverFile);
        }
        if(sftp)
        {
            printf("Closing session...\n");
            closeSftpSession(sftp);
        }
    }
    else
    {
        printf("USAGE:\n  %s <url> <private-key-file> <local-in-file> <server-file> <local-out-file> [key-passphrase]\n", argv[0]);
    }

    return 0;
}
