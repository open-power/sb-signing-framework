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
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <unistd.h>
#include <stdbool.h>
#include <fcntl.h>

#include "pscp_sftp.h"
#include "pscp_json.h"

bool GetArgs(int argc, char **argv);
void PrintUsage(void);
bool PrivateKeyEncrypted(const char* privKeyPath);
int GenerateFilename(char** filename, const char* directory, const char* base, const char* tag, bool verbose);

const char* pscp_request_tag = ".request";
const char* pscp_request_go_tag = ".request.go";
const char* pscp_response_tag = ".response";
const char* pscp_response_go_tag = ".response.go";
const char* pscp_remote_directory = "dropbox/";
const char* pscp_tmp_directory = "/tmp/";


// Required Parameters
char* pscp_project          = NULL;
char* pscp_epwd_path        = NULL;
char* pscp_sftp_url         = NULL;
char* pscp_pkey_path        = NULL;
char* pscp_comment          = NULL;
// Optional Parameters
char* pscp_parameters       = NULL;
char* pscp_payload_path     = NULL;
char* pscp_output_file      = NULL;
bool  verbose               = false;
bool  debug                 = false;
bool  pscp_print_server_stdout = false;

int main(int argc, char** argv)
{
    char* pscp_identifier           = NULL;
    char* json_string               = NULL;
    char* pscp_session_id           = NULL;
    char* pscp_request_filename     = NULL;
    char* pscp_request_go_filename  = NULL;
    char* pscp_response_filename    = NULL;
    char* pscp_response_go_filename = NULL;

    struct pscp_sftp_session* pscp_sftp_session = NULL;

    int status = 0;                     // Indicates what type of failure occured
    bool success = GetArgs(argc, argv); // Used to check failure in code

    if(!success)
    {
        // This silences the generic "ERROR" message that occurs if status is not set to something specific by GetArgs()
        status = -1;
    }

    // Verify that required parameters are found
    if(success && !(pscp_project && pscp_epwd_path && pscp_sftp_url && pscp_pkey_path))
    {
        success = false;
        fprintf(stderr, "ERROR: not all required parameters were found\n");
        PrintUsage();
    }
    
    // Check that the private key is encrypted
    if(success)
    {
        if(!PrivateKeyEncrypted(pscp_pkey_path))
        {
            success = false;
            fprintf(stderr, "ERROR: RSA private key must be encrypted\n");
        }
    }
    
    // Create the identifier for the user: <username>_<hostname>
    if(success)
    {
        const char * username = getenv("USER");
        const char * hostname = getenv("HOSTNAME");
        const char * nullString = "NULL"; // Used if no username or hostname is found

        size_t identifierMaxSize =   strlen(username)
                                   + strlen(hostname)
                                   + 2;  // Seperator and \0

        pscp_identifier = (char*)calloc(identifierMaxSize, 1);

        if(pscp_identifier)
        {
            if(username && hostname)
            {
                snprintf(pscp_identifier, identifierMaxSize, "%s_%s", username, hostname);
            }
            else if(username)
            {
                fprintf(stderr, "ERROR: Unable to find hostname in the environment\n");
                strncpy(pscp_identifier, username, identifierMaxSize);
            }
            else if(hostname)
            {
                fprintf(stderr, "ERROR: Unable to find username in the environment\n");
                strncpy(pscp_identifier, hostname, identifierMaxSize);
            }
            else
            {
                fprintf(stderr, "ERROR: Unable to find username or hostname in the environment\n");
                strncpy(pscp_identifier, nullString, identifierMaxSize);
            }

            if(strlen(pscp_identifier) == 0)
            {
                fprintf(stderr, "ERROR: Failure in generation of pscp_identifier\n");
                success = false;
            }
        }
        else
        {
            fprintf(stderr, "ERROR: Unable to allocate memory for pscp_identifier\n");
            success = false;
        }
    }

    // Create the session id: <username>_<hostname>_<timestamp>. This is also used as the base for filenames.
    if(success)
    {
        time_t timestamp = time(NULL);
        size_t len = strlen(pscp_identifier) 
            + (((int)log10(timestamp))+1)
            + 2;
        pscp_session_id = (char*)calloc(len, 1);
        if(pscp_session_id)
        {
            int rc = snprintf(pscp_session_id, len, "%s_%lx", pscp_identifier, timestamp);
            if(rc <= 0)
            {
                success = false;
                fprintf(stderr, "ERROR: snprintf for generating pscp_session_id failed\n");
            }
        }
        else
        {
            success = false;
            fprintf(stderr, "ERROR: unable to allocate memory for pscp_session_id\n");
        }
    }

    // Generate the filenames for communication with the server
    if(success)
    {
        status = GenerateFilename(&pscp_request_filename, pscp_tmp_directory, pscp_session_id, pscp_request_tag, verbose);
        if(status != 0)
        {
            fprintf(stderr, "ERROR: could not generate name for server-side %s file\n", pscp_request_tag); 
            success = false;
        }
    }
    if(success)
    {
        status = GenerateFilename(&pscp_request_go_filename, pscp_tmp_directory, pscp_session_id, pscp_request_go_tag, verbose);
        if(status != 0)
        {
            fprintf(stderr, "ERROR: could not generate name for server-side %s file\n", pscp_request_go_tag); 
            success = false;
        }
    }
    if(success)
    {
        status = GenerateFilename(&pscp_response_filename, pscp_tmp_directory, pscp_session_id, pscp_response_tag, verbose);
        if(status != 0)
        {
            success = false;
            fprintf(stderr, "ERROR: could not generate name for server-side %s file\n", pscp_response_tag); 
        }
    }
    if(success)
    {
        status = GenerateFilename(&pscp_response_go_filename, pscp_tmp_directory, pscp_session_id, pscp_response_go_tag, verbose);
        if(status != 0)
        {
            success = false;
            fprintf(stderr, "ERROR: could not generate name for server-side %s file\n", pscp_response_go_tag); 
        }
    }

    // Generate the json from the parameters
    if(success)
    { 
        int rc = createJsonString(&json_string, pscp_project, pscp_parameters, pscp_identifier, pscp_comment, pscp_epwd_path, pscp_payload_path, verbose);
        if(rc != 0)
        {
            fprintf(stderr, "ERROR: unable to create json: %d\n", rc);
            success = false;
            status = rc;
        }
    }

    // Write json string to a new request file
    if(success)
    {
        // Restrict access to request file to protect the encrypted password
        int fd = open(pscp_request_filename, O_CREAT | O_WRONLY, 0600);
        if(fd >= 0)
        {
            FILE* fp = fdopen(fd, "w");
            if(fp)
            {
                size_t json_string_len = strlen(json_string);
                size_t len_write = fwrite(json_string, 1, json_string_len, fp);
                if(len_write != json_string_len)
                {
                    fprintf(stderr, "ERROR: write to file was unsuccesful\n");
                    success = false;
                }
                fclose(fp);
            }
            else
            {
                success = false;
                fprintf(stderr, "ERROR: unable to convert file descriptor to FILE type: %s\n", pscp_request_filename);
            }
            close(fd);
        }
        else
        {
            success = false;
            fprintf(stderr, "ERROR: unable to open request file for writing: %s\n", pscp_request_filename);
        }
    }
    
    // Initialize the sftp library
    if(success)
    {
        int rc = pscp_sftp_global_init();
        if(rc != 0)
        {
            fprintf(stderr, "ERROR in sftp library initialization\n");
            success = false;
            status = rc;
        }
    }

    // Create the sftp session
    if(success)
    {
        pscp_sftp_session = startSftpSession(pscp_sftp_url, pscp_pkey_path, verbose);
        if(!pscp_sftp_session)
        {
            fprintf(stderr, "ERROR: unable to create pscp_curl session\n");
            success = false;
        }
    }

    // Send request file server
    if(success)
    {
        char* remote_request_filename = NULL;
        status = GenerateFilename(&remote_request_filename, pscp_remote_directory, pscp_session_id, pscp_request_tag, verbose);
        if(status == 0)
        {
            status = sendFileToServer(pscp_sftp_session, pscp_request_filename, remote_request_filename);
            free(remote_request_filename);
            if(status != 0)
            {
                success = false;
                fprintf(stderr, "ERROR: curl send failed for file %s\n", pscp_request_filename);
            }
        }
        else
        {
            success = false;
            fprintf(stderr, "ERROR: couldn't allocate memory for remote file name\n");
        }
    }

    // Send the GO file to server to start the signing
    if(success)
    {
        FILE * fp = fopen(pscp_request_go_filename, "w");
        if(fp)
        {
            fclose(fp);
            char* remote_request_go_filename = NULL;
            status = GenerateFilename(&remote_request_go_filename, pscp_remote_directory, pscp_session_id, pscp_request_go_tag, verbose);
            if(status == 0)
            {
                status = sendFileToServer(pscp_sftp_session, pscp_request_go_filename, remote_request_go_filename);
                if(status != 0)
                {
                    success = false;
                    fprintf(stderr, "ERROR: curl send failed for file %s\n", pscp_request_go_filename);
                }
                free(remote_request_go_filename);
            }
            else
            {
                success = false;
                fprintf(stderr, "ERROR: couldn't allocate memory for remote file name\n");
            }
        }
        else
        {
            success = false;
            fprintf(stderr, "ERROR: unable to open request.go file for writing: %s\n", pscp_request_go_filename);
        }
    }

    // Wait for signing server to create the response GO file
    if(success)
    {
        char* remote_response_go_filename = NULL;
        status = GenerateFilename(&remote_response_go_filename, pscp_remote_directory, pscp_session_id, pscp_response_go_tag, verbose);
        if(status == 0)
        {
            status = pollOnFileFromServer(pscp_sftp_session, pscp_response_go_filename, remote_response_go_filename);
            if(status != 0)
            {
                success = false;
                fprintf(stderr, "ERROR: no response from server\n");
            }
            free(remote_response_go_filename);
        }
        else
        {
            success = false;
            fprintf(stderr, "ERROR: could not generate %s filename\n", pscp_response_go_tag);
        }
    }

    // Copy the signing server response file to the client machine
    if(success)
    {
        char* remote_response_filename = NULL;
        status = GenerateFilename(&remote_response_filename, pscp_remote_directory, pscp_session_id, pscp_response_tag, verbose);
        if(status == 0)
        {
            status = getFileFromServer(pscp_sftp_session, pscp_response_filename, remote_response_filename);
            if(status != 0)
            {
                success = false;
                fprintf(stderr, "ERROR: unable to retreive file from server\n");
            }
            free(remote_response_filename);
        }
        else
        {
            success = false;
            fprintf(stderr, "ERROR: unable to generate remote filename\n");
        }
    }

    // Parse data from the server response and display it appropriately
    if(success)
    {
        int retval = 0;
        unsigned char* payload = NULL;
        char* stdout = NULL;
        size_t payload_len = 0;
        size_t stdout_len = 0;

        status = parseServerResponse(pscp_response_filename, &payload, &payload_len, &stdout, &stdout_len, &retval, verbose);
        if(status == 0)
        {
            status = retval;

            if(payload)
            {
                if(pscp_output_file)
                {
                    FILE* fp = fopen(pscp_output_file, "w");
                    if(fp)
                    {
                        size_t len = fwrite(payload, 1, payload_len, fp);
                        if(len != payload_len)
                        {
                            success = false;
                            fprintf(stderr, "ERROR: unable to write server payload to file. Only %lu/%lu bytes written\n", len, payload_len);
                        }
                        fclose(fp);
                    }
                    else
                    {
                        success = false;
                        fprintf(stderr, "ERROR: unable to open output file\n");
                    }
                }
                else
                {
                    success = false;
                    fprintf(stderr, "ERROR: no output filename was provided, unable to write reponse payload\n");
                }
                free(payload);
                payload = NULL;
            }
            if(stdout)
            {
                if(pscp_print_server_stdout)
                {
                    printf("\n==== Begin Standard Out ====\n%s\n==== End of Standard Out ====\n", stdout);
                }
                free(stdout);
            }
            if(retval != 0)
            {
                fprintf(stderr, "Signing server responded with failure: %d\n"
                                "Rerun with -stdout to see server output\n", retval);
            }
        }
        else
        {
            success = false;
            fprintf(stderr, "ERROR: could not parse server response\n");
        }
    }

    // Remove the created files from the local machine
    if(!debug)
    {
        if(verbose) printf("Removing auto-generated files\n");
        remove(pscp_request_filename);
        remove(pscp_request_go_filename);
        remove(pscp_response_filename);
        remove(pscp_response_go_filename);
    }

    if(success && debug)
    {
        printf("\nServer response written to: %s\n", pscp_response_filename);
    }

    if(pscp_sftp_session)
    {
        closeSftpSession(pscp_sftp_session);
        pscp_sftp_session = NULL;
    }
    if(pscp_identifier)
    {
        free(pscp_identifier);
        pscp_identifier = NULL;
    }
    if(json_string)
    {
        free(json_string);
        json_string = NULL;
    }
    if(pscp_session_id)
    {
        free(pscp_session_id);
        pscp_session_id = NULL;
    }
    if(pscp_request_filename)
    {
        free(pscp_request_filename);
        pscp_request_filename = NULL;
    }
    if(pscp_request_go_filename)
    {
        free(pscp_request_go_filename);
        pscp_request_go_filename = NULL;
    }
    if(pscp_response_filename)
    {
        free(pscp_response_filename);
        pscp_response_filename = NULL;
    }
    if(pscp_response_go_filename)
    {
        free(pscp_response_go_filename);
        pscp_response_go_filename = NULL;
    }

    if(!success && (status == 0))
    {
        // Set generic error status for non-specific error
        status = -1;
        fprintf(stderr, "ERROR\n");
    }

    if(success && (status == 0))
    {
        printf("DONE\n");
    }
    
    return status;
}

bool GetArgs(int argc, char **argv)
{
    bool success = true;
    int i;

    /* command line argument defaults */
    verbose = false;

    /* get the command line arguments */
    for (i=1 ; (i<argc) && (success) ; i++) {
        if (strcmp(argv[i],"-v") == 0) {
            verbose = true;
        }
        else if (strcmp(argv[i],"-d") == 0) {
            debug = true;
        }
        else if (strcmp(argv[i],"-project") == 0) {
            i++;
            pscp_project = argv[i];
        }
        else if (strcmp(argv[i],"-param") == 0) {
            i++;
            pscp_parameters = argv[i];
        }
        else if (strcmp(argv[i],"-epwd") == 0) {
            i++;
            pscp_epwd_path = argv[i];
        }
        else if (strcmp(argv[i],"-payload") == 0) {
            i++;
            pscp_payload_path = argv[i];
        }
        else if (strcmp(argv[i],"-comments") == 0) {
            i++;
            pscp_comment = argv[i];
        }
        else if (strcmp(argv[i],"-url") == 0) {
            i++;
            pscp_sftp_url = argv[i];
        }
        else if (strcmp(argv[i],"-pkey") == 0) {
            i++;
            pscp_pkey_path = argv[i];
        }
        else if (strcmp(argv[i],"-stdout") == 0) {
            pscp_print_server_stdout = true;
        }
        else if (strcmp(argv[i],"-o") == 0) {
            i++;
            pscp_output_file = argv[i];
        }
        else if (strcmp(argv[i],"-h") == 0) {
            PrintUsage();
            success = false;
        }
        else {
            fprintf(stderr, "\nframework: Error, %s is not a valid option\n",argv[i]);
            PrintUsage();
            success = false;
        }
    }
    return success;
}

void PrintUsage()
{
    printf("\n");
    printf("client:\n"
           "\t-h \t print usage help\n\n"
           "\tRequired:\n"
           "\t\t-project ''      - Name of the project\n"
           "\t\t-comments ''     - Identifier/Message for audit log\n"
           "\t\t-epwd 'path'     - File path to the hsm encrypted password\n"
           "\t\t-url ''          - sftp url. Example: sftp://user@address\n"
           "\t\t-pkey 'path'     - File path to the *encrypted* private key file\n"
           "\tOptional:\n"
           "\t\t-payload <path>  - File path to the binary to be signed\n"
           "\t\t-param ''        - Parameters to be passed to the signing framework. Ex '-v' or '-h'\n"
           "\t\t-o <file>        - output file to save the return payload\n"
           "\t\t-stdout          - Displays the stdout from the server\n"
           "\tDebugging:\n"
           "\t\t-v               - verbose tracing\n"
           "\t\t-d               - debug mode - files will not be deleted\n");
    printf("\n");
    return;
}

// Verifies that the provided private key is encrypted.
bool PrivateKeyEncrypted(const char* privKeyPath)
{
    bool encrypted = false;
    FILE * key = fopen(privKeyPath, "r");
    fseek(key, 0, SEEK_END);
    int len = ftell(key);
    rewind(key);
    
    char * privKey = calloc(len+1, 1);
    if(privKey)
    {
        size_t read_len = fread(privKey, 1, len, key);
    
        if(read_len == len)
        {
            char* location = strstr(privKey, "ENCRYPTED");
            if(location)
            {
                encrypted = true;
            }
        }
        free(privKey);
        privKey = NULL;
    }
    return encrypted;
}

// Merges the directory, base, and tag into a single string. 
int GenerateFilename(char** filename, const char* directory, const char* base, const char* tag, bool verbose)
{
    int status = 0;
    if(filename && directory && base && tag)
    {
        if(*filename)
        {
            free(*filename);
            *filename = NULL;
        }
        size_t len = strlen(directory) + strlen(base) + strlen(tag) + 1;
        *filename = (char*)calloc(len, 1);

        if(*filename)
        {
            int rc = snprintf(*filename, len, "%s%s%s", directory, base, tag);
            if(rc <= 0)
            {
                free(*filename);
                *filename = NULL;
                fprintf(stderr, "ERROR: generation of filename failed:\n\tdirectory: %s\n\tbase: %s\n\ttag: %s\n", directory, base, tag);
                status = -1;
            }
            else
            {
                if(verbose) printf("Filename Generated: %s\n", *filename);
            }
        }
        else
        {
            fprintf(stderr, "ERROR: unable to allocate memory for filename:\n\tdirectory: %s\n\tbase: %s\n\ttag: %s\n", directory, base, tag);
            status = -1;
        }
    }
    else
    {
        fprintf(stderr, "ERROR: null value passed in as argument to generateFilename()\n");
        status = -1;
    }
    return status;
}


