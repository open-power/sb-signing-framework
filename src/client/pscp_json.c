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

#include <string.h>
#include <stdio.h>
#include <ctype.h>

#include <json-c/json.h>

#include "pscp_json.h"

char NibbleToChar(const unsigned char nibble, const bool verbose);
char * ByteArrayToHexAscii(const unsigned char * byte, const size_t len, const bool verbose);
int HexAsciiToByteArray(unsigned char** byte, size_t* byte_len, const char* ascii, const size_t ascii_len, bool verbose);
int BinaryFileToJsonObject(struct json_object** json, FILE* fp, const bool verbose);
void TrimWhitespace(char *str);

char NibbleToChar(const unsigned char nibble, const bool verbose)
{
    if(nibble > 0xF)
    {
        if(verbose) fprintf(stderr, "ERROR: Data passed into nibbleToChar() is larger than a nibble\n");
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

unsigned char CharToNibble(char c, bool verbose)
{
    c = toupper(c);
    if(c >= '0' && c <= '9')
    {
        return (c - '0');
    }
    else if(c >= 'A' && c <= 'F')
    {
        return (c - 'A' + 10);
    }
    else
    {
        return 0xFF;
    }
}

char * ByteArrayToHexAscii(const unsigned char * byte, const size_t len, const bool verbose)
{
    size_t out_len = len * 2;
    char* out_str = malloc(out_len + 1);
    bool success = true;

    for(size_t i = 0; (i < len) && success; i++)
    {
        unsigned char hi = (byte[i] >> 4) & 0xF;
        unsigned char lo = byte[i] & 0x0F;
        char char_hi = NibbleToChar(hi, verbose);
        char char_lo = NibbleToChar(lo, verbose);
        if((char_hi != 0) && (char_lo != 0))
        {
            out_str[2*i] = char_hi;
            out_str[(2*i)+1] = char_lo;
        }
        else
        {
            if(verbose) fprintf(stderr, "Error in parsing binary file at index %x\n", (unsigned int)i);
            success = false;
        }
    }
    out_str[out_len] = 0;

    if(!success)
    {
        free(out_str);
        out_str = NULL;
    }
    return out_str;
}

int HexAsciiToByteArray(unsigned char** byte, size_t* byte_len, const char* ascii, const size_t ascii_len, bool verbose)
{
    bool success = true;
    int status = 0;
    if(byte && *byte == NULL && byte_len && ascii)
    {
        if(ascii_len % 2 == 0)
        {
            *byte_len = ascii_len / 2;
            *byte = calloc(*byte_len, 1);

            for(size_t i = 0; (i < *byte_len) && success; i++)
            {
                unsigned char hi = CharToNibble(ascii[i*2], verbose);
                unsigned char lo = CharToNibble(ascii[(i*2)+1], verbose);
                if(hi != 0xFF && lo != 0xFF)
                {
                    (*byte)[i] = (0xF0 & (hi << 4)) | (0x0F & lo);
                }
                else
                {
                    if(verbose) fprintf(stderr, "Error in parsing binary from ascii at byte %lu\n", i);
                    success = false;
                }
            }
        }
        else
        {
            success = false;
        }
        if(!success && *byte)
        {
            free(*byte);
        }
    }
    else
    {
        success = false;
    }
    if(status == 0 && !success)
    {
        status = -1;
    }

    return status;
}

int BinaryFileToJsonObject(struct json_object** json, FILE* fp, const bool verbose)
{
    int status = 0;
    bool success = true;

    if(!(json && (*json == NULL) && fp))
    {
        success = false;
    }

    if(success)
    {
        fseek(fp, 0, SEEK_END);
        int fileSize = ftell(fp);
        rewind(fp);
        
        unsigned char* hashFile = malloc((fileSize+1));
        if(hashFile)
        {
            size_t read_len = fread(hashFile, 1, fileSize, fp);
            if(read_len == fileSize)
            {
                char* hashString = ByteArrayToHexAscii(hashFile, read_len, verbose);

                if(hashString)
                {
                    json_object* tmp = json_object_new_string(hashString);
                    if(tmp)
                    {
                        *json = tmp;
                    }
                    else
                    {
                        success = false;
                    }
                    free(hashString);
                }
                else
                {
                    success = false;
                }
            }
            else
            {
                success = false;
                if(verbose) fprintf(stderr, "ERROR: difference between byte read and file size. File size: %d, Bytes read: %d\n", (int)fileSize, (int)read_len);
            }
            free(hashFile);
        }
        else
        {
            success = false;
            if(verbose) fprintf(stderr, "ERROR: Unable to allocate memory in binaryFileToJsonObject\n");
        }
    }

    if(!success && status == 0)
    {
        status = -1;
    }

    return status;
}

int createJsonString(char** rtnStr, const char* pscp_project, const char* pscp_parameters, const char* pscp_user, const char* pscp_comment, const char* pscp_epwd_path, const char* pscp_payload_path, const bool verbose)
{
    bool success = true;
    int status = 0;
    struct json_object* json = NULL;
    char* nullStr = "";

    // Check for required arguments
    if(!(pscp_project && pscp_epwd_path && pscp_user && pscp_comment && rtnStr && (*rtnStr == NULL)))
    {
        success = false;
    }

    if(success)
    {
        json = json_object_new_object();
        if(!json)
        {
            success = false;
        }
    }

    if(success)
    {
        if(!pscp_parameters)
        {
            pscp_parameters = nullStr;
        }
    }

    // Copy the strings into json objects
    if(success)
    {
        struct json_object* json_project    = json_object_new_string(pscp_project);
        struct json_object* json_parameters = json_object_new_string(pscp_parameters);
        struct json_object* json_user       = json_object_new_string(pscp_user);
        struct json_object* json_comment    = json_object_new_string(pscp_comment);

        if(json_project && json_parameters && json_user && json_comment)
        {
            // Ownership of memory is passed to parent json_object
            json_object_object_add(json, "project",    json_project);
            json_object_object_add(json, "parameters", json_parameters);
            json_object_object_add(json, "user",       json_user);
            json_object_object_add(json, "comment",    json_comment);
        }
        else
        {
            success = false;
            if(json_project) json_object_put(json_project);
            if(json_parameters) json_object_put(json_parameters);
            if(json_user) json_object_put(json_user);
            if(json_comment) json_object_put(json_comment);
        }
    }
    
    // Copy epwd file into json
    if(success)
    {
        FILE * epwdFile = fopen(pscp_epwd_path, "r");
        if(epwdFile)
        {
            fseek(epwdFile, 0, SEEK_END);
            int fileSize = ftell(epwdFile);
            rewind(epwdFile);

            char* epwd = calloc(fileSize+1, 1);
            if(epwd)
            {
                int len = fread(epwd, 1, fileSize, epwdFile);
                if(len == fileSize)
                {
                    TrimWhitespace(epwd);
                    struct json_object* json_epwd = json_object_new_string(epwd);
                    if(json_epwd)
                    {
                        json_object_object_add(json, "epwd", json_epwd);
                    }
                    else
                    {
                        success = false;
                    }
                }
                else
                {
                    fprintf(stderr, "ERROR: Unable to read epwd file %s\n", pscp_epwd_path);
                    success = false;
                }
                free(epwd);
            }
            else
            {
                if(verbose) fprintf(stderr, "ERROR: unable to allocate memory for epwd\n");
                success = false;
            }
        }
        else
        {
            success = false;
            fprintf(stderr, "ERROR: Unable to open epwd file %s\n", pscp_epwd_path);
        }
    }
    // Read in payload file (optional)
    if(success && pscp_payload_path)
    {
        FILE* fp = fopen(pscp_payload_path, "r");
        if(fp)
        {
            struct json_object* json_payload = NULL;
            int rc = BinaryFileToJsonObject(&json_payload, fp, verbose);
            if(rc == 0)
            {
                json_object_object_add(json, "payload", json_payload);
            }
            else
            {
                if(verbose) fprintf(stderr, "ERROR: Unable to stringify binary file %s\n", pscp_payload_path);
                success = false;
                status = rc;
            }
            fclose(fp);
        }
        else
        {
            fprintf(stderr, "ERROR: Unable to open payload file %s\n", pscp_payload_path);
            success = false;
        }
    }

    if(success)
    {
        const char* json_string = json_object_to_json_string(json);;
        if(json_string)
        {
            // When the json object is free'd, the memory where the string comes from is also lost
            *rtnStr = strdup(json_string);
        }
        else
        {
            if(verbose) fprintf(stderr, "ERROR: Unable to generate serialized json string\n");
        }
    }
    if(json)
    {
        json_object_put(json);
    }

    if(!success && status == 0)
    {
        status = -1;
    }

    return status;
}

int parseServerResponse(const char * responseFile, unsigned char** res_payload, size_t* res_payload_len, char** res_stdout, size_t* res_stdout_len, int* res_retval, bool verbose)
{
    int retval = -1;
    if(responseFile && res_payload && stdout && res_retval && res_payload_len && res_stdout_len)
    {
        FILE * fp = fopen(responseFile, "r");
        if(fp)
        {
            fseek(fp, 0, SEEK_END);
            int fileSize = ftell(fp);
            rewind(fp);

            *res_payload = NULL;
            *res_stdout = NULL;

            char * response = malloc(fileSize+1);
            if(response)
            {
                size_t len = fread(response, 1, fileSize, fp);
                if(len == fileSize)
                {
                    struct json_object* json = json_tokener_parse(response);
                    if(json)
                    {
                        json_object* tmp = NULL;
                        json_object_object_get_ex(json, "result", &tmp);
                        if(tmp)
                        {
                            const char* json_string = json_object_get_string(tmp);
                            size_t json_string_len = strlen(json_string);
                            HexAsciiToByteArray(res_payload, res_payload_len, json_string, json_string_len, verbose);
                        }

                        tmp = NULL;
                        json_object_object_get_ex(json, "stdout", &tmp);
                        if(tmp)
                        {
                            *res_stdout = strdup(json_object_get_string(tmp));
                            *res_stdout_len = strlen(*res_stdout);
                        }

                        tmp = NULL;
                        json_object_object_get_ex(json, "retval", &tmp);
                        if(tmp) *res_retval = json_object_get_int(tmp);
                        retval = 0;

                        json_object_put(json);
                    }
                }
                free(response);
            }
            fclose(fp);
        }
    }
    return retval;
}

// Removes any whitespace in the string
void TrimWhitespace(char *str)
{
    char* p = NULL;
    char* q = NULL;
    if(str)
    {
        p = str;
        q = str;
        while(*q != 0)
        {
            if(isspace(*q))
            {
                q++;
            }
            else
            {
                *p = *q;
                p++;
                q++;
            }
        }
        *p = 0;
    }
}
