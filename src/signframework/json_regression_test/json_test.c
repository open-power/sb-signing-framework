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

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <limits.h>
#include <time.h>

#include <json-c/json.h>

struct sign_request
{
    char* comment;
    char* epwd;
    char* parameters;
    char* payload;
    char* project;
    char* user;
};

struct sign_response
{
    char* output;
    char* payload;
    int retval;
};

struct test_case
{
    struct sign_request request;
    struct sign_response response;
    int expectedRc;
    bool resultExpected;
    char* name;
};

bool GetArgs(int argc, char **argv);
void PrintUsage();
bool RunTestCase(struct test_case* test_case, char* dropbox, int* num_failures);
bool GetRequestStructFromJson(struct sign_request* request, const char* json_string);
bool GetResponseStructFromJson(struct sign_response* request, const char* json_string);
int FileSize(FILE* fp);

char* dropbox_path = NULL;
char* valid_json = NULL;
bool verbose = false;
bool debug = false;
char* STR_OVERFLOW = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";

int main(int argc, char** argv)
{
    {
        bool success = GetArgs(argc, argv);
        if(!success)
        {
            return -1;
        }
    }

    struct test_case valid_case;
    int failures = 0;

    {
        bool success = true;
        valid_case.expectedRc = 0;
        valid_case.resultExpected = true;
        valid_case.name = "(Valid) Rerun of provided request";
        FILE* fp = fopen(valid_json, "r");
        if(fp)
        {
            int len = FileSize(fp);
            char* str = calloc(len+1, 1);
            if(str)
            {
                fread(str, 1, len, fp);
                success = GetRequestStructFromJson(&(valid_case.request), str);
                if(success)
                {
                    success = RunTestCase(&valid_case, dropbox_path, &failures);
                }
                else
                {
                    printf("Error in parsing the json file\n");
                    success = false;
                }
            }
            else
            {
                printf("Error in memory allocation\n");
                success = false;
            }
            fclose(fp);
        }
        else
        {
            printf("Unable to open file %s\n", valid_json);
            success = false;
        }
        if(!success)
        {
            printf("Provided \"good\" json failed. Aborting testing.\n");
            return -1;
        }
    }

    {
        struct test_case test = valid_case;
        test.expectedRc = 1;
        test.resultExpected = false;
        test.request.comment = STR_OVERFLOW;
        test.request.epwd = STR_OVERFLOW;
        test.request.parameters = STR_OVERFLOW;
        test.request.payload = STR_OVERFLOW;
        test.request.project = STR_OVERFLOW;
        test.request.user = STR_OVERFLOW;
        test.name = "Dropbox File Overflow";
        RunTestCase(&test, dropbox_path, &failures);
    }
    {
        struct test_case test = valid_case;
        test.expectedRc = 1;
        test.resultExpected = false;
        test.request.user = STR_OVERFLOW;
        test.name = "User Overflow";
        RunTestCase(&test, dropbox_path, &failures);
    }
    {
        struct test_case test = valid_case;
        test.expectedRc = 1;
        test.resultExpected = false;
        test.request.parameters = STR_OVERFLOW;
        test.name = "Parameters Overflow";
        RunTestCase(&test, dropbox_path, &failures);
    }
    {
        struct test_case test = valid_case;
        test.expectedRc = 1;
        test.resultExpected = false;
        test.request.epwd = STR_OVERFLOW;
        test.name = "EPWD Overflow";
        RunTestCase(&test, dropbox_path, &failures);
    }
    {
        struct test_case test = valid_case;
        test.expectedRc = 1;
        test.resultExpected = false;
        test.request.comment = STR_OVERFLOW;
        test.name = "Comment Overflow";
        RunTestCase(&test, dropbox_path, &failures);
    }
    {
        struct test_case test = valid_case;
        test.expectedRc = 1;
        test.resultExpected = false;
        test.request.project = STR_OVERFLOW;
        test.name = "Project Overflow";
        RunTestCase(&test, dropbox_path, &failures);
    }
    {
        struct test_case test = valid_case;
        test.expectedRc = 1;
        test.resultExpected = false;
        test.request.payload = NULL;
        test.name = "Null payload";
        RunTestCase(&test, dropbox_path, &failures);
    }
    {
        struct test_case test = valid_case;
        test.expectedRc = 1;
        test.resultExpected = false;
        test.request.project = NULL;
        test.name = "Null project";
        RunTestCase(&test, dropbox_path, &failures);
    }
    {
        struct test_case test = valid_case;
        test.expectedRc = 0;
        test.resultExpected = true;
        test.request.parameters = "garbage";
        test.name = "Garbage parameters";
        RunTestCase(&test, dropbox_path, &failures);
    }
    {
        struct test_case test = valid_case;
        test.expectedRc = 1;
        test.resultExpected = false;
        test.request.comment = NULL;
        test.name = "Null Comment";
        RunTestCase(&test, dropbox_path, &failures);
    }
    {
        struct test_case test = valid_case;
        test.expectedRc = 1;
        test.resultExpected = false;
        test.request.comment = NULL;
        test.request.epwd = NULL;
        test.request.parameters = NULL;
        test.request.payload = NULL;
        test.request.project = NULL;
        test.request.user = NULL;
        test.name = "Empty JSON";
        RunTestCase(&test, dropbox_path, &failures);
    }
    {
        struct test_case test = valid_case;
        test.expectedRc = 2;
        test.resultExpected = false;
        test.request.comment = "";
        test.request.epwd = "";
        test.request.parameters = "";
        test.request.payload = "";
        test.request.project = "";
        test.request.user = "";
        test.name = "Empty Values";
        RunTestCase(&test, dropbox_path, &failures);
    }
    {
        struct test_case test = valid_case;
        test.expectedRc = 1;
        test.resultExpected = false;
        test.request.epwd = "bad";
        test.name = "Invalid EPWD (3 nibbles)";
        RunTestCase(&test, dropbox_path, &failures);
    }
    {
        struct test_case test = valid_case;
        test.expectedRc = 1;
        test.resultExpected = false;
        test.request.epwd = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
        test.name = "Invalid EPWD (correct length)";
        RunTestCase(&test, dropbox_path, &failures);
    }
    {
        struct test_case test = valid_case;
        test.expectedRc = 0;
        test.resultExpected = true;
        test.request.comment = "";
        test.name = "Empty Comment";
        RunTestCase(&test, dropbox_path, &failures);
    }
    {
        struct test_case test = valid_case;
        test.expectedRc = 1;
        test.resultExpected = false;
        test.request.epwd = "";
        test.name = "Empty epwd";
        RunTestCase(&test, dropbox_path, &failures);
    }
    {
        struct test_case test = valid_case;
        test.expectedRc = 0;
        test.resultExpected = true;
        test.request.parameters = "";
        test.name = "Empty parameters";
        RunTestCase(&test, dropbox_path, &failures);
    }
    {
        struct test_case test = valid_case;
        test.expectedRc = 1;
        test.resultExpected = false;
        test.request.payload = "";
        test.name = "Empty payload";
        RunTestCase(&test, dropbox_path, &failures);
    }
    {
        struct test_case test = valid_case;
        test.expectedRc = 2;
        test.resultExpected = false;
        test.request.project = "";
        test.name = "Empty project";
        RunTestCase(&test, dropbox_path, &failures);
    }
    {
        struct test_case test = valid_case;
        test.resultExpected = true;
        test.request.user = "";
        test.name = "Empty user";
        RunTestCase(&test, dropbox_path, &failures);
    }
    {
        struct test_case test = valid_case;
        test.resultExpected = false;
        test.expectedRc = 1;
        test.request.epwd = NULL;
        test.name = "Null epwd";
        RunTestCase(&test, dropbox_path, &failures);
    }
    {
        struct test_case test = valid_case;
        test.resultExpected = false;
        test.expectedRc = 1;
        test.request.parameters = NULL;
        test.name = "Null parameters";
        RunTestCase(&test, dropbox_path, &failures);
    }
    {
        struct test_case test = valid_case;
        test.expectedRc = 1;
        test.resultExpected = false;
        test.request.user = NULL;
        test.name = "Null user";
        RunTestCase(&test, dropbox_path, &failures);
    }
    {
        struct test_case test = valid_case;
        test.expectedRc = 2;
        test.resultExpected = false;
        test.request.project = "Garbage";
        test.name = "Garbage project";
        RunTestCase(&test, dropbox_path, &failures);
    }

    printf("Number of failures: %d\n", failures);

    return failures;
}

bool GetArgs(int argc, char **argv)
{
    bool success = true;
    for(int i = 1; (i < argc) && success; i++)
    {
        if (strcmp(argv[i],"-dropbox") == 0) {
            i++;
            dropbox_path = argv[i];
        }
        else if (strcmp(argv[i],"-json") == 0) {
            i++;
            valid_json = argv[i];
        }
        else if (strcmp(argv[i],"-v") == 0) {
            verbose = true;
        }
        else if (strcmp(argv[i],"-d") == 0) {
            debug = true;
        }
        else
        {
            PrintUsage();
            success = false;
        }
    }
    // Check for required arguments
    if(!dropbox_path || !valid_json)
    {
        printf("Not all required argments found\n");
        success = false;
    }
    return success;
}

void PrintUsage()
{
    printf("\t-json 'path to good json'\n"
            "\t -dropbox 'path to run in'\n");
    return;
}

bool AddStringToJson(struct json_object* json, const char* key, const char* value)
{
    bool success = false;
    if(json && key && value)
    {
        struct json_object* obj = json_object_new_string(value);
        if(obj)
        {
            json_object_object_add(json, key, obj);
            success = true;
        }
        else
        {
            printf("ERROR in object creation\n");
        }
    }
    else
    {
        printf(" error in addstirngtojson params\n");
    }
    return success;
}

// Will create a json from the struct. If a value is NULL, no entry will be made.
bool CreateJsonString(char** json_string, const struct sign_request request)
{
    bool success = true;
    struct json_object* json = NULL;

    if(json_string)
    {
    }
    else
    {
        printf("Error in parameters\n");
        success = false;
    }

    json = json_object_new_object();
    if(json == NULL)
    {
        success = false;
    }

    if(success && request.project)
    {
        success = AddStringToJson(json, "project", request.project);
    }
    if(success && request.parameters)
    {
        success = AddStringToJson(json, "parameters", request.parameters);
    }
    if(success && request.user)
    {
        success = AddStringToJson(json, "user", request.user);
    }
    if(success && request.epwd)
    {
        success = AddStringToJson(json, "epwd", request.epwd);
    }
    if(success && request.payload)
    {
        success = AddStringToJson(json, "payload", request.payload);
    }
    if(success && request.comment)
    {
        success = AddStringToJson(json, "comment", request.comment);
    }

    if(success)
    {
        const char* str = json_object_to_json_string(json);
        if(json_string)
        {
            *json_string = strdup(str);
        }
        else
        {
            printf("ERROR in convert\n");
            success = false;
        }
    }

    if(json)
    {
        json_object_put(json);
    }

    return success;
}

int FileSize(FILE* fp)
{
    int len = -1;
    if(fp)
    {
        size_t pos = ftell(fp);
        fseek(fp, 0, SEEK_END);
        len = ftell(fp);
        fseek(fp, pos, SEEK_SET);
    }
    return len;
}

bool RunTestCase(struct test_case* test_case, char* dropbox, int* num_failures)
{
    char filename[NAME_MAX];
    char workingDir[PATH_MAX];
    char* json_string = NULL;
    bool success = true;
    time_t timestamp =time(NULL);

    // Change working directory to inside the dropbox
    getcwd(workingDir, PATH_MAX);
    chdir(dropbox);

    // generate json
    success = CreateJsonString(&json_string, test_case->request);

    // create request file
    if(success)
    {
        snprintf(filename, NAME_MAX, "test_%lx.request", timestamp);
        FILE* request_file = fopen(filename, "w");
        if(request_file)
        {
            fwrite(json_string, 1, strlen(json_string), request_file);
            fclose(request_file);
            if (verbose) printf("===== REQUEST =====\n%s\n===== REQUEST =====\n", json_string);
        }
        else
        {
            printf("Unable to open .request file\n");
            success = false;
        }
    }

    // create request go file
    if(success)
    {
        snprintf(filename, NAME_MAX, "test_%lx.request.go", timestamp);
        FILE* request_go_file = fopen(filename, "w");
        if(request_go_file)
        {
            fclose(request_go_file);
        }
        else
        {
            printf("Unable to open .request.go file\n");
            success = false;
        }
    }

    // wait for response
    if(success)
    {
        success = false;
        for( int i = 0; i < 5; i++)
        {
            snprintf(filename, NAME_MAX, "test_%lx.response.go", timestamp);
            FILE* response_go_file = fopen(filename, "r");
            if(response_go_file)
            {
                fclose(response_go_file);
                success = true;
                break;
            }
            else
            {
                if(errno == ENOENT)
                {
                    sleep(5);
                }
                else
                {
                    success = false;
                    break;
                }
            }
        }
        if(!success)
        {
            printf("Did not find .response.go file\n");
        }
    }

    // parse response, populate struct
    if(success)
    {
        snprintf(filename, NAME_MAX, "test_%lx.response", timestamp);
        FILE* response_file = fopen(filename, "r");
        if(response_file)
        {
            int file_size = FileSize(response_file);
            char* response_string = calloc(file_size + 1, 1);
            fread(response_string, 1, file_size, response_file);
            if (verbose) printf("===== RESPONSE =====\n%s\n===== RESPONSE =====\n", response_string);
            success = GetResponseStructFromJson(&test_case->response, response_string);
            if(!success)
            {
                printf("Unable to populate response struct\n");
            }
        }
        else
        {
            printf("Unable to open .response file\n");
            success = false;
        }
    }
    // compare expected & actual rc, return success
    if(success && test_case->response.retval != test_case->expectedRc)
    {
        printf("Unexpected RC (%d) from server. Expected %d\n", test_case->response.retval, test_case->expectedRc);
        success = false;
    } else if (success && test_case->resultExpected && test_case->response.payload == NULL) {
        printf("Payload missing from server.\n");
        success = false;
    } else if (success && !test_case->resultExpected && test_case->response.payload != NULL) {
        printf("Unexpected payload from server.\n");
        success = false;
    }

    if(success)
    {
        printf("%s: PASS\n", test_case->name);
    }
    else
    {
        printf("%s: FAIL\n", test_case->name);
        (*num_failures)++;
        exit(1);
    }

    if (verbose) printf("\n\n");

    // Restore the working directory
    chdir(workingDir);

    return success;
}

bool GetStringFromJson(char** retval, struct json_object* json, const char* key)
{
    bool success = false;
    if(retval && json && key)
    {
        struct json_object* tmp = NULL;
        json_object_object_get_ex(json, key, &tmp);
        if(tmp)
        {
            const char* json_string = json_object_get_string(tmp);
            if(json_string)
            {
                *retval = strdup(json_string);
                success = true;
            }
        }
    }
    return success;
}

bool GetIntFromJson(int* retval, struct json_object* json, const char* key)
{
    bool success = false;
    if(retval && json && key)
    {
        struct json_object* tmp = NULL;
        json_object_object_get_ex(json, key, &tmp);
        if(tmp)
        {
            *retval = json_object_get_int(tmp);
            success = true;
        }
    }
    return success;
}

bool GetRequestStructFromJson(struct sign_request* request, const char* json_string)
{
    bool success = true;
    if(request && json_string)
    {
        struct json_object* json = json_tokener_parse(json_string);
        if(json)
        {
            // parse each field

            char* project = NULL;
            char* parameters = NULL;
            char* user = NULL;
            char* epwd = NULL;
            char* payload = NULL;
            char* comment = NULL;
            success &= GetStringFromJson(&project,    json, "project");
            success &= GetStringFromJson(&parameters, json, "parameters");
            success &= GetStringFromJson(&user,       json, "user");
            success &= GetStringFromJson(&epwd,       json, "epwd");
            success &= GetStringFromJson(&payload,    json, "payload");
            success &= GetStringFromJson(&comment,    json, "comment");

            if(project && parameters && user && epwd && payload && comment)
            {
                request->comment    = comment;
                request->epwd       = epwd;
                request->parameters = parameters;
                request->payload    = payload;
                request->project    = project;
                request->user       = user;
            }
            else
            {
                success = false;
            }
            json_object_put(json); // Frees the json_object's memory
        }
        else
        {
            success = false;
        }
    }
    else
    {
        success = false;
    }

    return success;
}

bool GetResponseStructFromJson(struct sign_response* response, const char* json_string)
{
    bool success = true;
    if(response && json_string)
    {
        struct json_object* json = json_tokener_parse(json_string);
        if(json)
        {
            // parse each field
            char* out = NULL;
            char* payload = NULL;
            int retval;
            success &= GetStringFromJson(&out, json, "stdout");
            bool has_payload = GetStringFromJson(&payload, json, "result");
            success &= GetIntFromJson(&retval, json, "retval");

            if(has_payload)
            {
                response->payload = payload;
            }
            else
            {
                response->payload = NULL;
            }
            if(success)
            {
                response->output  = out;
                response->retval  = retval;
            }
            else
            {
                printf("Could not extract values from parsed json\n");
            }
            json_object_put(json); // Frees the json_object's memory
        }
        else
        {
            printf("GetResponseStructFromJson: Unable to parse string\n");
            success = false;
        }
    }
    else
    {
        printf("GetResponseStructFromJson: Null arguments\n");
        success = false;
    }
    return success;
}
