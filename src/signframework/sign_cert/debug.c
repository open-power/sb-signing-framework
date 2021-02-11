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

#include "utils.h"

#include "debug.h"

extern FILE* messageFile;

/* PrintAll() prints 'message', the length, and then the entire byte array 'buff'
 */

void PrintAll(FILE *file, const char *message, unsigned long length, const unsigned char *buff)
{
    unsigned long i;

    if (buff != NULL) {
        fprintf(file, "%s length %lu\n ", message, length);
        for (i = 0 ; i < length ; i++) {
            if (i && !( i % 16 )) {
                fprintf(file, "\n ");
            }
            fprintf(file, "%.02x ",buff[i]);
        }
        fprintf(file, "\n");
    }
    else {
        fprintf(file, "%s null\n", message);
    }
    return;
}

/* sprintAll() hex prints the byte array 'buff' to 'string'.  'string' must be long enough to hold
   the entire array.  length * 4 should be safe, two characters, a space, and some newlines.
*/

void sprintAll(char *string, unsigned long length, const unsigned char* buff)
{
    unsigned long i;

    if (buff != NULL) {
        for (i = 0 ; i < length ; i++) {
            if (i && !( i % 16 )) {
                sprintf(string, "\n ");
                string += strlen("\n ");
            }
            sprintf(string, "%.2X ",buff[i]);
            string += 3;
        }
        sprintf(string, "\n");
        string += strlen("\n ");
    }
    else {
        sprintf(string, "null\n");
    }
    return;
}

/* Hook to simulate an error */
int makeError = FALSE;		/* user sets to create an error */
static int letError = TRUE;	/* lets user create only one error */

int GetError(int statusIn)
{
    if (makeError && letError) {
        letError = FALSE;
        return statusIn;
    }
    else {
        return 0;
    }
}
