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
#include <errno.h>

#include "cca_functions.h"
#include "utils.h"

/* local prototypes */

int GetArgs(int argc,
	    char **argv);
void PrintUsage(void);

/* global variables */

FILE *messageFile = NULL;
int verbose = TRUE;
int debug = TRUE;

int main(int argc, char** argv)
{
    int 		rc = 0;

    messageFile = stdout;	/* trace always goes to stdout */

    if (rc == 0) {
	rc = GetArgs(argc, argv);
    }    
    /* generate a master key */
    if (rc == 0) {
	if (verbose) fprintf(messageFile, "Setting the clock\n");
	rc = Crypto_Facility_SetClock();
    }
    fprintf(messageFile, "\tsetclock rc %d\n\n", rc);
    return rc;
}

/* GetArgs() gets the command line arguments
   
   Returns ERROR_CODE on error.
*/
 
int GetArgs(int argc,
	    char **argv)
{
    int		rc = 0;
    int 	i;

    /* command line argument defaults */
    verbose = FALSE;

    /* get the command line arguments */
    for (i=1 ; (i<argc) && (rc == 0) ; i++) {
	if (strcmp(argv[i],"-h") == 0) {
	    PrintUsage();
	    rc = ERROR_CODE;
	}
	else if (strcmp(argv[i],"-v") == 0) {
	    verbose = TRUE;
	}
	else {
	    printf("setclock: Error, %s is not a valid option\n", argv[i]);
	    PrintUsage();
	    rc = ERROR_CODE;
	}
    }
    return rc;
}

void PrintUsage()
{
    printf("\n");
    printf("setclock:\n"
	   "\t[-v - verbose tracing]\n"
	   "\t[-h - print usage help]\n");
    printf("\n");
    printf("\n");
    return;
}
