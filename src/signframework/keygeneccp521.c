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
#include <errno.h>
#include <time.h>

/* local */
#include "utils.h"
#include "cca_functions.h"
#include "cca_functions_ecc.h"
#include "cca_structures_ecc.h"

/* local prototypes */

long getArgs(const char **keyFilename,
	     const char **pubKeyFilename,
	     const char **userName,
	     const char **password,
	     int *verbose,
	     int argc,
	     char ** argv);
void printUsage(void);

/* global variables */
FILE *messageFile = NULL;
int verbose = FALSE;

/* see printUsage() for the program description */

int main(int argc, char** argv)
{
    long		rc = 0;		/* general return code */
    time_t 		start_time;
    int 		loggedIn = FALSE;	/* Boolean */

    /* command line arguments */
    const char	*keyFilename;		/* destination file for the generated key pair */
    const char	*pubKeyFilename;	/* destination file for the generated public key */
    const char	*userName;		/* optional user name */
    const char 	*password;		/* optional user password */

    messageFile = stdout;

    /* skeleton CCA key token, template parameters for the eventual generated key pair */
    long          	skeleton_key_length;
    unsigned char 	skeleton_key[3500];	/* CCA key template, maximum length */

    /* generated CCA key pair token */
    long          	generated_key_length;
    unsigned char 	generated_key[3500];	/* CCA ECC key token stream, maximum length */

    EccKeyTokenPublic 	eccKeyTokenPublic;

    /* initialization */
    setvbuf(stdout, 0, _IONBF, 0);	/* output may be going through pipe */
    start_time = time(NULL);
    printf("keygeneccp521: Key generation at %s", ctime(&start_time));
    
    /* get command line arguments */
    if (rc == 0) {
	rc = getArgs(&keyFilename, &pubKeyFilename,
		     &userName, &password,
		     &verbose, argc, argv);
    }
    /*
      Log in
    */
    if ((rc == 0) && (userName != NULL)) {
	if (verbose) printf("keygeneccp521: logging in to coprocessor as %s\n", userName);
	rc = Login_Control(TRUE,		/* logIn */
			   userName, password);
    }
    if ((rc == 0) && (userName != NULL)) {
	loggedIn = TRUE;
    }
    /* build a skeleton key token */
    if (rc == 0) {
	skeleton_key_length = sizeof(skeleton_key);
	rc = PKA_Key_Token_Build_ECCP521(&skeleton_key_length, skeleton_key);
    }
    /* generate an ECC key pair using the skeleton key token */
    if (rc == 0) {
	generated_key_length =  sizeof(generated_key);
	rc = PKA_Key_Generate(&generated_key_length, generated_key,
			      skeleton_key_length, skeleton_key);
    }
    /* store the key token in a file */
    if (rc == 0) {
	rc = File_WriteBinaryFile(generated_key, generated_key_length, keyFilename);
    }    
    /* extract the public key from the key token */
    if (rc == 0) {
	if (verbose) printf("keygeneccp521: extract the public key from the key token\n");
	rc = getPKA96EccPublicKey(&eccKeyTokenPublic,	/* output: CCA structure */
				  generated_key_length,		
				  generated_key);		/* input: PKA96 key token */
    }
    /* verify the public key length */
    if (rc == 0) {
	if (verbose) printf("keygeneccp521: public key length %u\n", eccKeyTokenPublic.pLength);
	if (eccKeyTokenPublic.pLength != ECC_PRIME_521) {
	    printf("keygeneccp521: Error public key length invalid\n");
	    rc = ERROR_CODE;
	}
    }
    /* store the public key token in a file */
    if (rc == 0) {
	rc = File_WriteBinaryFile(eccKeyTokenPublic.publicKey, eccKeyTokenPublic.qLen,
				  pubKeyFilename);
    }
    /* since the program exits, this is probably not necessary */
    if (loggedIn) {
	rc = Login_Control(FALSE,		/* logIn */
			   userName, password);
    }
    /* exit handling */
    if (rc == 0) {
	printf("keygeneccp521: Success\n");
	return EXIT_SUCCESS;
    }
    else {
	printf("keygeneccp521: Failure\n");
	return EXIT_FAILURE;
    }
}

/* getArgs() parses the command line arguments into the supplied parameters

 */

long getArgs(const char **keyFilename,
	     const char **pubKeyFilename,
	     const char **userName,
	     const char **password,
	     int *verbose,
	     int argc,
	     char **argv)
{
    long	rc = 0;
    int 	i;

    /* command line argument defaults */
    *keyFilename = NULL;
    *pubKeyFilename = NULL;
    *userName = NULL;
    *password = NULL;
    *verbose = FALSE;
    
    /* get the command line arguments */
    for (i=1 ; (i<argc) && (rc == 0) ; i++) {
	if (strcmp(argv[i],"-k") == 0) {
	    i++;
	    if (i < argc) {
		*keyFilename = argv[i];
	    }
	    else {
		printf("-k option (key file name) needs a value\n");
		rc = ERROR_CODE;
	    }
	}
	else if (strcmp(argv[i],"-p") == 0) {
	    i++;
	    if (i < argc) {
		*pubKeyFilename = argv[i];
	    }
	    else {
		printf("-p option (public key file name) needs a value\n");
		rc = ERROR_CODE;
	    }
	}
	else if (strcmp(argv[i],"-u") == 0) {
	    i++;
	    if (i < argc) {
		*userName = argv[i];
	    }
	    else {
		printf("-u (user name and password needs a user name\n");
		rc = ERROR_CODE;
	    }
	    i++;
	    if (i < argc) {
		*password = argv[i];
	    }
	    else {
		printf("-u (user name and password needs a password\n");
		rc = ERROR_CODE;
	    }
	}
	else if (strcmp(argv[i],"-h") == 0) {
	    printUsage();
	    rc = ERROR_CODE;
	}
	else if (strcmp(argv[i],"-v") == 0) {
	    *verbose = TRUE;
	}
	else {
	    printf("\n%s is not a valid option\n",argv[i]);
	    printUsage();
	    rc = ERROR_CODE;
	}
    }
    /* verify command line arguments */
    if (rc == 0) {
	if (*keyFilename == NULL) {
	    printf("-k option (key file name) must be specified\n");
	    rc = ERROR_CODE;
	}
    }
    if (rc == 0) {
	if (*pubKeyFilename == NULL) {
	    printf("-p option (public key file name) must be specified\n");
	    rc = ERROR_CODE;
	}
    }
    if (rc == 0) {
	if (*userName != NULL) {
	    if (strlen(*userName) > 8) {
		printf("-u option user name must be <= 8 bytes\n");
		rc = ERROR_CODE;
	    }
	}
    }
    return rc;
}

void printUsage()
{
    printf("\n");
    printf("keygeneccp521 -k key_token_file_name -p public_key_file_name\n"
	   "\t[-u user password]\n"
	   "\t[-v] [-s]\n");
    printf("\n");
    printf("Example: keygeneccp521 -k key.tok -p pub.bin\n");
    printf("\n");
    printf("Generates an ECC P-521 signing key token using CCA, and stores the\n"
	   "resulting key pair token in the key token file.  The public key\n"
	   "is stored in binary in the public key token file.\n"
	   "\n"
	   "If -u is specified, the program logs on to the coprocessor using the specified user\n"
	   "name and password.  If -u is not specified, the DEFAULT profile is used\n");
    printf("\n");
    printf("\t-k key token file name\n");
    printf("\t-p public key modulus file name\n");
    printf("\t-u user name and password\n");
    printf("\t-h help\n");
    printf("\t-v enable debug tracing\n");
    printf("\n");
    return;
}

