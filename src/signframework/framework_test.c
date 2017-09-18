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

/* This program is a stub 'signer' application used to test the Notes code signer framework.  It
   simply prints a 'hello' message and then the command line arguments it was called with.
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>

#include "openssl/evp.h"

#include "cca_functions.h"
#include "cca_structures.h"
#include "ossl_functions.h"
#ifdef ADD_ECC
#include "cca_structures_ecc.h"
#include "cca_functions_ecc.h"
#include "ossl_functions_ecc.h"
#endif
#include "utils.h"
#include "debug.h"

/* local prototypes */

int EchoArgs(int argc, char** argv);
int CheckAuxArgs(int argc, char** argv);
int GetArgs(const char **outputBodyFilename,
            const char **usr,
            const char **password,
            const char **projectLogFileName,
            const char **projectAuxConfigFileName,
            const char **sender,
            const char **project,
            const char **keyFileName,
            const char **inputAttachmentFileName,
            const char **outputAttachmentFileName,
            int *verbose,
            int argc,
            char **argv);
int GetAuxArgs(char **signAlgorithm,
               const char *projectAuxConfigFileName);
void PrintUsage(void);

int SignSample(const char 	*keyFileName,
               const char 	*inputAttachmentFileName,
               const char 	*outputAttachmentFileName,
               FILE 		*projectLogFile,
               const char	*signAlgorithm);
int SignSampleRSA(unsigned char 	*keyToken,
                  size_t		keyTokenLength,
                  unsigned char		*testMessage,
                  size_t		testMessageLength,
                  const char 		*outputAttachmentFileName,
                  FILE 			*projectLogFile);
#ifdef ADD_ECC
int SignSampleECCP521(unsigned char 	*keyToken,
                      size_t		keyTokenLength,
                      unsigned char	*testMessage,
                      size_t		testMessageLength,
                      const char 	*outputAttachmentFileName,
                      FILE 		*projectLogFile);

#endif

/* This table describes the parameters added by the auxiliary configuration file.  They should not
   be in the input body, as this might indicate a misguided or malicious attempt to override the
   project auxiliary configuration file values.  It might also indicate a program design error,
   where a framework value clashes with the project auxiliary configuration file values.

   Use this table to screen the user input.
*/

static const char *claTable[] = {
    "-sign_algorithm",
};


/* messages are traced here */
FILE *messageFile = NULL;
int  verbose = FALSE;
int debug = FALSE;

int main(int argc, char** argv)
{
    int 	rc = 0;
    const char  *usr = NULL;
    const char 	*password = NULL;
    const char 	*projectLogFileName = NULL;
    FILE	*projectLogFile = NULL;			/* closed @1 */
    const char 	*projectAuxConfigFileName = NULL;
    char 	*signAlgorithm = NULL;			/* freed @2 */
    time_t      log_time;
    const char 	*sender = NULL;
    const char 	*project = NULL;
    const char 	*keyFileName = NULL;
    const char 	*inputAttachmentFileName = NULL;
    const char 	*outputAttachmentFileName = NULL;
    const char 	*outputBodyFilename = NULL;

    messageFile = stdout;

    /* OpenSSL_add_all_algorithms(); */
    /* get caller's command line arguments */
    if (rc == 0) {
        rc = GetArgs(&outputBodyFilename,
                     &usr,
                     &password,
                     &projectLogFileName,
                     &projectAuxConfigFileName,
                     &sender,
                     &project,
                     &keyFileName,
                     &inputAttachmentFileName,
                     &outputAttachmentFileName,
                     &verbose,
                     argc, argv);
    }
    /* check that no command line arguments clash with those in the project auxiliary configuration
       file */
    if (rc == 0) {
        rc = CheckAuxArgs(argc, argv);
    }
    /* get additional parameters from the project auxiliary configuration file */
    if (rc == 0) {
        rc = GetAuxArgs(&signAlgorithm,		/* freed @2 */
                        projectAuxConfigFileName);
    }
    /* sample - log in to CCA */
    if (rc == 0) {
        if (verbose) fprintf(messageFile, "Hello from framework_test\n");
        if (verbose) fprintf(messageFile, "Logging in with user name %s\n", usr);
        rc = Login_Control(TRUE,	/* log in */
                           usr,		/* CCA profile */
                           password);	/* CCA password */
    }
    /* sample audit logging */
    if (rc == 0) {
        if (verbose) fprintf(messageFile, "Opening audit log %s\n", projectLogFileName);
        projectLogFile = fopen(projectLogFileName, "a");		/* closed @1 */
        if (projectLogFile == NULL) {
            fprintf(messageFile, "ERROR1015: Cannot open audit log %s, %s\n",
                    projectLogFileName, strerror(errno));
            rc = ERROR_CODE;
        }
    }
    /* update audit log, begin this entry */
    if (projectLogFile != NULL) {
        if (verbose) fprintf(messageFile, "Updating audit log\n");
        log_time = time(NULL);
        fprintf(projectLogFile, "\n%s", ctime(&log_time));
        fprintf(projectLogFile, "\tSender: %s\n", sender);
        fprintf(projectLogFile, "\tProject: %s\n", project);
        fprintf(projectLogFile, "\tProgram: %s\n", argv[0]);
        fprintf(projectLogFile, "\tKey file: %s\n", keyFileName);
        fprintf(projectLogFile, "\tProfile %s\n", usr);
    }
    /*
      sample  - sign and verify
    */
    if (rc == 0) {
        if (verbose) fprintf(messageFile, "Signing\n");
        if (verbose) fprintf(messageFile, "  Input attachment %s\n", inputAttachmentFileName);
        if (verbose) fprintf(messageFile, "  Output attachment %s\n", outputAttachmentFileName);
        rc = SignSample(keyFileName,
                        inputAttachmentFileName,
                        outputAttachmentFileName,
                        projectLogFile,
                        signAlgorithm);
    }
    /* sample log out of CCA */
    if (rc == 0) {
        if (verbose) fprintf(messageFile, "Logging out with user name %s\n", usr);
        rc = Login_Control(FALSE,	/* log out */
                           usr,		/* CCA profile */
                           NULL);	/* password */
    }
    /* stub processor prints the command line arguments */
    if (rc == 0) {
        rc = EchoArgs(argc, argv);
    }
    fprintf(messageFile, "Return code: %u\n", rc);
    /* update audit log */
    if (projectLogFile != NULL) {
        fprintf(projectLogFile, "\tReturn code: %d\n", rc);
    }
    /* clean up */
    if (projectLogFile != NULL) {
        fclose(projectLogFile);		/* @1 */
    }
    free(signAlgorithm);		/* @2 */
    if (messageFile != stdout) {
        fflush(messageFile);
        fclose(messageFile);
    }

    return rc;
}

/* SignSample() is sample code to demonstrate CCA signing and verification

 */

int SignSample(const char 	*keyFileName,
               const char 	*inputAttachmentFileName,
               const char 	*outputAttachmentFileName,
               FILE 		*projectLogFile,
               const char	*signAlgorithm)
{
    int		rc = 0;
    /*
      signing key
    */
    unsigned char 	*keyToken = NULL;		/* CCA key token */
    size_t		keyTokenLength;
    /*
      data to be signed
    */
    unsigned char 	*testMessage = NULL;
    size_t		testMessageLength;

    /* get the CCA key token */
    if (rc == 0) {
        if (verbose) fprintf(messageFile, "SignSample: Reading CCA key token file %s\n",
                             keyFileName);
        rc = File_ReadBinaryFile(&keyToken, &keyTokenLength, 2000, keyFileName); /* freed @1 */
        if (rc != 0) {
            fprintf(messageFile, "ERROR1026: Could not open key file: %s\n", keyFileName);
        }
    }
    /* get the input message */
    if (rc == 0) {
        if (verbose) fprintf(messageFile, "SignSample: Reading input file %s\n",
                             inputAttachmentFileName);
        rc = File_ReadBinaryFile(&testMessage , &testMessageLength, 10000,
                                 inputAttachmentFileName);	/* freed @2 */
        if (rc != 0) {
            fprintf(messageFile, "ERROR1027 while opening the attachment, file: %s\n",
                    inputAttachmentFileName);
        }
    }
    if (rc == 0) {
        if (strcmp(signAlgorithm, "rsa") == 0) {
            rc = SignSampleRSA(keyToken,
                               keyTokenLength,
                               testMessage,
                               testMessageLength,
                               outputAttachmentFileName,
                               projectLogFile);
        }
#ifdef ADD_ECC
        else if (strcmp(signAlgorithm, "eccp521") == 0) {
            rc = SignSampleECCP521(keyToken,
                                   keyTokenLength,
                                   testMessage,
                                   testMessageLength,
                                   outputAttachmentFileName,
                                   projectLogFile);
        }
#endif
        else {
            fprintf(messageFile,
                    "ERROR1022: Unsupported signature algorithm: %s\n",
                    signAlgorithm);
            rc = ERROR_CODE;
        }
    }
    /* clean up */
    free(keyToken);	/* @1 */
    free(testMessage);	/* @2 */
    return rc;
}

int SignSampleRSA(unsigned char 	*keyToken,
                  size_t		keyTokenLength,
                  unsigned char		*testMessage,
                  size_t		testMessageLength,
                  const char 		*outputAttachmentFileName,
                  FILE 			*projectLogFile)
{
    int		rc = 0;

    int		valid;			/* true if signature verifies */

    RsaKeyTokenPublic 	rsaKeyTokenPublic;	/* CCA public key structure */
    /* http://tools.ietf.org/html/draft-ietf-smime-sha2-11 */

    /* SHA-1 with RSA OID (Object Identifier) */
    static const unsigned char sha1_rsa_oid[] = {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E,
                                                 0x03, 0x02, 0x1A, 0x05, 0x00, 0x04, 0x14};
    /* SHA-256 with RSA OID (Object Identifier) */
    static const unsigned char sha256_rsa_oid[] = {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
                                                   0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
                                                   0x00, 0x04, 0x20};

    /* SHA-512 with RSA OID (Object Identifier) */
    static const unsigned char sha512_rsa_oid[] = {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
                                                   0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
                                                   0x00, 0x04, 0x40};
    /*
      digest to be signed
    */
    unsigned char 	hash1[sizeof(sha1_rsa_oid) + SHA1_SIZE];	/* OID + SHA-1 digest */
    unsigned char 	hash256[sizeof(sha256_rsa_oid) + SHA256_SIZE];	/* OID + SHA-256 digest */
    unsigned char 	hash512[sizeof(sha512_rsa_oid) + SHA512_SIZE];	/* OID + SHA-512 digest */
    unsigned long 	hashLength;
    /*
      signature
    */
    unsigned char  	signature[N_SIZE];
    unsigned long 	signatureLength;
    unsigned long 	signatureBitLength;

    /* extract the CCA public key from the CCA key token  */
    if (rc == 0) {
        if (verbose) fprintf(messageFile, "SignSample: key token length %u\n", (uint)keyTokenLength);
        if (verbose)
            fprintf(messageFile, "SignSample: extract the public key from CCA key token\n");
        rc = getPKA96PublicKey(&rsaKeyTokenPublic,	/* output: structure */
                               keyTokenLength,
                               keyToken,		/* input: PKA96 key token */
                               2048);
    }
    unsigned int i;			/* loop through digest algorithms */
    const char *hashStr;		/* test, for trace */
    const unsigned char *oid;		/* object identifier */
    size_t oidSize;			/* size of object identifier */
    unsigned char *hash;		/* OID + digest */
    unsigned int digestLength;		/* digest length */
    long (*verifyFunc)();		/* signature verification function */

    /* loop for SHA1, SHA256, SHA512 */
    for (i = 0 ; (rc == 0) && (i < 3) ; i++) {
        switch (i) {
        case 0:
            hashStr = "sha1";
            oid = sha1_rsa_oid;
            oidSize = sizeof(sha1_rsa_oid);
            hash = hash1;
            hashLength = sizeof(hash1);
            digestLength = SHA1_SIZE;
            verifyFunc = osslVerify;
            break;
        case 1:
            hashStr = "sha256";
            oid = sha256_rsa_oid;
            oidSize = sizeof(sha256_rsa_oid);
            hash = hash256;
            hashLength = sizeof(hash256);
            digestLength = SHA256_SIZE;
            verifyFunc = osslVerify256;
            break;
        case 2:
            hashStr = "sha512";
            oid = sha512_rsa_oid;
            oidSize = sizeof(sha512_rsa_oid);
            hash = hash512;
            hashLength = sizeof(hash512);
            digestLength = SHA512_SIZE;
            verifyFunc = osslVerify512;
            break;
        }
        /* prepend OID */
        if (rc == 0) {
            if (verbose) fprintf(messageFile, "SignSample: Hashing input data with %s\n", hashStr);
            memcpy(hash, oid, oidSize);
        }
        /* hash the data for signing, append the hash */
        if (rc == 0) {
            switch (i) {
            case 0:
                Ossl_SHA1(hash + oidSize,
                          testMessageLength, testMessage,
                          0L, NULL);
                break;
            case 1:
                Ossl_SHA256(hash + oidSize,
                            testMessageLength, testMessage,
                            0L, NULL);
                break;
            case 2:
                Ossl_SHA512(hash + oidSize,
                            testMessageLength, testMessage,
                            0L, NULL);
                break;
            }
        }
        /* sign with the coprocessor.  The coprocessor doesn't know the digest algorithm.  It just
           signs an OID + digest1 */
        if (rc == 0) {
            if (verbose) PrintAll(messageFile,
                                  "SignSample: hash to sign",
                                  hashLength, hash);
            signatureLength = sizeof(signature);
            rc = Digital_Signature_Generate(&signatureLength,		/* i/o */
                                            &signatureBitLength,	/* output */
                                            signature,			/* output */
                                            keyTokenLength,		/* input */
                                            keyToken,			/* input */
                                            hashLength,			/* input */
                                            hash);			/* input */

        }
        /* sample  - create the audit log entry */
        if (rc == 0) {
            if (verbose) fprintf(messageFile, "SignSample: Updating audit log\n");
            /* binary data as printable */
            char pubkey_string[N_SIZE * 4];
            char digest_string[SHA512_SIZE * 4];	/* use the largest */
            char sig_string[N_SIZE * 4];

            /* get the user and group structures */
            /* binary to printable */
            sprintAll(pubkey_string, N_SIZE, rsaKeyTokenPublic.n);
            sprintAll(digest_string, digestLength, hash + oidSize);
            sprintAll(sig_string, N_SIZE, signature);
            /* send to audit log */
            fprintf(projectLogFile, "\tPublic Key:\n %s\n", pubkey_string);
            fprintf(projectLogFile, "\tDigest:\n %s\n", digest_string);
            fprintf(projectLogFile, "\tSignature:\n %s\n", sig_string);
        }
        /*
          The verify functions should never fail.  They are just sanity checks on the code.
        */
        /* sanity check on the signature length */
        if (rc == 0) {
            if (signatureLength != N_SIZE) {
                fprintf(messageFile, "ERROR1001: signature invalid length %lu\n", signatureLength);
                rc = ERROR_CODE;
            }
        }
        /* verify the signature with the coprocessor key CCA token */
        if (rc == 0) {
            if (verbose)
                fprintf(messageFile,
                        "SignSample: verify signature with the coprocessor key token\n");
            rc = Digital_Signature_Verify(N_SIZE,			/* input */
                                          signature,			/* input signature */
                                          keyTokenLength,		/* input */
                                          keyToken,			/* input key */
                                          hashLength,			/* input */
                                          hash);			/* input hash */
        }
        /* sample code to verify the signature using openssl */
        if (rc == 0) {
            if (verbose) fprintf(messageFile,
                                 "SignSample: verify signature with OpenSSL and the key token\n");
            rc = verifyFunc(&valid,
                            hash + oidSize,			/* input: digest to be verified */
                            rsaKeyTokenPublic.e,		/* exponent */
                            rsaKeyTokenPublic.eLength,
                            rsaKeyTokenPublic.n, 		/* public key */
                            rsaKeyTokenPublic.nByteLength,
                            signature,				/* signature */
                            signatureLength);
            if (!valid) {
                fprintf(messageFile,
                        "ERROR1023: Error verifying signature with OpenSSL and the key token\n");
                rc = ERROR_CODE;
            }
        }
        /* write the SHA-256 signature to the output attachment  */
        if ((rc == 0) && (outputAttachmentFileName != NULL) && (i == 1)) {
            if (verbose) fprintf(messageFile, "SignSample: Writing output file %s\n",
                                 outputAttachmentFileName);
            rc = File_WriteBinaryFile(signature, signatureLength, outputAttachmentFileName);
        }
        /* write the signature as hex ascii to the output body */
        if (rc == 0) {
            char *signatureString = NULL;	/* freed @3 */
            if (rc == 0) {
                rc = Malloc_Safe((unsigned char **)&signatureString,	/* freed @3 */
                                 (signatureLength * 2) + 1,
                                 (signatureLength * 2) + 1);
            }
            if (rc == 0) {
                Format_ToHexascii(signatureString, signature, signatureLength);
                fprintf(messageFile, "Signature with %s digest, length %u\n%s\n",
                        hashStr,
                        (uint)strlen(signatureString),
                        signatureString);
            }
            free(signatureString);	/* @3 */
        }
    }

    return rc;
}

#ifdef ADD_ECC

int SignSampleECCP521(unsigned char 	*keyToken,
                      size_t		keyTokenLength,
                      unsigned char	*testMessage,
                      size_t		testMessageLength,
                      const char 	*outputAttachmentFileName,
                      FILE 		*projectLogFile)
{
    int		rc = 0;
    int		valid;			/* true if signature verifies */

    EccKeyTokenPublic 	eccKeyTokenPublic;	/* CCA public key structure */
    /*
      digest to be signed
    */
    unsigned char 	hash1[SHA1_SIZE];	/* SHA-1 digest */
    unsigned char 	hash256[SHA256_SIZE];	/* SHA-256 digest */
    unsigned char 	hash512[SHA512_SIZE];	/* SHA-512 digest */
    unsigned long 	hashLength;
    /*
      signature
    */
    unsigned char  	signature[132];		/* FIXME 132 according to CCA, openssl produces
                                           139 */
    unsigned long signatureLength;
    unsigned long signatureBitLength;

    /* extract the CCA public key from the CCA key token  */
    if (rc == 0) {
        if (verbose) fprintf(messageFile, "SignSampleECCP521: key token length %u\n",
                             (uint)keyTokenLength);
        if (verbose)
            fprintf(messageFile, "SignSampleECCP521: extract the public key from CCA key token\n");
        rc = getPKA96EccPublicKey(&eccKeyTokenPublic,	/* output: structure */
                                  keyTokenLength,
                                  keyToken);		/* input: PKA96 key token */
    }
    unsigned int i;			/* loop through digest algorithms */
    const char *hashStr;		/* test, for trace */
    unsigned char *hash;		/* digest */

    /* loop for SHA1, SHA256, SHA512 */
    for (i = 0 ; (rc == 0) && (i < 3) ; i++) {
        if (rc == 0) {
            switch (i) {
            case 0:
                hashStr = "sha1";
                hash = hash1;
                hashLength = sizeof(hash1);
                break;
            case 1:
                hashStr = "sha256";
                hash = hash256;
                hashLength = sizeof(hash256);
                break;
            case 2:
                hashStr = "sha512";
                hash = hash512;
                hashLength = sizeof(hash512);
                break;
            }
            /* hash the data for signing */
            if (verbose) fprintf(messageFile, "SignSampleECCP521: Hashing input data with %s\n",
                                 hashStr);
            switch (i) {
            case 0:
                Ossl_SHA1(hash,
                          testMessageLength, testMessage,
                          0L, NULL);
                break;
            case 1:
                Ossl_SHA256(hash,
                            testMessageLength, testMessage,
                            0L, NULL);
                break;
            case 2:
                Ossl_SHA512(hash,
                            testMessageLength, testMessage,
                            0L, NULL);
                break;
            }
            if (verbose) PrintAll(messageFile,
                                  "SignSampleECCP521: hash to sign",
                                  hashLength, hash);
        }
        /* sign with the coprocessor.  The coprocessor doesn't know the digest algorithm.  It just
           signs a digest */
        if (rc == 0) {
            signatureLength = sizeof(signature);
            rc = Digital_Signature_Generate_ECC(&signatureLength,	/* i/o */
                                                &signatureBitLength,	/* output */
                                                signature,		/* output */
                                                keyTokenLength,		/* input */
                                                keyToken,		/* input */
                                                hashLength,		/* input */
                                                hash);			/* input */

        }
        /* sample  - create the audit log entry */
        if (rc == 0) {
            if (verbose) fprintf(messageFile, "SignSampleECCP521: Updating audit log\n");
            /* binary data as printable */
            char pubkey_string[133 * 4];
            char digest_string[SHA512_SIZE * 4];	/* use the largest */
            char sig_string[132 * 4];

            /* get the user and group structures */
            /* binary to printable */
            sprintAll(pubkey_string, eccKeyTokenPublic.qLen, eccKeyTokenPublic.publicKey);
            sprintAll(digest_string, hashLength, hash);
            sprintAll(sig_string, signatureLength, signature);
            /* send to audit log */
            fprintf(projectLogFile, "\tPublic Key:\n %s\n", pubkey_string);
            fprintf(projectLogFile, "\tDigest:\n %s\n", digest_string);
            fprintf(projectLogFile, "\tSignature:\n %s\n", sig_string);
        }
        /*
          The verify functions should never fail.  They are just sanity checks on the code.
        */
        /* sanity check on the signature length */
        if (rc == 0) {
            if (signatureLength != sizeof(signature)) {
                fprintf(messageFile, "ERROR1001: signature invalid length %lu\n", signatureLength);
                rc = ERROR_CODE;
            }
        }
        /* verify the signature with the coprocessor key CCA token */
        if (rc == 0) {
            if (verbose)
                fprintf(messageFile,
                        "SignSampleECCP521: verify signature with the coprocessor key token\n");
            rc = Digital_Signature_Verify_ECC(signatureLength,		/* input */
                                              signature,		/* input signature */
                                              keyTokenLength,		/* input */
                                              keyToken,			/* input key */
                                              hashLength,		/* input */
                                              hash);			/* input hash */
        }
        /* sample code to verify the signature using openssl */
        if (rc == 0) {
            if (verbose) fprintf(messageFile,
                                 "SignSampleECCP521: "
                                 "verify signature with OpenSSL and the key token\n");
            rc = Ossl_VerifyECC(&valid,
                                hash,			/* input: digest to be verified */
                                hashLength,
                                eccKeyTokenPublic.publicKey,
                                eccKeyTokenPublic.qLen,
                                signature,		/* input: signature */
                                signatureLength);
            if (!valid) {
                fprintf(messageFile,
                        "ERROR1024: "
                        "Error verifying signature with OpenSSL and the key token\n");
                rc = ERROR_CODE;
            }
        }
        /* write one signature to the output attachment  */
        if ((rc == 0) && (outputAttachmentFileName != NULL)) {
            if (verbose) fprintf(messageFile, "SignSampleECCP521: Writing output file %s\n",
                                 outputAttachmentFileName);
            rc = File_WriteBinaryFile(signature, signatureLength, outputAttachmentFileName);
        }
        /* write the signature as hex ascii to the output body */
        if (rc == 0) {
            char *signatureString = NULL;	/* freed @3 */
            if (rc == 0) {
                rc = Malloc_Safe((unsigned char **)&signatureString,	/* freed @3 */
                                 (signatureLength * 2) + 1,
                                 (signatureLength * 2) + 1);
            }
            if (rc == 0) {
                Format_ToHexascii(signatureString, signature, signatureLength);
                fprintf(messageFile, "Signature with %s digest\n%s\n",
                        hashStr,
                        signatureString);
            }
            free(signatureString);	/* @3 */
        }
    }
    /* cleanup */
    return rc;
}

#endif

/* EchoArgs() prints all incoming command line arguments, except it does not print the plaintext
   password. */

int EchoArgs(int argc, char** argv)
{
    int 	rc = 0;
    int 	irc;
    int 	i;

    fprintf(messageFile, "framework_test argc = %u\n", argc);

    for (i = 0 ; i < argc ; i++) {
        fprintf(messageFile, "%u: %s\n", i, argv[i]);
        irc = strcmp(argv[i], "-pwd");		/* if the argv is -pwd */
        if (irc == 0) {
            i++;				/* skip the next argument */
        }
    }
    return rc;
}

/* GetArgs() gets the command line arguments from the framework.
 */

int GetArgs(const char **outputBodyFilename,
            const char **usr,
            const char **password,
            const char **projectLogFileName,
            const char **projectAuxConfigFileName,
            const char **sender,
            const char **project,
            const char **keyFileName,
            const char **inputAttachmentFileName,
            const char **outputAttachmentFileName,
            int *verbose,
            int argc,
            char **argv)
{
    long	rc = 0;
    int 	i;
    FILE	*tmpFile;

    /* command line argument defaults */
    *outputBodyFilename = NULL;
    *verbose = FALSE;

    /* get the command line arguments */
    for (i = 1 ; (i < argc) && (rc == 0) ; i++) {
        if (strcmp(argv[i],"-obody") == 0) {
            i++;
            if (i < argc) {
                *outputBodyFilename = argv[i];
                rc = File_Open(&tmpFile, *outputBodyFilename, "a");
                /* switch messageFile from stdout ASAP so all messages get returned via email */
                if (rc == 0) {
                    messageFile = tmpFile;
                    setvbuf(messageFile , 0, _IONBF, 0);
                }
            }
            else {
                fprintf(messageFile,
                        "ERROR1002: -obody option (output email body) needs a value\n");
                rc = ERROR_CODE;
            }
        }
        else if (strcmp(argv[i],"-usr") == 0) {
            i++;
            if (i < argc) {
                *usr = argv[i];
            }
            else {
                fprintf(messageFile,
                        "ERROR1003: -usr option (CCA user ID) needs a value\n");
                rc = ERROR_CODE;
            }
        }
        else if (strcmp(argv[i],"-core") == 0) {
            int *p = NULL;
            i = *p;
        }
        else if (strcmp(argv[i],"-pwd") == 0) {
            i++;
            if (i < argc) {
                *password = argv[i];
            }
            else {
                fprintf(messageFile,
                        "ERROR1004: -pwd option (CCA password) needs a value\n");
                rc = ERROR_CODE;
            }
        }
        else if (strcmp(argv[i],"-log") == 0) {
            i++;
            if (i < argc) {
                *projectLogFileName = argv[i];
            }
            else {
                fprintf(messageFile,
                        "ERROR1005: -log option (audit log file name) needs a value\n");
                rc = ERROR_CODE;
            }
        }
        else if (strcmp(argv[i],"-auxcfg") == 0) {
            i++;
            if (i < argc) {
                *projectAuxConfigFileName = argv[i];
            }
            else {
                fprintf(messageFile,
                        "ERROR1019: "
                        "-auxcfg option (auxiliary configuration file name) needs a value\n");
                rc = ERROR_CODE;
            }
        }
        else if (strcmp(argv[i],"-sender") == 0) {
            i++;
            if (i < argc) {
                *sender = argv[i];
            }
            else {
                fprintf(messageFile,
                        "ERROR1006: -sender option needs a value\n");
                rc = ERROR_CODE;
            }
        }
        else if (strcmp(argv[i],"-project") == 0) {
            i++;
            if (i < argc) {
                *project = argv[i];
            }
            else {
                fprintf(messageFile,
                        "ERROR1007: -project option needs a value\n");
                rc = ERROR_CODE;
            }
        }
        else if (strcmp(argv[i],"-key") == 0) {
            i++;
            if (i < argc) {
                *keyFileName = argv[i];
            }
            else {
                fprintf(messageFile,
                        "ERROR1008: -key option needs a value\n");
                rc = ERROR_CODE;
            }
        }
        else if (strcmp(argv[i],"-di") == 0) {
            i++;
            if (i < argc) {
                *inputAttachmentFileName = argv[i];
            }
            else {
                fprintf(messageFile,
                        "ERROR1016: -di option needs a value\n");
                rc = ERROR_CODE;
            }
        }
        else if (strcmp(argv[i],"-do") == 0) {
            i++;
            if (i < argc) {
                *outputAttachmentFileName = argv[i];
            }
            else {
                fprintf(messageFile,
                        "ERROR1009: -do option needs a value\n");
                rc = ERROR_CODE;
            }
        }
        /* this allows the framework to probe whether the project specific program can be called.
           The program should do nothing except return success. */
        else if (strcmp(argv[i],"-h") == 0) {
            PrintUsage();
            exit(0);
        }
        else if (strcmp(argv[i],"-v") == 0) {
            *verbose = TRUE;
        }
        /* This code intentionally does not have an 'else error' clause.  The framework can in
           general add command line arguments that are ignored by the project specific program. */
    }
    /* verify mandatory command line arguments */
    if (rc == 0) {
        // If the usr isn't specified just use the sender
        if (*usr == NULL) {
            *usr = *sender;
        }
        if (*usr == NULL) {
            fprintf(messageFile,
                    "ERROR1010: -usr option missing\n");
            rc = ERROR_CODE;
        }
    }
    if (rc == 0) {
        if (*password == NULL) {
            fprintf(messageFile,
                    "ERROR1018: -pwd option missing\n");
            rc = ERROR_CODE;
        }
    }
    if (rc == 0) {
        if (*sender== NULL) {
            fprintf(messageFile,
                    "ERROR1011: -sender option missing\n");
            rc = ERROR_CODE;
        }
    }
    if (rc == 0) {
        if (*projectLogFileName == NULL) {
            fprintf(messageFile,
                    "ERROR1012: -log option missing\n");
            rc = ERROR_CODE;
        }
    }
#if 0	/* A program that needs auxiliary configuration data would use this test.  It's commented
           out here because the regression test tries both. */
    if (rc == 0) {
        if (*projectAuxConfigFileName == NULL) {
            fprintf(messageFile,
                    "ERROR1020: -auxcfg option missing\n");
            rc = ERROR_CODE;
        }
    }
#endif
    if (rc == 0) {
        if (*keyFileName == NULL) {
            fprintf(messageFile,
                    "ERROR1014: -key option missing\n");
            rc = ERROR_CODE;
        }
    }
    if (rc == 0) {
        if (*inputAttachmentFileName == NULL) {
            fprintf(messageFile,
                    "ERROR1017: -di option missing\n");
            rc = ERROR_CODE;
        }
    }
    return rc;
}

/* CheckAuxArgs() checks that no command line arguments clash with those in the project auxiliary
   configuration file
*/

int CheckAuxArgs(int argc, char** argv)
{
    int		rc = 0;
    int		irc;
    size_t	i;
    int 	j;

    /* screen out command line arguments that attempt to override the project auxiliary
       configuration file values */

    /* for each value in the project auxiliary configuration file */
    for (i = 0 ; (rc == 0) && (i < (sizeof(claTable)/sizeof(char *))) ; i++) {

        /* for each value from the command line */
        for (j = 0 ; (rc == 0) && (j < argc) ; j++) {

            irc = strcmp(claTable[i], argv[j]);

            if (irc == 0) {
                fprintf(messageFile, "ERROR1025: %s illegal in input body\n", argv[j]);
                rc = ERROR_CODE;
            }
        }
    }
    return rc;
}

int GetAuxArgs(char **signAlgorithm,			/* freed by caller */
               const char *projectAuxConfigFileName)
{
    int		rc = 0;
    char	*lineBuffer = NULL;		/* freed @2 */
    size_t	lineBufferLength = 4000;	/* hard code for the project */
    FILE 	*projectAuxConfigFile = NULL;	/* closed @1 */

    if (projectAuxConfigFileName != NULL) {
        /* open project auxiliary configuration file */
        if (rc == 0) {
            if (verbose) fprintf(messageFile,
                                 "Opening  auxiliary configuration file %s\n",
                                 projectAuxConfigFileName);
            projectAuxConfigFile = fopen(projectAuxConfigFileName, "r");	/* closed @1 */
            if (projectAuxConfigFile == NULL) {
                fprintf(messageFile,
                        "ERROR1021: Cannot open auxiliary configuration file %s, %s\n",
                        projectAuxConfigFileName, strerror(errno));
                rc = ERROR_CODE;
            }
        }
        /* allocate a line buffer, used when parsing the configuration file */
        if (rc == 0) {
            rc = Malloc_Safe((unsigned char **)&lineBuffer,	/* freed @2 */
                             lineBufferLength,
                             lineBufferLength);		/* hard code for the project */
        }
        if (rc == 0) {
            rc = File_MapNameToValue(signAlgorithm,		/* freed by caller */
                                     "sign_algorithm",	/* name to search for */
                                     lineBuffer,		/* supplied buffer for lines */
                                     lineBufferLength,	/* size of the line buffer */
                                     projectAuxConfigFile);	/* input file stream */
        }
        if (rc == 0) {
            if (verbose) fprintf(messageFile, "Signature algorithm: %s\n", *signAlgorithm);
        }
        if (projectAuxConfigFile != NULL) {
            fclose(projectAuxConfigFile);	/* @1 */
        }
    }
    else {	/* projectAuxConfigFileName == NULL, use default */
        if (rc == 0) {
            rc = Malloc_Safe((unsigned char **)signAlgorithm,	/* freed by caller */
                             sizeof("rsa"),
                             sizeof("rsa"));		/* hard code the default */
        }
        if (rc == 0) {
            memcpy(*signAlgorithm, "rsa", sizeof("rsa"));
        }
    }
    free(lineBuffer);			/* @2 */
    return rc;
}

void PrintUsage()
{
    fprintf(messageFile, "\n");
    fprintf(messageFile,
            "\tframework_test usage:\n"
            "\n"
            "Common arguments:\n"
            "\n"
            "\t-usr        - CCA user (profile) ID\n"
            "\t[-core      - cause the program to core dump]\n"
            "\t[-v         - verbose logging]\n"
            "\t[-h         - print usage help]\n"
            "\n"
            "Email only arguments:\n"
            "\n"
            "\t-project    - project name\n"
            "\t-epwd       - CCA user password (encrypted)\n"
            "\n"
            "Command line only arguments:\n"
            "\n"
            "\t-obody      - output email body file name (should be first argument)\n"
            "\t-sender     - email sender\n"
            "\t-di         - input attachment file name\n"
            "\t-do         - output attachment file name\n"
            "\t-log        - project audit log file name\n"
            "\t-auxcfg     - project auxiliary configuration file name\n"
            "\t-key        - project CCA signing key token\n"
            "\t-pwd        - CCA user password (plaintext)\n"
            );
    fprintf(messageFile, "\n");
    return;
}
