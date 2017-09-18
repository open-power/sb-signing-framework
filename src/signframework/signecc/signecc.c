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

/* This program signs with an ECC P521 key.  Since ECC doesn't add an object identifier (OID), this
   one program will sign a hash of any length that will fit.  */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>

#include "openssl/evp.h"

#include "cca_structures.h"
#include "cca_structures_ecc.h"
#include "cca_functions.h"
#include "cca_functions_ecc.h"
#include "ossl_functions_ecc.h"
#include "ossl_functions.h"
#include "utils.h"
#include "debug.h"

#include "eccutils.h"

#include "Container.h"

/* local prototypes */

int GetArgs(const char **outputBodyFilename,
            const char **usr,
            const char **password,
            const char **projectLogFileName,
            const char **sender,
            const char **project,
            const char **auxcfgFilename,
            const char **keyFileName,
            const char **inputAttachmentFileName,
            const char **outputAttachmentFileName,
            int *verbose,
            int argc,
            char **argv);
int CheckAlgorithms(const char *signAlgorithm,
                    const char *digestAlgorithm);

void PrintUsage(void);

int CheckPrefix(const char     *inputAttachmentFileName,   /* file holding prefix binary, also the output file */
                FILE           *projectLogFile);           /* audit log file */
uint16_t getUint16( uint8_t *data, int p_endianess );
uint32_t getUint32( uint8_t *data, int p_endianess );
void putUint32( uint32_t *value, uint8_t *data, int p_endianess );

int Sign(const char 		*keyFileName,
         const char 	*inputAttachmentFileName,
         const char 	*outputAttachmentFileName,
         FILE 		*projectLogFile);
int SignECCP521(unsigned char 	*keyToken,
                size_t		keyTokenLength,
                unsigned char	*testMessage,
                size_t		testMessageLength,
                const char 	*outputAttachmentFileName,
                FILE 		*projectLogFile);

/* messages are traced here */
FILE *messageFile = NULL;
int  verbose = FALSE;
int debug = FALSE;

int main(int argc, char** argv)
{
    int 	rc = 0;
    int 	rc1 = 0;
    size_t	i;	/* iterate through project configuration files */
    size_t 	j;	/* interate through senders in a file */
    time_t      log_time;
    int		loggedIn = FALSE;

    /* command line parameters */
    const char  *usr = NULL;
    const char 	*password = NULL;
    const char 	*projectLogFileName = NULL;
    FILE	*projectLogFile = NULL;				/* closed @1 */
    const char 	*sender = NULL;
    const char 	*project = NULL;
    const char	*auxcfgFilename = NULL;	/* project auxiliary configuration file name */
    const char 	*keyFileName = NULL;
    const char 	*inputAttachmentFileName = NULL;
    const char 	*outputAttachmentFileName = NULL;
    const char 	*outputBodyFilename = NULL;

    /* parameters from project auxiliary configuration file */
    char 		*signAlgorithm = NULL;			/* freed @2 */
    char 		*digestAlgorithm = NULL;		/* freed @3 */
    int 		checkUnique;
    int 		rawHeaderInput;
    unsigned int 	numberOfProjectFiles = 0;
    char 		**projectConfigFilenames = NULL;	/* freed @4 */
    unsigned int 	*numberOfSenders = NULL;	/* array of number of senders per
                                                   project, freed @5 */
    char 		***senders = NULL;			/* array of senders per project,
                                               freed @6 */
    messageFile = stdout;

    /* get caller's command line arguments */
    if (rc == 0) {
        rc = GetArgs(&outputBodyFilename,
                     &usr,
                     &password,
                     &projectLogFileName,
                     &sender,
                     &project,
                     &auxcfgFilename,
                     &keyFileName,
                     &inputAttachmentFileName,
                     &outputAttachmentFileName,
                     &verbose,
                     argc, argv);
    }
    /* get auxiliary arguments from auxiliary configuration file */
    if (rc == 0) {
        rc = GetAuxArgs(&signAlgorithm,			/* freed @2 */
                        &digestAlgorithm,		/* freed @3 */
                        &checkUnique,
                        &rawHeaderInput,                /* Raw Prefix Header or hash provided? */
                        &numberOfProjectFiles,
                        &projectConfigFilenames,	/* array of file names, freed @4 */
                        auxcfgFilename);
    }
    /* verify that the specified crypto algorithms are supported */
    if (rc == 0) {
        rc = CheckAlgorithms(signAlgorithm,
                             digestAlgorithm);
    }
    /* The auxiliary configuration file links multiple signing projects  */
    if ((rc == 0) && checkUnique) {
        rc = GetSendersArray(&senders,
                             &numberOfSenders,		/* freed @5 */
                             numberOfProjectFiles,
                             projectConfigFilenames);	 /* array of file names */
    }
    /* if required, check that all co-signer senders in the project configuration files are unique.
       This ensures that no one co-signer is authorized for more than one signing key.  */
    if ((rc == 0) && checkUnique) {
        rc = CheckSenders(numberOfProjectFiles,
                          projectConfigFilenames,
                          numberOfSenders,
                          senders);
    }
    /* audit logging */
    if (rc == 0) {
        if (verbose) fprintf(messageFile, "Opening audit log %s\n", projectLogFileName);
        projectLogFile = fopen(projectLogFileName, "a");		/* closed @1 */
        if (projectLogFile == NULL) {
            fprintf(messageFile, "ERROR1018: Cannot open audit log %s, %s\n",
                    projectLogFileName, strerror(errno));
            rc = ERROR_CODE;
        }
    }
    /* update audit log, begin this entry */
    if (projectLogFile != NULL) {
        if (verbose) fprintf(messageFile, "Updating audit log\n");
        log_time = time(NULL);
        fprintf(projectLogFile, "\n%s", ctime(&log_time));
        fprintf(projectLogFile, "\tSender  : %s\n", sender);
        fprintf(projectLogFile, "\tProject : %s\n", project);
        fprintf(projectLogFile, "\tProgram : %s\n", argv[0]);
        fprintf(projectLogFile, "\tKey file: %s\n", keyFileName);
        fprintf(projectLogFile, "\tProfile : %s\n", usr);
    }
    /* log in to CCA */
    if (rc == 0) {
        if (verbose) fprintf(messageFile, "Logging in with user name %s\n", usr);
        rc = Login_Control(TRUE,	/* log in */
                           usr,		/* CCA profile */
                           password);	/* CCA password */
        if (rc == 0) {
            loggedIn = TRUE;
        }
        else {
            File_Printf(projectLogFile, messageFile,
                        "ERROR1024 : Login failed, Bad user name %s or bad password\n", usr);
        }
    }
    /* If raw prefix provided as input, apply required container policies by checking flag field bits */
    if ((rc == 0) && rawHeaderInput) {
        if (verbose) fprintf(messageFile, "Checking Prefix Header\n");
        if (verbose) fprintf(messageFile, "  Input attachment %s\n", inputAttachmentFileName);
        rc = CheckPrefix(inputAttachmentFileName,
                          projectLogFile);
    }
    /* sign and verify */
    if (rc == 0) {
        if (verbose) fprintf(messageFile, "Signing\n");
        if (verbose) fprintf(messageFile, "  Input attachment %s\n", inputAttachmentFileName);
        if (verbose) fprintf(messageFile, "  Output attachment %s\n", outputAttachmentFileName);
        rc = Sign(keyFileName,
                  inputAttachmentFileName,
                  outputAttachmentFileName,
                  projectLogFile);
    }
    /* log out of CCA */
    if (loggedIn) {
        if (verbose) fprintf(messageFile, "Logging out with user name %s\n", usr);
        rc1 = Login_Control(FALSE,	/* log out */
                            usr,	/* CCA profile */
                            NULL);	/* password */
        if (rc == 0) {
            rc = rc1;
        }
    }
    File_Printf(projectLogFile, messageFile,
                "Return code: %u\n", rc);
    /* clean up */
    if (projectLogFile != NULL) {
        fclose(projectLogFile);		/* @1 */
    }
    free(signAlgorithm);		/* @2 */
    free(digestAlgorithm);		/* @3 */
    if (projectConfigFilenames != NULL) {
        for (i = 0 ; i < numberOfProjectFiles ; i++) {
            free(projectConfigFilenames[i]);
        }
        free(projectConfigFilenames);	/* @4 */
    }
    if (senders != NULL) {
        for (i = 0 ; i < numberOfProjectFiles ; i++) {
            if (senders[i] != NULL) {
                for (j = 0 ; j < numberOfSenders[i] ; j++) {
                    free(senders[i][j]);
                }
            }
            free(senders[i]);
        }
        free(senders);			/* @6 */
    }
    free(numberOfSenders);		/* @5 */
    if (messageFile != stdout) {
        fflush(messageFile);
        fclose(messageFile);
    }
    return rc;
}

/* CheckAlgorithms() verifies that the crypto algorithms are valid for the project.

   Currently, only eccp521 and SHA-512 are supported.
*/

int CheckAlgorithms(const char *signAlgorithm,
                    const char *digestAlgorithm)
{
    int		rc = 0;

    if (rc == 0) {
        if (strcmp(signAlgorithm, "eccp521") != 0) {
            fprintf(messageFile,
                    "ERROR1027: Signing algorithm %s not supported\n",
                    signAlgorithm);
            rc = ERROR_CODE;
        }
    }
    if (rc == 0) {
        if (strcmp(digestAlgorithm, "SHA-512") != 0) {
            fprintf(messageFile,
                    "ERROR1028: Digest algorithm %s not supported\n",
                    digestAlgorithm);
            rc = ERROR_CODE;
        }
    }
    return rc;
}
/* CheckPrefix() receives the rawcontainer header as input and executes policy checks
 *  against raw before hashing into inputfile to be used for rest of signing flow
 *
 *     1. Never sign a HW Prefix Hdr w/ .new key. bit on
 *     2. Policy change later to allow Prod key 1 to prod key 2 if/as required
 *     3. Imprint to prod key 1 header can be signed w/o sign server (imprint only)
 *     4. NEVER sign a HW Prefix Hdr w/ any Attributes flags set (bits 12-23)
 *
 *     HW Prefix Header flags field
 *        Key sets: bits 0-11
 *        Attributes: bits 12-23
 *        Special Containers: bits 24-31
 *        flags (FW key indicator)
 *           1000 0000 0000 0000 0000 0000 0000 0000  Images signed by KeySet 1 (op-build)
 *           0100 0000 0000 0000 0000 0000 0000 0000  Images signed by KeySet 2 (fips-build)
 *           0010 0000 0000 0000 0000 0000 0000 0000  Images signed by KeySet 3 (ODM e.g., IBM AIX Kernel)
 *        --- for attributes
 *           xxxx xxxx xxxx 1000 0000 0000 xxxx xxxx  Enable SBE checking of mailbox scratch reg for secure boot disable req
 *        --- for .new key. container
 *           0000 0000 0000 0000 0000 0000 0000 0001  New Key Container which is signed by the current key
 *                                                      (Nested Payload Image signed by new key)
 */
int CheckPrefix(const char     *inputAttachmentFileName,   /* file holding prefix binary, also the output file */
                FILE           *projectLogFile)            /* audit log file */
{
    int            rc = 0;
    unsigned char  *p_raw_prefix = NULL;  /* prefix header to be analyzed  */
    unsigned char  *p_hdr = NULL;
    unsigned char  *p_flags = NULL;
    PrefixHdr *hwPrefixHdr = NULL; /* prefix header overlay */
    size_t         prefixSize;
    unsigned char digest[SHA512_SIZE];  /* digest to be generated  */
    const uint32_t OP_BLD_CONTAINER   = 0x80000000;
    const uint32_t FIPS_BLD_CONTAINER = 0x40000000;
    const uint32_t NEW_KEY_CONTAINER  = 0x00000001;
    const uint32_t ATTR_FLAG_MASK     = 0x000FFF00;
    const uint16_t HDR_LEN = 98;
    const uint8_t  HDR_VER = 1;
    const uint8_t  HDR_HASH = 1;
    const uint8_t  HDR_SIG = 1;

    if (verbose) fprintf(messageFile, "CheckPrefix: Reading input file %s\n",
                         inputAttachmentFileName);
    rc = File_ReadBinaryFile(&p_raw_prefix , &prefixSize, sizeof(PrefixHdr),
                             inputAttachmentFileName);      /* freed @22 */

    PrintAll(messageFile,
             "Input file data", prefixSize, p_raw_prefix);  /* test code */
    fprintf(messageFile, "Prefix Size: %d\n", (int)prefixSize);

    if (rc != 0) {
        File_Printf(projectLogFile, messageFile,
                    "ERROR1020 while opening the attachment, file: %s\n",
                    inputAttachmentFileName);
    }

    if (rc == 0 && prefixSize != (sizeof(PrefixHdr)-ECID_SIZE-2) ) {  /* TODO: find the majic number 2 */
        File_Printf(projectLogFile, messageFile,
                    "SIZE ERROR on input file: %s\n",
                    inputAttachmentFileName);
        rc = ERROR_CODE;
        fprintf(messageFile, "Calculated Prefix Size: %d\n", (int)sizeof(PrefixHdr)-ECID_SIZE);
        fprintf(messageFile, "sizeof PrefixHdr: %d\n", (int)sizeof(PrefixHdr));
    }

    /* Overlay PrefixHdr struct and perform checks
    *  Confirm version, algos, key count for this proj, ecidCnt
    *  then check flag bits
    */
    if (rc == 0) {
        if (verbose) fprintf(messageFile, "CheckPrefix: Perform checks on header  %s\n",
                             inputAttachmentFileName);

        /* Construct and init a HwPrefixHdr  */
        hwPrefixHdr = (PrefixHdr *) malloc(sizeof(PrefixHdr));
        if (hwPrefixHdr == NULL) {
	    File_Printf(projectLogFile, messageFile,
                    "Malloc ERROR on PrefixHdr: %s\n",
                    inputAttachmentFileName);
            rc = ERROR_CODE;
        }
        if (rc == 0) {
            /* Build the PrefixHdr */
            p_hdr = p_raw_prefix;
            hwPrefixHdr->m_version = getUint16(p_hdr,1);
            p_hdr += 2;
            hwPrefixHdr->m_hashAlg = *p_hdr++;
            hwPrefixHdr->m_sigAlg  = *p_hdr++;
            memcpy( hwPrefixHdr->m_codeStartOffset, p_hdr, 8 );
            p_hdr += 8;
            memcpy( hwPrefixHdr->m_reserved, p_hdr, 8 );
            p_hdr += 8;
            hwPrefixHdr->m_flags = getUint32( p_hdr,1 );
            p_flags = p_hdr;   // use to update original header later
            p_hdr += 4;
            hwPrefixHdr->m_swKeyCount  = *p_hdr++;
            memcpy( hwPrefixHdr->m_payloadSize, p_hdr, 8 );
            p_hdr += 8;
            memcpy( hwPrefixHdr->m_payloadHash, p_hdr, SHA512_DIGEST_SIZE );
            p_hdr += SHA512_DIGEST_SIZE;

            fprintf(messageFile, "Prefix Version: %u\n", hwPrefixHdr->m_version);
            fprintf(messageFile, "Prefix Hash Alg: %u\n", hwPrefixHdr->m_hashAlg);
            fprintf(messageFile, "Prefix Signature Alg: %u\n", hwPrefixHdr->m_sigAlg);
            fprintf(messageFile, "Prefix flags: %08X\n", hwPrefixHdr->m_flags);
            fprintf(messageFile, "FW Key Count: %u\n", hwPrefixHdr->m_swKeyCount);

            /* Check Valid Prefix Hdr here  */
            if (verbose) fprintf(messageFile, "CheckPrefix: Checking Valid Hdr  %s\n",
                             inputAttachmentFileName);
            if (prefixSize != HDR_LEN || hwPrefixHdr->m_version != HDR_VER || hwPrefixHdr->m_hashAlg != HDR_HASH || hwPrefixHdr->m_sigAlg != HDR_SIG) {
                File_Printf(projectLogFile, messageFile,
                    "Invalid HDR Fields Found: %s\n",
                    inputAttachmentFileName);
                rc = ERROR_CODE;
            }
         }
         if (rc == 0) {

	    /* Check Flag bits here  */
            if (verbose) fprintf(messageFile, "CheckPrefix: Checking Flag bits  %s\n",
                             inputAttachmentFileName);

            /* NEVER sign w/ attributes or new key (for now) so silently clear those bits */
            hwPrefixHdr->m_flags &= ~(ATTR_FLAG_MASK);
            hwPrefixHdr->m_flags &= ~(NEW_KEY_CONTAINER);
            putUint32(&(hwPrefixHdr->m_flags), p_flags, 1 );
            fprintf(messageFile, "Updated Prefix flags: %08X\n", getUint32( p_flags,1 ));

            /* Check that at least one of the key sets is set */
            if (hwPrefixHdr->m_flags & OP_BLD_CONTAINER) {
                File_Printf(projectLogFile, messageFile,
                    "Valid op-bld Container: %s\n",
                    inputAttachmentFileName);
             } else if (hwPrefixHdr->m_flags & FIPS_BLD_CONTAINER) {
                File_Printf(projectLogFile, messageFile,
                    "Valid fips-bld Container: %s\n",
                    inputAttachmentFileName);
             } else {
                File_Printf(projectLogFile, messageFile,
                    "Invalid Flag Field Set: %s\n",
                    inputAttachmentFileName);
                rc = ERROR_CODE;
             }
        }
    }
    /* Hash prefix and return to "input" file to enable proceeding w/ signing flow   */
    if (rc == 0) {
       if (verbose) fprintf(messageFile, "CheckPrefix: Create digest of header  %s\n",
                             inputAttachmentFileName);
          Ossl_SHA512(digest,
                   prefixSize,
                   p_raw_prefix,  // p_raw_prefix with any flags cleared
                   0L, NULL);
       PrintAll(messageFile,
                "Updated prefix header", prefixSize, p_raw_prefix);

       PrintAll(messageFile,
                "SHA512 of prefix header", SHA512_SIZE, digest);
    }
    if (rc == 0) {
       if (verbose) fprintf(messageFile, "CheckPrefix: Writing digest of header back input file  %s\n",
                             inputAttachmentFileName);

       rc = File_WriteBinaryFile(digest, SHA512_SIZE,
                         inputAttachmentFileName);
       if (rc != 0) {
           File_Printf(projectLogFile, messageFile,
                       "ERROR while writing hash back to input attachment file: %s\n",
                       inputAttachmentFileName);
       }
    }
    /* clean up */
    free(p_raw_prefix);       /* @22 */
    free(hwPrefixHdr);  /* @24 */

    return rc;
}


/* Sign() does ECC P521 signing and verification

 */

int Sign(const char 	*keyFileName,			/* ECC P521 key token */
         const char 	*inputAttachmentFileName,	/* file holding the digest to be signec */
         const char 	*outputAttachmentFileName,	/* file for signature */
         FILE 		*projectLogFile)		/* audit log file */
{
    int		rc = 0;
    /*
      signing key
    */
    unsigned char 	*keyToken = NULL;		/* CCA key token */
    size_t		keyTokenLength;
    /*
      digest to be signed
    */
    unsigned char 	*digest = NULL;
    size_t		digestLength;

    /* get the CCA key token */
    if (rc == 0) {
        if (verbose) fprintf(messageFile, "Sign: Reading CCA key token file %s\n",
                             keyFileName);
        rc = File_ReadBinaryFile(&keyToken, &keyTokenLength, 2000, keyFileName); /* freed @1 */
        if (rc != 0) {
            File_Printf(projectLogFile, messageFile,
                        "ERROR1019: Could not open key file: %s\n", keyFileName);
        }
    }
    /* get the input digest */
    if (rc == 0) {
        if (verbose) fprintf(messageFile, "Sign: Reading input file %s\n",
                             inputAttachmentFileName);
        size_t length = 0;
        rc = File_GetSize(&length, inputAttachmentFileName);
        if (rc != 0) {
            File_Printf(projectLogFile, messageFile,
                        "ERROR1020 while opening the attachment, file: %s\n",
                        inputAttachmentFileName);
        } else if (length != SHA512_SIZE) {
            rc = 1;
            File_Printf(projectLogFile, messageFile,
                        "ERROR1020 while opening the attachment, incorrect size ACT=%d EXP=%d, file: %s\n",
                        length, SHA512_SIZE, inputAttachmentFileName);
        } else {
            rc = File_ReadBinaryFile(&digest , &digestLength, SHA512_SIZE,
                                     inputAttachmentFileName);	/* freed @2 */
        }
        if (rc != 0) {
            File_Printf(projectLogFile, messageFile,
                        "ERROR1020 while opening the attachment, file: %s\n",
                        inputAttachmentFileName);
        }
    }
    if (rc == 0) {
        rc = SignECCP521(keyToken,
                         keyTokenLength,
                         digest,
                         digestLength,
                         outputAttachmentFileName,
                         projectLogFile);
    }
    /* clean up */
    free(keyToken);	/* @1 */
    free(digest);	/* @2 */
    return rc;
}

int SignECCP521(unsigned char 	*keyToken,
                size_t		keyTokenLength,
                unsigned char	*digest,
                size_t		digestLength,
                const char 	*outputAttachmentFileName,
                FILE 		*projectLogFile)
{
    int		rc = 0;
    int		valid;				/* true if signature verifies */

    EccKeyTokenPublic 	eccKeyTokenPublic;	/* CCA public key structure */
    /*
      signature
    */
    unsigned char  	signature[132];		/* NOTE 132 according to CCA, openssl produces
                                           139 */
    unsigned long signatureLength;
    unsigned long signatureBitLength;

    /* extract the CCA public key from the CCA key token  */
    if (rc == 0) {
        if (verbose) fprintf(messageFile, "SignECCP521: key token length %d\n",
                             (int)keyTokenLength);
        if (verbose)
            fprintf(messageFile, "SignECCP521: extract the public key from CCA key token\n");
        rc = getPKA96EccPublicKey(&eccKeyTokenPublic,	/* output: structure */
                                  keyTokenLength,
                                  keyToken);		/* input: PKA96 key token */
    }
    /* sign with the coprocessor.  The coprocessor doesn't know the digest algorithm.  It just
       signs a digest */
    if (rc == 0) {
        signatureLength = sizeof(signature);
        rc = Digital_Signature_Generate_ECC(&signatureLength,		/* i/o */
                                            &signatureBitLength,	/* output */
                                            signature,			/* output */
                                            keyTokenLength,		/* input */
                                            keyToken,			/* input */
                                            digestLength,		/* input */
                                            digest);			/* input */

    }
    /* create the audit log entry */
    if (rc == 0) {
        if (verbose) fprintf(messageFile, "SignECCP521: Updating audit log\n");
        /* binary data as printable */
        char pubkey_string[133 * 4];
        char digest_string[SHA512_SIZE * 4];	/* use the largest */
        char sig_string[132 * 4];

        /* get the user and group structures */
        /* binary to printable */
        sprintAll(pubkey_string, eccKeyTokenPublic.qLen, eccKeyTokenPublic.publicKey);
        sprintAll(digest_string, digestLength, digest);
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
            File_Printf(projectLogFile, messageFile,
                        "ERROR1021: signature invalid length %lu\n", signatureLength);
            rc = ERROR_CODE;
        }
    }
    /* verify the signature with the coprocessor key CCA token */
    if (rc == 0) {
        if (verbose)
            fprintf(messageFile,
                    "SignECCP521: verify signature with the coprocessor key token\n");
        rc = Digital_Signature_Verify_ECC(signatureLength,		/* input */
                                          signature,		/* input signature */
                                          keyTokenLength,		/* input */
                                          keyToken,			/* input key */
                                          digestLength,		/* input */
                                          digest);			/* input digest */
    }
    /* code to verify the signature using openssl */
    if (rc == 0) {
        if (verbose) fprintf(messageFile,
                             "SignECCP521: "
                             "verify signature with OpenSSL and the key token\n");
        rc = Ossl_VerifyECC(&valid,
                            digest,			/* input: digest to be verified */
                            digestLength,
                            eccKeyTokenPublic.publicKey,
                            eccKeyTokenPublic.qLen,
                            signature,		/* input: signature */
                            signatureLength);
        if (!valid) {
            File_Printf(projectLogFile, messageFile,
                        "ERROR1022 verifying signature with OpenSSL and the key token\n");
            rc = ERROR_CODE;
        }
    }
    /* write the signature to the output attachment  */
    if (rc == 0) {
        if (verbose) fprintf(messageFile, "SignECCP521: Writing output file %s\n",
                             outputAttachmentFileName);
        rc = File_WriteBinaryFile(signature, signatureLength, outputAttachmentFileName);
        if (rc != 0) {
            File_Printf(projectLogFile, messageFile,
                        "ERROR1023 writing signature to file %s\n", outputAttachmentFileName);
            rc = ERROR_CODE;
        }
    }
    /* cleanup */
    return rc;
}

/* GetArgs() gets the command line arguments from the framework.
 */

int GetArgs(const char **outputBodyFilename,
            const char **usr,
            const char **password,
            const char **projectLogFileName,
            const char **sender,
            const char **project,
            const char **auxcfgFilename,
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
                        "ERROR1001: -obody option (output email body) needs a value\n");
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
                        "ERROR1002: -usr option (CCA user ID) needs a value\n");
                rc = ERROR_CODE;
            }
        }
        else if (strcmp(argv[i],"-pwd") == 0) {
            i++;
            if (i < argc) {
                *password = argv[i];
            }
            else {
                fprintf(messageFile,
                        "ERROR1003: -pwd option (CCA password) needs a value\n");
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
                        "ERROR1004: -log option (audit log file name) needs a value\n");
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
                        "ERROR1005: -sender option needs a value\n");
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
                        "ERROR1006: -project option needs a value\n");
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
                        "ERROR1007: -key option needs a value\n");
                rc = ERROR_CODE;
            }
        }
        else if (strcmp(argv[i],"-auxcfg") == 0) {
            i++;
            if (i < argc) {
                *auxcfgFilename = argv[i];
            }
            else {
                fprintf(messageFile,
                        "ERROR1008: -auxcfg option needs a value\n");
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
                        "ERROR1009: -di option needs a value\n");
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
                        "ERROR1010: -do option needs a value\n");
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
                    "ERROR1011: -usr option missing\n");
            rc = ERROR_CODE;
        }
    }
    if (rc == 0) {
        if (*password == NULL) {
            fprintf(messageFile,
                    "ERROR1012: -pwd option missing\n");
            rc = ERROR_CODE;
        }
    }
    if (rc == 0) {
        if (*sender== NULL) {
            fprintf(messageFile,
                    "ERROR1013: -sender option missing\n");
            rc = ERROR_CODE;
        }
    }
    if (rc == 0) {
        if (*projectLogFileName == NULL) {
            fprintf(messageFile,
                    "ERROR1014: -log option missing\n");
            rc = ERROR_CODE;
        }
    }
    if (rc == 0) {
        if (*keyFileName == NULL) {
            fprintf(messageFile,
                    "ERROR1015: -key option missing\n");
            rc = ERROR_CODE;
        }
    }
    if (rc == 0) {
        if (*auxcfgFilename == NULL) {
            fprintf(messageFile,
                    "ERROR1026: -auxcfg option missing\n");
            rc = ERROR_CODE;
        }
    }
    if (rc == 0) {
        if (*inputAttachmentFileName == NULL) {
            fprintf(messageFile,
                    "ERROR1016: -di option missing\n");
            rc = ERROR_CODE;
        }
    }
    if (rc == 0) {
        if (*outputAttachmentFileName == NULL) {
            fprintf(messageFile,
                    "ERROR1017: -do option missing\n");
            rc = ERROR_CODE;
        }
    }
    return rc;
}

void PrintUsage()
{
    fprintf(messageFile, "\n");
    fprintf(messageFile,
            "\tsignecc usage:\n"
            "\n"
            "Common arguments:\n"
            "\n"
            "\t-usr        - CCA user (profile) ID\n"
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
            "\t[-obody      - output email body file name (should be first argument)]\n"
            "\t-sender     - request sender\n"
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

uint16_t getUint16( uint8_t *data, int p_endianess )
{
    uint16_t value = 0;

    if (p_endianess)
    {
        value = data[1] | (data[0] << 8);
    }
    else
    {
        value = data[0] | (data[1] << 8);
    }

    return value;
}

uint32_t getUint32( uint8_t *data, int p_endianess )
{
    uint32_t value = 0;

    if (p_endianess)
    {
        value = (data[3] | (data[2] << 8) | (data[1] << 16) | (data[0] << 24));
    }
    else
    {
        value = (data[0] | (data[1] << 8) | (data[2] << 16) | (data[3] << 24));
    }

    return value;
}


void putUint32( uint32_t *value, uint8_t *data, int p_endianess )
{
    if (p_endianess)
    {
       data[0] = (uint8_t)(((*value) & 0xff000000) >> 24);
       data[1] = (uint8_t)(((*value) & 0x00ff0000) >> 16);
       data[2] = (uint8_t)(((*value) & 0x0000ff00) >>  8);
       data[3] = (uint8_t)(((*value) & 0x000000ff));
    }
    else
    {
       data[0] = (uint8_t)(((*value) & 0x000000ff));
       data[1] = (uint8_t)(((*value) & 0x0000ff00) >>  8);
       data[2] = (uint8_t)(((*value) & 0x00ff0000) >> 16);
       data[3] = (uint8_t)(((*value) & 0xff000000) >> 24);
    }

    return;
}
