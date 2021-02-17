/* Copyright 2021 IBM Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


/* This program creates and signs a certificate.

   The steps are:

   Get the issuer key and certificate data
   Get the subject key and certificate data
   Test that the subject key is a signing key that belongs to this coprocessor
   Form the X509 certificate
   Digest the certificate
   Sign the certificate
   Append the signature to the certificate
   Write the certificate to a file
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>

#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "cca_functions.h" 
#include "cca_structures.h"
#include "ossl_functions.h"
#include "ossl_certificate.h"

#include "utils.h"
#include "debug.h"

/* NOTE:  These next four have to stay in sync.  The program will not run otherwise. */

/* Strings in auxiliary configuration file for issuer */ 

const char *IssuerStrings[] = {
    "issuerCountryName",
    "issuerStateOrProvinceName",
    "issuerLocalityName",
    "issuerOrganizationName",
    "issuerCommonName"
};    

/* Strings in auxiliary configuration file for issuer */ 

const char *SubjectStrings[] = {
    "subjectCountryName",
    "subjectStateOrProvinceName",
    "subjectLocalityName",
    "subjectOrganizationName",
    "subjectCommonName"
};    

/* CertNames is n array holding the basic info doe an X509 certificate */

typedef char * CertNames[5];

/* Strings for openssl X509 certificate builder.  The nid is used to add the item to the
   certificate.  The key is only used for debug tracing. */

CertificateNameRow certificateNameTable[] = {
    { "countryName",			NID_countryName},
    { "stateOrProvinceName",		NID_stateOrProvinceName},
    { "localityName",			NID_localityName},
    { "organizationName",		NID_organizationName},
    { "commonName",			NID_commonName},
};

/* local prototypes */

void CertNames_Init(CertNames *certNames);
void CertNames_Delete(CertNames *certNames);

int CertNames_GetAll(CertNames 	*certNames,
		     const char *certStrings[],
		     char	*lineBuffer,
		     size_t	lineBufferLength,
		     FILE 	*projectAuxConfigFile,
		     const char *projectAuxConfigFileName,
		     FILE 	*projectLogFile);

int CertNames_GetTop(CertNames 	*certNames,
		     const char *certStrings[],
		     char	*lineBuffer,
		     size_t	lineBufferLength,
		     FILE 	*projectAuxConfigFile,
		     const char *projectAuxConfigFileName,
		     FILE 	*projectLogFile);

#if 0
int CertNames_GetLast(CertNames  *certNames,
		      const char *certStrings[],
		      char	 *lineBuffer,
		      size_t	 lineBufferLength,
		      FILE 	 *projectAuxConfigFile,
		      const char *projectAuxConfigFileName,
		      FILE 	 *projectLogFile);
#endif

int GetArgs(const char **outputBodyFilename,
	    const char **usr,
	    const char **password,
	    const char **projectLogFileName,
	    const char **projectAuxConfigFileName,
	    const char **sender,
	    const char **project,
	    const char **certify_project,
	    const char **keyFileName,
	    const char **outputAttachmentFileName,
	    int *verbose,
	    int argc,
	    char **argv);
int GetAuxArgs(char **signAlgorithm,
	       char **digestAlgorithm,
	       unsigned int *validity,
	       CertNames *issuerCertNames,
	       CertNames *subjectCertNames,
	       char **certifyKeyFileName,		
	       int  *final,
	       const char *certify_project,
	       const char *projectAuxConfigFileName,
	       FILE *projectLogFile);

int GetCertifyArgs(char 	**certifyKeyFileName,
		   CertNames 	*subjectCertNames,
		   int  	final,
		   const char 	*certify_project,
		   char		*lineBuffer,
		   size_t	lineBufferLength,
		   FILE 	*projectLogFile);

void PrintUsage(void);

int CheckAuxArgs(const char *signAlgorithm,
		 const char *digestAlgorithm,
		 FILE *projectLogFile);

int CreateCert(X509 			**x509Certificate,
	       unsigned char 		*nModulus,
	       unsigned int 		nLength,
	       unsigned char 		*eExponent,
	       unsigned int 		eLength,
	       char			**issuerEntries,
	       size_t			issuerEntriesLength,
	       char 			**subjectEntries,
	       size_t 			subjectEntriesLength,
	       CertificateNameRow 	certificateNameTable[],
	       size_t 			certificateNameTableRows,
	       unsigned int 		validity,
	       int  			final,
	       char 			*digestAlgorithm,
	       FILE 			*projectLogFile);
int Sign(unsigned char		**signature,
	 unsigned long		*signatureLength,
	 RsaKeyTokenPublic  	*rsaKeyTokenPublic,
	 const char 		*keyFileName,
	 unsigned char		*digest,
	 size_t			digestLength,
	 const char		*digestAlgorithm,
	 FILE 			*projectLogFile);

int TestSign(unsigned char	**signature,
	     unsigned long	*signatureLength,
	     unsigned char	**digest,
	     const char 	*keyFileName,
	     FILE 		*projectLogFile);
int TestVerify(X509 *x509Certificate,
	       RsaKeyTokenPublic *rsaKeyTokenPublic,
	       FILE 		*projectLogFile);

/* messages are traced here */
FILE *messageFile = NULL;
int  verbose = FALSE;
int debug = FALSE;

int main(int argc, char** argv)
{
    int 		rc = 0;
    int 		rc1 = 0;
    int 		irc = 0;

    /* command line arguments */
    const char 		*outputBodyFilename = NULL;	/* for email results */
    const char  	*usr = NULL;			/*  CCA profile */
    const char 		*password = NULL;		/* CCA plaintext password */
    const char 		*projectLogFileName = NULL;	/* audit log file name */
    const char 		*projectAuxConfigFileName = NULL;
    const char 		*sender = NULL;			/* email sender, for audit log */
    const char 		*project = NULL;		/* this project, for audit log */
    const char 		*certify_project = NULL;	/* for key to be certified */
    const char 		*keyFileName = NULL;		/* certifying key */
    const char 		*outputAttachmentFileName = NULL;	/* to return DER certificate */

    FILE		*projectLogFile = NULL;			/* closed @1 */

    /* auxcfg arguments */
    char 		*signAlgorithm = NULL;		/* freed @2 */
    char 		*digestAlgorithm = NULL;	/* freed @3 */
    unsigned int	validity;			/* in years */
    CertNames 		issuerCertNames;		/* for x509 certificate */
    CertNames 		subjectCertNames;		/* for x509 certificate */
    int  		final;				/* bool, final certificate in the chain */
    char 		*certifyKeyFileName = NULL;	/* key to be certified, freed @6 */
    
    time_t      	log_time;
    int			loggedIn = FALSE;

    /* key to be certified */
    unsigned char 	*certifyKeyToken = NULL;	/* CCA key token, freed @7 */
    size_t		certifyKeyTokenLength;
    X509 		*x509Certificate = NULL;	/* freed @8 */

    /* certificate digest to be signed */
    unsigned char 	*digest = NULL;			/* freed @9 */
    unsigned int 	digestLength;			/* just the digest */
    unsigned int 	oidDigestLength;		/* length of digest plus OID */

    /* certificate signature */
    unsigned char	*signature = NULL;		/* freed @10 */
    unsigned long	signatureLength;
    int			signatureAdded = FALSE;		/* has signature been added to certificate */

    messageFile = stdout;

    CertNames_Init(&issuerCertNames);				/* freed @4 */
    CertNames_Init(&subjectCertNames);				/* freed @5 */
    
    OpenSSL_add_all_algorithms();
    /* get caller's command line arguments */
    if (rc == 0) {
	rc = GetArgs(&outputBodyFilename,
		     &usr,
		     &password,
		     &projectLogFileName,
		     &projectAuxConfigFileName,
		     &sender,
		     &project,
		     &certify_project,
		     &keyFileName,
		     &outputAttachmentFileName,
		     &verbose,
		     argc, argv);
    }
    /* audit logging */
    if (rc == 0) {
	if (verbose) fprintf(messageFile, "Opening audit log %s\n", projectLogFileName);
	projectLogFile = fopen(projectLogFileName, "a");		/* closed @1 */
	if (projectLogFile == NULL) {
	    fprintf(messageFile, "ERROR1151: Cannot open audit log %s, %s\n",
		    projectLogFileName, strerror(errno));
	    rc = ERROR_CODE;
	}
    }
    if (rc == 0) {
	if (verbose) fprintf(messageFile, "Program: sign_cert\n");
    }
    /* update audit log, begin this entry */
    if (projectLogFile != NULL) {
	if (verbose) fprintf(messageFile, "Updating audit log\n");
	log_time = time(NULL);
	fprintf(projectLogFile, "\n%s", ctime(&log_time));
	fprintf(projectLogFile, "\tSender: %s\n", sender);
	fprintf(projectLogFile, "\tProject: %s\n", project);
	fprintf(projectLogFile, "\tProgram: %s\n", argv[0]);
	fprintf(projectLogFile, "\tCertifying Key file: %s\n", keyFileName);
	fprintf(projectLogFile, "\tProfile %s\n", usr);
    }
    /* program sanity check */
    if (rc == 0) {
	size_t tmpSize = sizeof(CertNames) / sizeof(char *);
	if (
	    (tmpSize != (sizeof(certificateNameTable)/sizeof(CertificateNameRow))) ||
	    (tmpSize != (sizeof(IssuerStrings)/sizeof(char *))) ||
	    (tmpSize != (sizeof(SubjectStrings)/sizeof(char *))) ) {
	    
	    File_Printf(projectLogFile, messageFile,
			"ERROR1158: Source code table mismatch\n");
	    rc = ERROR_CODE;
	}
    }
    /* get additional parameters from the project auxiliary configuration file */
    if (rc == 0) {
	rc = GetAuxArgs(&signAlgorithm,			/* freed @2 */
			&digestAlgorithm,		/* freed @3 */
			&validity,
			&issuerCertNames,		/* freed @4 */
			&subjectCertNames,		/* freed @5 */
			&certifyKeyFileName,		/* freed @6 */		
			&final,
			certify_project,
			projectAuxConfigFileName,
			projectLogFile);
    }
    /* log to audit log */
    if (rc == 0) {
	fprintf(projectLogFile, "\n");
	fprintf(projectLogFile, "\tSigning algorithm: %s\n", signAlgorithm);
	fprintf(projectLogFile, "\tDigest algorithm: %s\n", digestAlgorithm);
	fprintf(projectLogFile, "\tValidity: %u years\n", validity);
	fprintf(projectLogFile, "\tFinal certificate: %u\n", final);
	fprintf(projectLogFile, "\tCertify project: %s\n", certify_project);
	fprintf(projectLogFile, "\tKey to certify file: %s\n", certifyKeyFileName);
    }
    /* trace input parameters */
    if (rc == 0) {
	if (verbose) {
	    fprintf(messageFile, "\n");
	    fprintf(messageFile, "\tSigning algorithm: %s\n", signAlgorithm);
	    fprintf(messageFile, "\tDigest algorithm: %s\n", digestAlgorithm);
	    fprintf(messageFile, "\tValidity: %u years\n", validity);
	    fprintf(messageFile, "\tFinal certificate: %u\n", final);
	    fprintf(messageFile, "\tCertify project: %s\n", certify_project);
	    fprintf(messageFile, "\tKey to certify file: %s\n", certifyKeyFileName);

	    fprintf(messageFile, "\n");
	    fprintf(messageFile, "\tissuerCountryName: %s\n", issuerCertNames[0]);
	    fprintf(messageFile, "\tissuerStateOrProvinceName: %s\n", issuerCertNames[1]);
	    fprintf(messageFile, "\tissuerLocalityName: %s\n", issuerCertNames[2]);
	    fprintf(messageFile, "\tissuerOrganizationName: %s\n", issuerCertNames[3]);
	    fprintf(messageFile, "\tissuerCommonName: %s\n", issuerCertNames[4]);

	    fprintf(messageFile, "\n");
	    fprintf(messageFile, "\tsubjectCountryName: %s\n", subjectCertNames[0]);
	    fprintf(messageFile, "\tsubjectStateOrProvinceName: %s\n", subjectCertNames[1]);
	    fprintf(messageFile, "\tsubjectLocalityName: %s\n", subjectCertNames[2]);
	    fprintf(messageFile, "\tsubjectOrganizationName: %s\n", subjectCertNames[3]);
	    fprintf(messageFile, "\tsubjectCommonName: %s\n", subjectCertNames[4]);
	    fprintf(messageFile, "\n");
	}
    }
    /* verify that the specified crypto algorithms are supported */
    if (rc == 0) {
	rc = CheckAuxArgs(signAlgorithm,
			  digestAlgorithm,
			  projectLogFile);
    }
    /* read the CCA key token for the key being certified */
    if (rc == 0) {
	if (verbose) fprintf(messageFile, "Key token being certified at %s\n",
			     certifyKeyFileName);
	rc = File_ReadBinaryFile(&certifyKeyToken, 		/* freed @7 */
				 &certifyKeyTokenLength,
				 4000, certifyKeyFileName);
	if (rc != 0) {
	    File_Printf(projectLogFile, messageFile,
			"ERROR1152: Could not open key file: %s\n", certifyKeyFileName);
	}
    }    
    /* extract the public key from the key to be certified */
    RsaKeyTokenPublic certifyRsaKeyTokenPublic;		/* key to be certified */
    if (rc == 0) {
	rc = getPKA96PublicKey(&certifyRsaKeyTokenPublic,
			       certifyKeyTokenLength,
			       certifyKeyToken,
			       2048);
	if (rc != 0) {
	    File_Printf(projectLogFile, messageFile,
			"ERROR1153: Could not parse key file: %s\n", keyFileName);
	}
    }
    /* construct the certificate */
    if (rc == 0) {
	rc = CreateCert(&x509Certificate,	/* X509 certificate to be generated, freed @8 */
			certifyRsaKeyTokenPublic.n,		/* key to be certified */
			certifyRsaKeyTokenPublic.nByteLength,
			certifyRsaKeyTokenPublic.e,
			certifyRsaKeyTokenPublic.eLength,
			issuerCertNames,
			sizeof(CertNames) / sizeof(char *),
			subjectCertNames,
			sizeof(CertNames) / sizeof(char *),
			certificateNameTable,
			sizeof(certificateNameTable)/sizeof(CertificateNameRow),
			validity,
			final,
			digestAlgorithm,
			projectLogFile);
    }
    /* calculate the certificate digest to be signed */
    if (rc == 0) {
	rc = Ossl_Cert_GetDigest(&digest,		/* digest plus OID, freed @9 */
				 &digestLength,		/* just the digest */
				 &oidDigestLength,	/* length of digest plus OID */
				 digestAlgorithm,
				 x509Certificate);
	if (rc != 0) {
	    File_Printf(projectLogFile, messageFile,
			"ERROR1154: Could not digest the certificate\n");
	}
    }
    /* trace the certificate before signing */
    if (rc == 0) {
	if (verbose) PrintAll(messageFile,
			      "Certificate digest to sign",
			      digestLength, digest + oidDigestLength - digestLength);
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
			"ERROR1155 : Login failed, Bad user name %s or bad password\n", usr);
	}
    }
    /* sign an all zero digest with the key to be certified.  This validates that the key token is
       really a CCA key token from this coprocessor, and thus is eligible to be certified.
    */
    unsigned char 	*testDigest = NULL;
    unsigned char	*testSignature = NULL;
    unsigned long	testSignatureLength;
    if (rc == 0) {
	if (verbose) fprintf(messageFile, "Test signing with key to be certified\n");
	rc = TestSign(&testSignature, &testSignatureLength,	/* output, freed @11 */
		      &testDigest,				/* output, freed @12 */
		      certifyKeyFileName,			/* inputs */
		      projectLogFile);
	
    }   
    free(testSignature);	/* @11 */
    free (testDigest);		/* @12 */
    testSignature = NULL;
        
    /* sign the certificate digest */
    RsaKeyTokenPublic  	rsaKeyTokenPublic;	/* signing key token, CCA format */
    if (rc == 0) {
	if (verbose) fprintf(messageFile, "Signing certificate\n");
	rc = Sign(&signature, &signatureLength,	/* output, freed @10 */
		  &rsaKeyTokenPublic,		/* output: signing key token, CCA format */
		  keyFileName,			/* inputs */
		  digest,			/* OID plus digest */
		  oidDigestLength,		/* OID plus digest */
		  digestAlgorithm,
		  projectLogFile);
    }
    /* log out of CCA ASAP after signing, no rc test, log out even on error */
    if (loggedIn) {
	if (verbose) fprintf(messageFile, "Logging out with user name %s\n", usr);
 	rc1 = Login_Control(FALSE,	/* log out */
			    usr,	/* CCA profile */
			    NULL);	/* password */
	if (rc == 0) {
	    rc = rc1;
	}
    }
    /* attach the signature to the certificate */
    if (rc == 0) {
	Ossl_Cert_AddSignature(x509Certificate,
			       signature,
			       signatureLength);
	signatureAdded = TRUE;
    }
    /* sanity check, verify the certificate signature against the CCA signing key */
    if (rc == 0) {
	rc = TestVerify(x509Certificate,	/* certificate to verify */
			&rsaKeyTokenPublic,	/* signing key token, CCA format */
			projectLogFile);
    }
    /* write the certificate to the output attachment */
    if (rc == 0) {
	if (verbose) fprintf(messageFile, "Writing certificate to %s\n",
			     outputAttachmentFileName);
	rc = Ossl_Cert_Write(outputAttachmentFileName,
			     x509Certificate);
	if (rc != 0) {
	    File_Printf(projectLogFile, messageFile,
		    "ERROR1156: Cannot write certificate to %s\n\n",
		    outputAttachmentFileName);
	}
    }    
    if (rc == 0) {
	/* digest audit logging, for debugging if certificate chain verification later fails */
	PrintAll(projectLogFile, "\tDigest of certificate being signed:",
		 digestLength, digest + oidDigestLength - digestLength);
	/* certificate audit logging */
	irc = X509_print_fp(projectLogFile, x509Certificate);
	if (irc != 1) {
	    File_Printf(projectLogFile, messageFile,
		    "ERROR1157 in certificate print X509_print_fp()\n");
	    rc = ERROR_CODE;
	}
	if (verbose) {
	    irc = X509_print_fp(messageFile, x509Certificate);
	    if (irc != 1) {
		File_Printf(projectLogFile, messageFile,
			    "ERROR1157 in certificate print X509_print_fp()\n");
		rc = ERROR_CODE;
	    }
	}
    }
    if (verbose) {
	File_Printf(projectLogFile, messageFile,
		    "\tReturn code: %u\n", rc);
    }
    /* clean up */
    if (projectLogFile != NULL) {
	fclose(projectLogFile);			/* @1 */
    }
    if (messageFile != stdout) {
	fflush(messageFile);
	fclose(messageFile);
    }
    free(signAlgorithm);			/* @2 */
    free(digestAlgorithm);			/* @3 */
    CertNames_Delete(&issuerCertNames);		/* @4 */
    CertNames_Delete(&subjectCertNames);	/* @5 */
    free(certifyKeyFileName);			/* @6 */
    free(certifyKeyToken);			/* @7 */
    X509_free(x509Certificate);			/* @8 */
    free(digest);				/* @9 */
    /* if the signature was added to the certificate, it will be freed as part of it.  If not, free
       it here. */
    if (!signatureAdded) {
	free(signature);			/* @10 */
    }
    return rc;
}

/* Sign() does the CCA signing.  It does a sanity check verification using both CCA and openssl.

 */

int Sign(unsigned char		**signature,		/* output, freed by caller */
	 unsigned long		*signatureLength,
	 RsaKeyTokenPublic  	*rsaKeyTokenPublic,	/* output: signing key token, CCA format */
	 const char 		*keyFileName,		/* input: signing key */
	 unsigned char		*digest,		/* digest plus OID */
	 size_t			oidDigestLength,	/* digest plus OID */
	 const char		*digestAlgorithm,
	 FILE 			*projectLogFile)
{
    int		rc = 0;

    /* signing key */
    unsigned char 	*keyToken = NULL;	/* CCA signing key token, freed @1 */
    size_t		keyTokenLength;

    int			valid;			/* true if signature verifies */
    unsigned long 	signatureBitLength;	/* unused */

    /* get the CCA signing key token */
    if (rc == 0) {
	if (verbose) fprintf(messageFile, "Sign: Reading CCA key token file %s\n",
			     keyFileName);
	rc = File_ReadBinaryFile(&keyToken, &keyTokenLength, 2000, keyFileName); /* freed @1 */
	if (rc != 0) {
	    File_Printf(projectLogFile, messageFile,
			"ERROR1031: Could not open key file: %s\n", keyFileName);
	}
    }
    /* allocate a buffer for the RSA signature */
    if (rc == 0) {
	*signatureLength = N_SIZE;
	rc = Malloc_Safe(signature,		/* freed by caller */
			 N_SIZE,
			 N_SIZE);		/* hard code for the project */
    }
    /* extract the signing CCA public key from the CCA signing key token  */
    if (rc == 0) {
	if (verbose) fprintf(messageFile, "Sign: key token length %lu\n", keyTokenLength);
	if (verbose)
	    fprintf(messageFile, "Sign: extract the public key from CCA key token\n");
	rc = getPKA96PublicKey(rsaKeyTokenPublic,	/* output: structure */
			       keyTokenLength,		
			       keyToken,		/* input: PKA96 key token */
			       2048);
	if (rc != 0) {
	    File_Printf(projectLogFile, messageFile,
			"ERROR1035: Could not parse key file: %s\n", keyFileName);
	}
    }
    long (*verifyFunc)();	/* signature verification function varies with digest algorithm */
    unsigned int 	digestLength;	/* digest length without OID */
    
    /* process digest algorithm */
    if (rc == 0) {
	if (verbose)
	    fprintf(messageFile, "Sign: Parsing the digest algorithm\n");
	if (strcmp(digestAlgorithm, "SHA-1") == 0) {
	    digestLength = SHA1_SIZE;
	    verifyFunc = osslVerify;
	}
	else if (strcmp(digestAlgorithm, "SHA-256") == 0) {
	    digestLength = SHA256_SIZE;
	    verifyFunc = osslVerify256;
	}
	else {
	    File_Printf(projectLogFile, messageFile,
			"ERROR1032: Digest algorithm %s not supported\n",
			digestAlgorithm);
	    rc = ERROR_CODE;
	}
    }
    /* sign with the coprocessor.  The coprocessor doesn't know the digest algorithm.  It just
       signs an OID + digest, supplying the padding */
    if (rc == 0) {
	if (verbose) PrintAll(messageFile,
			      "Sign: hash to sign",
			      oidDigestLength, digest);
	rc = Digital_Signature_Generate(signatureLength,	/* i/o */
					&signatureBitLength,	/* output */
					*signature,		/* output */
					keyTokenLength,		/* input */
					keyToken,		/* input */
					oidDigestLength,	/* input */
					digest,			/* input */
					SIGN_PKCS_1_1);		/* input */
    }
    /*
      The verify functions should never fail.  They are just sanity checks on the code.
    */
    /* sanity check on the signature length */
    if (rc == 0) {
	if (*signatureLength != N_SIZE) {
	    File_Printf(projectLogFile, messageFile,
			"ERROR1033: signature invalid length %lu\n", *signatureLength);
	    rc = ERROR_CODE;
	}
    }
    /* verify the signature with the coprocessor signing key CCA token */
    if (rc == 0) {
	if (verbose)
	    fprintf(messageFile,
		    "Sign: verify signature with the coprocessor key token\n");
	rc = Digital_Signature_Verify(N_SIZE,			/* input */
				      *signature,		/* input signature */
				      keyTokenLength,		/* input */
				      keyToken,			/* input key */
				      oidDigestLength,		/* input */
				      digest,			/* input hash */
				      SIGN_PKCS_1_1);		/* input format */
    }
    /* sample code to verify the signature using openssl */
    if (rc == 0) {
	if (verbose) fprintf(messageFile,
			     "Sign: verify signature with OpenSSL and the key token\n");
	rc = verifyFunc(&valid,
			digest + oidDigestLength - digestLength, /* input: digest to be verified */
			rsaKeyTokenPublic->e,		/* exponent */
			rsaKeyTokenPublic->eLength, 
			rsaKeyTokenPublic->n, 		/* public key */
			rsaKeyTokenPublic->nByteLength,
			*signature,			/* signature */
			*signatureLength);
	if (!valid) {
	    File_Printf(projectLogFile, messageFile,
		    "ERROR1034: Error verifying signature with OpenSSL and the key token\n");
	    rc = ERROR_CODE;
	}
    }
    /* clean up */
    free(keyToken);	/* @1 */
    return rc;
}

/* TestSign() does the CCA signing.  This validates that the key to be certified is a CCA key and
   thus worthy of being certified.

   It does a sanity check verification using both CCA and openssl.

   SHA-1 is as good as any just to test.  An all zero digest is signed, which is useless to an
   attacker.

*/

int TestSign(unsigned char	**signature,		/* output, freed by caller */
	     unsigned long	*signatureLength,
	     unsigned char	**digest,		/* output, freed by caller */
	     const char 	*keyFileName,		/* input: signing key */
	     FILE 		*projectLogFile)
{
    int		rc = 0;

    /* signing key */
    unsigned char 	*keyToken = NULL;	/* CCA signing key token, freed @1 */
    size_t		keyTokenLength;
    RsaKeyTokenPublic 	rsaKeyTokenPublic;	/* signing key CCA public key structure */

    int			valid;			/* true if signature verifies */
    unsigned long 	signatureBitLength;	/* unused */

    unsigned int 	oidDigestLength;	/* length of digest plus OID */
    
    /* SHA-1 with RSA OID (Object Identifier) */
    static const unsigned char sha1_rsa_oid[] = {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E,
						 0x03, 0x02, 0x1A, 0x05, 0x00, 0x04, 0x14};

    /* get the CCA signing key token */
    if (rc == 0) {
	if (verbose) fprintf(messageFile, "TestSign: Reading CCA key token file %s\n",
			     keyFileName);
	rc = File_ReadBinaryFile(&keyToken, &keyTokenLength, 2000, keyFileName); /* freed @1 */
	if (rc != 0) {
	    File_Printf(projectLogFile, messageFile,
			"ERROR1031: Could not open key file: %s\n", keyFileName);
	}
    }
    /* extract the CCA signing public key from the CCA signing key token  */
    if (rc == 0) {
	if (verbose) fprintf(messageFile, "TestSign: key token length %lu\n", keyTokenLength);
	if (verbose)
	    fprintf(messageFile, "TestSign: extract the public key from CCA key token\n");
	rc = getPKA96PublicKey(&rsaKeyTokenPublic,	/* output: structure */
			       keyTokenLength,		
			       keyToken,		/* input: PKA96 key token */
			       2048);
	if (rc != 0) {
	    File_Printf(projectLogFile, messageFile,
			"ERROR1035: Could not parse key file: %s\n", keyFileName);
	}
    }
    /* allocate a buffer for the RSA signature */
    if (rc == 0) {
	*signatureLength = N_SIZE;
	rc = Malloc_Safe(signature,		/* freed by caller */
			 N_SIZE,
			 N_SIZE);		/* hard code for the project */
    }
    /* allocate a buffer for the OID plus digest */
    if (rc == 0) {
	oidDigestLength = sizeof(sha1_rsa_oid) + SHA1_SIZE;
	rc = Malloc_Safe(digest,	/* freed by caller */
			 oidDigestLength,
			 oidDigestLength);
    }
    /* prepend OID, set digest to zeros (test value) */
    if (rc == 0) {
	if (verbose) fprintf(messageFile,
			     "Ossl_Cert_GetDigest: Prepending OID, length %lu\n",
			     sizeof(sha1_rsa_oid));
	memset(*digest, 0, oidDigestLength);
	memcpy(*digest, sha1_rsa_oid, sizeof(sha1_rsa_oid));
    }
    /* sign with the coprocessor.  The coprocessor doesn't know the digest algorithm.  It just
       signs an OID + digest */
    if (rc == 0) {
	if (verbose) PrintAll(messageFile,
			      "TestSign: hash to sign",
			      oidDigestLength, *digest);
	rc = Digital_Signature_Generate(signatureLength,	/* i/o */
					&signatureBitLength,	/* output */
					*signature,		/* output */
					keyTokenLength,		/* input */
					keyToken,		/* input */
					oidDigestLength,	/* input */
					*digest,		/* input */
					SIGN_PKCS_1_1);		/* input */
					
    }
    /*
      The verify functions should never fail.  They are just sanity checks on the code.
    */
    /* sanity check on the signature length */
    if (rc == 0) {
	if (*signatureLength != N_SIZE) {
	    File_Printf(projectLogFile, messageFile,
			"ERROR1033: test signature invalid length %lu\n", *signatureLength);
	    rc = ERROR_CODE;
	}
    }
    /* verify the signature with the coprocessor key CCA token */
    if (rc == 0) {
	if (verbose)
	    fprintf(messageFile,
		    "TestSign: verify signature with the coprocessor key token\n");
	rc = Digital_Signature_Verify(N_SIZE,			/* input */
				      *signature,		/* input signature */
				      keyTokenLength,		/* input */
				      keyToken,			/* input key */
				      oidDigestLength,		/* input */
				      *digest,			/* input hash */
				      SIGN_PKCS_1_1);		/* input format */
    }
    /* sample code to verify the signature using openssl */
    if (rc == 0) {
	if (verbose) fprintf(messageFile,
			     "TestSign: verify signature with OpenSSL and the key token\n");
	rc = osslVerify(&valid,
			*digest + oidDigestLength - SHA1_SIZE, /* input: digest to be verified */
			rsaKeyTokenPublic.e,		/* exponent */
			rsaKeyTokenPublic.eLength, 
			rsaKeyTokenPublic.n, 		/* public key */
			rsaKeyTokenPublic.nByteLength,
			*signature,			/* signature */
			*signatureLength);
	if (!valid) {
	    File_Printf(projectLogFile, messageFile,
			"ERROR1034: "
			"Error verifying test signature with OpenSSL and the key token\n");
	    rc = ERROR_CODE;
	}
    }
    /* clean up */
    free(keyToken);	/* @1 */
    return rc;
}

/* TestVerify() is a sanity check.  It verifies the X509 certificate signature against the CCA
   signing key
*/

int TestVerify(X509 		*x509Certificate,	/* certificate to verify */
	       RsaKeyTokenPublic *rsaKeyTokenPublic,	/* signing key token, CCA format */
	       FILE 		*projectLogFile)
{
    int			rc = 0;
    int 		irc = 0;
    RSA 	  	*rsaSignKey;	/* signing key OpenSSL format */
    EVP_PKEY 		*evpSignkey;	/* signing key, EVP format */
    evpSignkey = NULL;			/* freed @1 */
    rsaSignKey = NULL;			/* freed @2 */

    /* convert the CCA signing key structure to OpenSSL RSA structure */
    if (rc == 0) {
	if (verbose) fprintf(messageFile,
			     "TestVerify: Verifying the certificate using openSSL\n");
	if (verbose) fprintf(messageFile,
			     "TestVerify: Converting signing key to openssl RSA format\n");
	rc = osslBinToRSA(&rsaSignKey,		/* freed by caller */
			  rsaKeyTokenPublic->e,
			  rsaKeyTokenPublic->eLength,
			  rsaKeyTokenPublic->n,
			  rsaKeyTokenPublic->nByteLength);
	if (rc != 0) {
	    File_Printf(projectLogFile, messageFile,
			"ERROR1041 converting signing key from CCA to RSA\n");
	    rc = ERROR_CODE;
	}
    }
    /* create an EVP_PKEY public key type */
    if (rc == 0) {
	evpSignkey = EVP_PKEY_new();
	if (evpSignkey == NULL) {
	    File_Printf(projectLogFile, messageFile,
			"ERROR1042 allocating EVP format key\n");
	    rc = ERROR_CODE;
	}
    }
    /* convert signing key from OpenSSL RSA to EVP_PKEY public key type */
    if (rc == 0) {
	if (verbose) fprintf(messageFile,
			     "TestVerify: Converting signing key to openssl EVP format\n");
	irc = EVP_PKEY_assign_RSA(evpSignkey, rsaSignKey);
	if (irc != 1) {
	    File_Printf(projectLogFile, messageFile,
			"ERROR1043 converting signing key from RSA to EVP format\n");
	    rc = ERROR_CODE;
	}
    }
    /* verify the certificate signature using the signing public key */
    if (rc == 0) {
	if (verbose) fprintf(messageFile, "TestVerify: Verifying the certificate\n");
	irc = X509_verify(x509Certificate, evpSignkey);
	if (irc != 1) {
	    File_Printf(projectLogFile, messageFile,
			"ERROR1044 verifying certificate against CCA signing key\n");
	    rc = ERROR_CODE;
	}
    }
    if (evpSignkey != NULL) {
	EVP_PKEY_free(evpSignkey);	/* @1 */
	rsaSignKey = NULL;	/* I think freeing the EVP object implicitly frees the RSA object */
    }
    if (rsaSignKey != NULL) {
	RSA_free(rsaSignKey);		/* @2 */	
    }
    return rc;
}

/* CheckAlgorithms() verifies that arguments that may be specified from the auxiliary configuration
   file have been set and are valid.

   The signature algorithm RSA-2048 is supported.
   The digest algorithms SHA-1, SHA-256, SHA-512 are supported.
*/

int CheckAuxArgs(const char *signAlgorithm,
		 const char *digestAlgorithm,
		 FILE *projectLogFile)
{
    int		rc = 0;

    /* digestAlgorithm */
    if (rc == 0) {
	if ((strcmp(digestAlgorithm, "SHA-1") != 0) &&
	    (strcmp(digestAlgorithm, "SHA-256") != 0)) {
	    File_Printf(projectLogFile, messageFile,
			"ERROR1201: Digest algorithm %s not supported\n",
			digestAlgorithm);
	    rc = ERROR_CODE;
	}
    }
    /* signAlgorithm */
    if (rc == 0) {
	if (strcmp(signAlgorithm, "RSA-2048") != 0) {
	    File_Printf(projectLogFile, messageFile,
		    "ERROR1202: Signing algorithm %s not supported\n",
		    signAlgorithm);
	    rc = ERROR_CODE;
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
	    const char **certify_project,
	    const char **keyFileName,
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
	else if (strcmp(argv[i],"-auxcfg") == 0) {
	    i++;
	    if (i < argc) {
		*projectAuxConfigFileName = argv[i];
	    }
	    else {
		fprintf(messageFile,
			"ERROR1005: "
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
	else if (strcmp(argv[i],"-certify_project") == 0) {
	    i++;
	    if (i < argc) {
		*certify_project = argv[i];
	    }
	    else {
		fprintf(messageFile,
			"ERROR1008: -certify_project option needs a value\n");
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
			"ERROR1009: -key option needs a value\n");
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
	if (*projectLogFileName == NULL) {
	    fprintf(messageFile,
		    "ERROR1013: -log option missing\n");
	    rc = ERROR_CODE;
	}
    }
    if (rc == 0) {
	if (*projectAuxConfigFileName == NULL) {
	    fprintf(messageFile,
		    "ERROR1014: -auxcfg option missing\n");
	    rc = ERROR_CODE;
	}
    }
    if (rc == 0) {
	if (*sender== NULL) {
	    fprintf(messageFile,
		    "ERROR1015: -sender option missing\n");
	    rc = ERROR_CODE;
	}
    }
    if (rc == 0) {
	if (*project == NULL) {
	    fprintf(messageFile,
		    "ERROR1016: -project option missing\n");
	    rc = ERROR_CODE;
	}
    }
    if (rc == 0) {
	if (*certify_project == NULL) {
	    fprintf(messageFile,
		    "ERROR1017: -certify_project option missing\n");
	    rc = ERROR_CODE;
	}
    }
    if (rc == 0) {
	if (*keyFileName == NULL) {
	    fprintf(messageFile,
		    "ERROR1018: -key option missing\n");
	    rc = ERROR_CODE;
	}
    }
    if (rc == 0) {
	if (*outputAttachmentFileName == NULL) {
	    fprintf(messageFile,
		    "ERROR1019: -do option missing\n");
	    rc = ERROR_CODE;
	}
    }
    return rc;
}

/* GetAuxArgs() gets project parameters form the project auxiliary configuration file
 */

int GetAuxArgs(char **signAlgorithm,			/* freed by caller */	
	       char **digestAlgorithm,			/* freed by caller */	
	       unsigned int *validity,
	       CertNames *issuerCertNames,		/* freed by caller */	
	       CertNames *subjectCertNames,		/* freed by caller */
	       char **certifyKeyFileName,		/* freed by caller */		
	       int  *final,
	       const char *certify_project,
	       const char *projectAuxConfigFileName,
	       FILE *projectLogFile)
{
    int		rc = 0;
    char	*lineBuffer = NULL;			/* freed @3 */
    size_t	lineBufferLength = 4000;		/* hard code for the project */
    FILE 	*projectAuxConfigFile = NULL;		/* closed @1 */
    FILE 	*certifyProjectAuxConfigFile = NULL;	/* closed @2 */

    /* allocate a line buffer, used when parsing the configuration file */
    if (rc == 0) {
	rc = Malloc_Safe((unsigned char **)&lineBuffer,	/* freed @2 */
			 lineBufferLength,
			 lineBufferLength);		/* hard code for the project */
	if (rc != 0) {
	    File_Printf(projectLogFile, messageFile,
			"ERROR1051: Internal error at Malloc_Safe");
	}
    }
    /* open issuer (this certifying key) project auxiliary configuration file */
    if (rc == 0) {
	if (verbose) fprintf(messageFile,
			     "Opening auxiliary configuration file %s\n",
			     projectAuxConfigFileName);
	projectAuxConfigFile = fopen(projectAuxConfigFileName, "r");	/* closed @1 */
	if (projectAuxConfigFile == NULL) {
	    File_Printf(projectLogFile, messageFile,
			"ERROR1052: Cannot open auxiliary configuration file %s, %s\n",
			projectAuxConfigFileName, strerror(errno));
	    rc = ERROR_CODE;
	}
    }
    /* get the signature algorithm */
    if (rc == 0) {
	rc = File_MapNameToValue(signAlgorithm,		/* freed by caller */
				 "sign_algorithm",	/* name to search for */
				 lineBuffer,		/* supplied buffer for lines */
				 lineBufferLength,	/* size of the line buffer */
				 projectAuxConfigFile);	/* input file stream */
	if (rc != 0) {
	    File_Printf(projectLogFile, messageFile,
			"ERROR1053: Auxiliary configuration file %s missing sign_algorithm\n",
			projectAuxConfigFileName);
	}
    }
    /* get the digest algorithm */
    if (rc == 0) {
	rc = File_MapNameToValue(digestAlgorithm,	/* freed by caller */
				 "digest_algorithm",	/* name to search for */
				 lineBuffer,		/* supplied buffer for lines */
				 lineBufferLength,	/* size of the line buffer */
				 projectAuxConfigFile);	/* input file stream */
	if (rc != 0) {
	    File_Printf(projectLogFile, messageFile,
			"ERROR1054: Auxiliary configuration file %s missing digest_algorithm\n",
			projectAuxConfigFileName);
	}
    }
    /* get the validity */
    if (rc == 0) {
	rc = File_MapNameToUint(validity,
				"validity",
				lineBuffer,
				lineBufferLength,
				projectAuxConfigFile);
	if (rc != 0) {
	    File_Printf(projectLogFile, messageFile,
			"ERROR1055: Auxiliary configuration file %s missing or bad validity\n",
			projectAuxConfigFileName);
	}
    }
    /* get the issuer (this certifying key) certificate names */
    if (rc == 0) {
	rc = CertNames_GetAll(issuerCertNames,
			      IssuerStrings,
			      lineBuffer,
			      lineBufferLength,
			      projectAuxConfigFile,
			      projectAuxConfigFileName,
			      projectLogFile);
    }
    /* get final, boolean, is this the final certificate in the chain */
    if (rc == 0) {
	rc = File_MapNameToBool(final,
				"final",
				lineBuffer,
				lineBufferLength,
				projectAuxConfigFile);
	if (rc != 0) {
	    File_Printf(projectLogFile, messageFile,
			"ERROR1056: Auxiliary configuration file %s missing or bad final\n",
			projectAuxConfigFileName);
	}
    }	
    /* for the final certificate in the chain, the subject is in the issuer's project's auxiliary
       configuration file - except for the last value.

       'top' are the top parameters, omitting the last value
    */
    if ((rc == 0) && *final) {
	rc = CertNames_GetTop(subjectCertNames,
			      SubjectStrings,
			      lineBuffer,
			      lineBufferLength,
			      projectAuxConfigFile,
			      projectAuxConfigFileName,
			      projectLogFile);
    }    
    /* for the final certificate, the subjectCommonName is the name of the certify project */
    /* FIXME this might change */
    if ((rc == 0) && *final) {
	rc = Malloc_Strcpy(&((*subjectCertNames)[(sizeof(CertNames) / sizeof(char *)) - 1]),
			   certify_project);
	if (rc != 0) {
	    File_Printf(projectLogFile, messageFile,
			"ERROR1057: Internal error at Malloc_Strcpy");
	}
    }
    /* get the parameters for the key to be certified, certify_project is specified by the end
       user */
    if (rc == 0) {
	rc = GetCertifyArgs(certifyKeyFileName,	/* freed by caller */
			    subjectCertNames,
			    *final,
			    certify_project,
			    lineBuffer,
			    lineBufferLength,
			    projectLogFile);
    }
    if (projectAuxConfigFile != NULL) {
	fclose(projectAuxConfigFile);		/* @1 */
    }
    if (certifyProjectAuxConfigFile != NULL) {
	fclose(certifyProjectAuxConfigFile );	/* @2 */
    }
    free(lineBuffer);				/* @3 */
    return rc;
}

/*  GetCertifyArgs() gets the parameters for the key to be certified.

    The key being certified always comes from the 'certify_project'.

    If this is not the final certificate in the chain, the subject is in the auxiliary configuration
    file (as the issuer) for the project key being certified.

    If this is the final certificate in the chain, the subject is in the auxiliary configuration
    file (as the subject) for the certifying key.  The final certificate in a chain certifies
    project signing keys.  These projects in general will not have an auxiliary configuration file
    with an issuer.  The exception is the final subjectCommonName, which today is the name of the
    certify_project.  FIXME This may change.

*/

int GetCertifyArgs(char 	**certifyKeyFileName,	/* freed by caller */
		   CertNames 	*subjectCertNames,
		   int  	final,
		   const char 	*certify_project,
		   char		*lineBuffer,
		   size_t	lineBufferLength,
		   FILE 	*projectLogFile)
{
    int rc = 0;
    
    const char 	*frameworkConfigFilename 	= NULL;
    FILE 	*frameworkConfigFile 		= NULL;		/* closed @1 */
    char 	*certifyProjectConfigFilename 	= NULL;		/* freed @2 */
    FILE 	*certifyProjectConfigFile 	= NULL;		/* closed @3 */
    char 	*certifyProjectAuxCfgFilename 	= NULL;		/* freed @5 */
    FILE 	*certifyProjectAuxCfgFile 	= NULL;		/* closed @6 */
   
    /* get the name of the framework configuration file */
    if (rc == 0) {
	frameworkConfigFilename = getenv("FRAMEWORK_CONFIG_FILE");
	if (frameworkConfigFilename == NULL) {
	    File_Printf(projectLogFile, messageFile,
			"ERROR1101: "
			"FRAMEWORK_CONFIG_FILE environment variable is not set\n");
	    rc = ERROR_CODE;
	}
    }
    /* open the framework configuration file */
    if (rc == 0) {
	if (verbose) fprintf(messageFile,
			     "Opening framework configuration file %s\n",
			     frameworkConfigFilename);
	frameworkConfigFile = fopen(frameworkConfigFilename, "r");	/* closed @1 */
	if (frameworkConfigFile == NULL) {
	    File_Printf(projectLogFile, messageFile,
			"ERROR1102: Cannot open framework configuration file %s, %s\n",
			frameworkConfigFilename, strerror(errno));
	    rc = ERROR_CODE;
	}
    }
    /* get certify (subject) project configuration file from framework configuration file */
    if (rc == 0) {
	rc = File_MapNameToValue(&certifyProjectConfigFilename,	/* freed @2 */
				 certify_project,		/* name to search for */
				 lineBuffer,			/* supplied buffer for lines */
				 lineBufferLength,		/* size of the line buffer */
				 frameworkConfigFile);		/* input file stream */
	if (rc != 0) {
	    File_Printf(projectLogFile, messageFile,
			"ERROR1103: Certify project %s missing, not found in %s\n",
			certify_project, frameworkConfigFilename);
	}
    }
    /* open project configuration file for the key to be certified */
    if (rc == 0) {
	if (verbose) fprintf(messageFile,
			     "Opening certify project configuration file %s\n",
			     certifyProjectConfigFilename);
	certifyProjectConfigFile = fopen(certifyProjectConfigFilename, "r");	/* closed @3 */
	if (certifyProjectConfigFile == NULL) {
	    File_Printf(projectLogFile, messageFile,
			"ERROR1104: Cannot open certify project configuration file %s, %s\n",
			certifyProjectConfigFilename, strerror(errno));
	    rc = ERROR_CODE;
	}
    }
    /* From the project configuration file for the key to be certified, get the certifyKeyFilename
       for the key to be certified */
    if (rc == 0) {
	rc = File_MapNameToValue(certifyKeyFileName, 		/* freed by caller */
				 "key",
				 lineBuffer,
				 lineBufferLength,
				 certifyProjectConfigFile);
	if (rc != 0) {
	    File_Printf(projectLogFile, messageFile,
			"ERROR1106: Cannot find key entry in certify project configuration file %s\n",
			certifyProjectConfigFilename);
	    rc = ERROR_CODE;
	}
    }
    if (rc == 0) {
	if (verbose) fprintf(messageFile,
			     "Certify project key file name: %s\n",
			     *certifyKeyFileName);
    }
    /* If this is not the final certificate in the chain, the subject comes from the issuer values
       in the auxCfgFilename for the key to be certified */
    if ((rc == 0) && !final) {
	rc = File_MapNameToValue(&certifyProjectAuxCfgFilename, /* freed @5 */
				 "auxcfg",
				 lineBuffer,
				 lineBufferLength,
				 certifyProjectConfigFile);
	if (rc != 0) {
	    File_Printf(projectLogFile, messageFile,
			"ERROR1107: Cannot find auxcfg entry in certify project configuration file %s\n",
			certifyProjectConfigFilename);
	    rc = ERROR_CODE;
	}
    }
    if ((rc == 0) && !final) {
	if (verbose) fprintf(messageFile,
			     "Certify project auxiliary configuration file name: %s\n",
			     certifyProjectAuxCfgFilename);
    }
    /* open the auxiliary project configuration file for the key to be certified */
    if ((rc == 0) && !final) {
	if (verbose) fprintf(messageFile,
			     "Opening certify project auxiliary configuration file %s\n",
			     certifyProjectAuxCfgFilename);
	certifyProjectAuxCfgFile = fopen(certifyProjectAuxCfgFilename, "r");	/* closed @6 */
	if (certifyProjectAuxCfgFile == NULL) {
	    File_Printf(projectLogFile, messageFile,
			"ERROR1105: Cannot open certify auxiliary configuration file %s, %s\n",
			certifyProjectAuxCfgFilename, strerror(errno));
	    rc = ERROR_CODE;
	}
    }

    /* the subject for this certificate is the issuer of the key to be certified */
    if ((rc == 0) && !final) {
	rc = CertNames_GetAll(subjectCertNames,
			      IssuerStrings,
			      lineBuffer,
			      lineBufferLength,
			      certifyProjectAuxCfgFile,
			      certifyProjectAuxCfgFilename,
			      projectLogFile);
    }
    /* close the framework configuration file */
    if (frameworkConfigFile != NULL) {
	fclose(frameworkConfigFile);		/* @1 */
    }
    free(certifyProjectConfigFilename);		/* @2 */
    if (certifyProjectConfigFile != NULL) {
	fclose(certifyProjectConfigFile);	/* @3 */
    }
    free(certifyProjectAuxCfgFilename);		/* @5 */
    if (certifyProjectAuxCfgFile != NULL) {
	fclose(certifyProjectAuxCfgFile);	/* @6 */
    }
    return rc;
}

/* CreateCert() forms an X509 certificate, but does not sign it.
 */

int CreateCert(X509 **x509Certificate,	/* X509 certificate to be generated, freed by caller */
	       unsigned char 		*nModulus,	/* key to be certified */
	       unsigned int 		nLength,
	       unsigned char 		*eExponent,
	       unsigned int 		eLength,
	       char			**issuerEntries,
	       size_t			issuerEntriesLength,
	       char 			**subjectEntries,
	       size_t 			subjectEntriesLength,
	       CertificateNameRow 	certificateNameTable[],
	       size_t 			certificateNameTableRows,
	       unsigned int 		validity,
	       int  			final,			/* bool, final certificate in the chain */
	       char 			*digestAlgorithm,
	       FILE 			*projectLogFile)
{
    int			rc = 0;
    int			irc = 0;

    /* allocate memory for the X509 structure */
    if (rc == 0) {
	*x509Certificate = X509_new();
	if (*x509Certificate == NULL) {
	    File_Printf(projectLogFile, messageFile,
			"ERROR1301 allocating memory for certificate\n");
	    rc = ERROR_CODE;
	}
    }
    /* fill in basic X509 information */
    if (rc == 0) {
	rc = Ossl_Cert_AddBasicInfo(*x509Certificate,
				    nLength, nModulus,
				    issuerEntriesLength,
				    issuerEntries,		/* certificate issuer */
				    subjectEntriesLength,
				    subjectEntries,
				    certificateNameTable,
				    certificateNameTableRows,
				    validity);
	if (rc != 0) {
	    File_Printf(projectLogFile, messageFile,
			"ERROR1302 adding basic information to certificate\n");
	}
    }
    if (rc == 0) {
	/* the last certificate in the chain certifies a project signing key.  That key cannot be a CA */
	if (final) {
	    if (rc == 0) {
		rc = Ossl_Cert_AddExtension(*x509Certificate, NID_basic_constraints, "critical,CA:FALSE");
	    }
	    if (rc == 0) {
		rc = Ossl_Cert_AddExtension(*x509Certificate, NID_key_usage, "critical,digitalSignature");
	    }
	}
	/* root and intermediate certificates can be CA's */
	else {
	    if (rc == 0) {
		rc = Ossl_Cert_AddExtension(*x509Certificate, NID_basic_constraints, "critical,CA:TRUE");
	    }
	    if (rc == 0) {
		rc = Ossl_Cert_AddExtension(*x509Certificate, NID_key_usage, "critical,keyCertSign");
	    }
	}
    }
    /* add the public key to be certified */
    if (rc == 0) {
	rc = Ossl_Cert_AddPublicKey(*x509Certificate,
				    nLength, nModulus,
				    eLength, eExponent);
	if (rc != 0) {
	    File_Printf(projectLogFile, messageFile,
			"ERROR1303 adding public key to certificate\n");
	}
    }
    /* attach the signature algorithm to the certificate */
    if (rc == 0) {
	rc = Ossl_Cert_AddSignatureAlgorithm(*x509Certificate, digestAlgorithm);
	if (rc != 0) {
	    File_Printf(projectLogFile, messageFile,
			"ERROR1304: Could not add signature algorithm to certificate\n");
	}
    }
    /* trace the certificate before signing  */
    if ((rc == 0) && verbose) {
	irc = X509_print_fp(messageFile, *x509Certificate);
	if (irc != 1) {
	    File_Printf(projectLogFile, messageFile,
		    "ERROR1305 in certificate print X509_print_fp()\n");
	    rc = ERROR_CODE;
	}
    }
    return rc;
}

/* CertNames_Init() initializes all members to NULL so the free is safe */

void CertNames_Init(CertNames *certNames)
{
    unsigned int i;
    
    for (i = 0 ; i < (sizeof(CertNames) / sizeof(char *)) ; i++) {
	(*certNames)[i] = NULL;
    }
    return;
}

/* CertNames_Delete() frees all members */

void CertNames_Delete(CertNames *certNames)
{
    unsigned int i;

    for (i = 0 ; i < (sizeof(CertNames) / sizeof(char *)) ; i++) {
	free((*certNames)[i]);
    }
    return;
}

/* CertNames_GetAll() gets all values in the certNames array from the auxiliary configuration
   file */

int CertNames_GetAll(CertNames 	*certNames,
		     const char *certStrings[],
		     char	*lineBuffer,
		     size_t	lineBufferLength,
		     FILE 	*projectAuxConfigFile,
		     const char *projectAuxConfigFileName,
		     FILE 	*projectLogFile)
{
    int rc = 0;
    unsigned int i;
   
    
    for (i = 0 ; (rc == 0) && i < (sizeof(CertNames) / sizeof(char *)) ; i++) {

	rc = File_MapNameToValue(&((*certNames)[i]),		/* freed by caller */
				 certStrings[i],	/* name to search for */
				 lineBuffer,		/* supplied buffer for lines */
				 lineBufferLength,	/* size of the line buffer */
				 projectAuxConfigFile);	/* input file stream */
	if (rc != 0) {
	    File_Printf(projectLogFile, messageFile,
			"ERROR1211: Auxiliary configuration file %s missing %s\n",
			projectAuxConfigFileName, certStrings[i]);
	}
    }
    return rc;
}

/* CertNames_GetTop() gets all but the last value in the certNames array from the auxiliary
   configuration file */

int CertNames_GetTop(CertNames 	*certNames,
		     const char *certStrings[],
		     char	*lineBuffer,
		     size_t	lineBufferLength,
		     FILE 	*projectAuxConfigFile,
		     const char *projectAuxConfigFileName,
		     FILE 	*projectLogFile)
{
    int rc = 0;
    unsigned int i;
    
    for (i = 0 ; (rc == 0) && i < ((sizeof(CertNames) / sizeof(char *)) - 1) ; i++) {

	rc = File_MapNameToValue(&((*certNames)[i]),	/* freed by caller */
				 certStrings[i],	/* name to search for */
				 lineBuffer,		/* supplied buffer for lines */
				 lineBufferLength,	/* size of the line buffer */
				 projectAuxConfigFile);	/* input file stream */
	if (rc != 0) {
	    File_Printf(projectLogFile, messageFile,
			"ERROR1212: Auxiliary configuration file %s missing %s\n",
			projectAuxConfigFileName, certStrings[i]);
	}
    }
    return rc;
}

#if 0
/* CertNames_GetLast() gets the last value in the certNames array from the auxiliary
   configuration file */

int CertNames_GetLast(CertNames  *certNames,
		      const char *certStrings[],
		      char	 *lineBuffer,
		      size_t	 lineBufferLength,
		      FILE 	 *projectAuxConfigFile,
		      const char *projectAuxConfigFileName,
		      FILE 	 *projectLogFile)
{
    int rc = 0;

    int i = (sizeof(CertNames) / sizeof(char *)) - 1;
    
    rc = File_MapNameToValue(&((*certNames)[i]),	/* freed by caller */
			     certStrings[i],		/* name to search for */
			     lineBuffer,		/* supplied buffer for lines */
			     lineBufferLength,		/* size of the line buffer */
			     projectAuxConfigFile);	/* input file stream */
    if (rc != 0) {
	File_Printf(projectLogFile, messageFile,
		    "ERROR1213: Auxiliary configuration file %s missing %s\n",
		    projectAuxConfigFileName, certStrings[i]);
    }
    return rc;
}	
#endif

void PrintUsage()
{
    fprintf(messageFile, "\n");
    fprintf(messageFile,
	    "sign_cert: Creates an X509 certificate for certify_project key and signs it using\n"
	    "the project signing key.\n"
	    "\n"
	    "Issuer values come from the project auxiliary configuration file\n"
	    "\n"
	    "Subject values come from the certify_project for all but the final certificate\n"
	    "For the final certificate, they come from the project auxiliary configuration file\n"
	    "except for the subjectCommonName\n"
	    "\n"
	    "\tsign_cert usage:\n"
	    "\n"
	    "Common arguments:\n"
	    "\n"
	    "\t-project          - project name (for the certifying key)\n"
	    "\t-certify_project  - project name (for the key to be certified)\n"
	    "\t-usr              - CCA user (profile) ID\n"
	    "\t[-v               - verbose logging]\n"
	    "\t[-h               - print usage help]\n"
	    "\n"
	    "Email only arguments:\n"
	    "\n"
	    "\t-epwd             - CCA user password (encrypted)\n"
	    "\n"
	    "Command line only arguments:\n"
	    "\n"
	    "\t-obody      - output email body file name (should be first argument)\n"
	    "\t-sender     - email sender\n"
	    "\t-do         - output attachment file name\n"
	    "\t-log        - project audit log file name\n"
	    "\t-auxcfg     - project auxiliary configuration file name\n"
	    "\t-key        - project CCA signing key token (certifying key) \n"
	    "\t-pwd        - CCA user password (plaintext)\n"
	    "\n"
	    );
    fprintf(messageFile, "\n");
    return;
}
