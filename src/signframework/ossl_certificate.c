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

/* FIXME add error codes */

#include <stdio.h>
#include <string.h>

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

#include "utils.h"
#include "debug.h"

#include "ossl_certificate.h"

/* The TPM OAEP encoding parameter */
static const unsigned char tpm_oaep_pad_str[] = { 'T', 'C', 'P', 'A' };

/* messages are traced here

   All messages, even error messages, are traced only if verbose is set.  There messages are
   'techie' and should not be returned unless the user asks for them.
*/

extern FILE* messageFile;
extern int verbose;

/* FIXME make the n and e names the same everywhere */



/* Ossl_Cert_Read() reads 'inputFileName' to an openssl X509 structure.
   
   The input file is DER (binary), not PEM.
*/

int Ossl_Cert_Read(X509 **x509Certificate,		/* output, freed by caller */
		   const char *inputFileName)
{
    int			rc = 0;
    int			irc = 0;
    unsigned char 	*certStream = NULL;		/* freed @1 */
    size_t		certStreamLength;
    unsigned char 	*tmpPtr;			/* because d2i_X509 moves the ptr */

    /* sanity check for memory leak */
    if (rc == 0) {
	if (*x509Certificate != NULL) {
	    if (verbose) fprintf(messageFile,
				 "Ossl_CertRead: X509 certificate not NULL at entry\n");
	    rc = ERROR_CODE;
	}	
    }
    /* read the DER file */
    if (rc == 0) {
	rc = File_ReadBinaryFile(&certStream,     	/* freed @1 */
				 &certStreamLength,
				 2000,			/* FIXME */
				 inputFileName);
    }
    /* convert from DER to X509 */
    if (rc == 0) {
	tmpPtr = certStream;
	*x509Certificate = d2i_X509(NULL,
				    (const unsigned char **)&tmpPtr, certStreamLength);
	if (*x509Certificate == NULL) {
	    if (verbose) fprintf(messageFile,
				 "Ossl_CertRead: Error in certificate deserialization d2i_X509()\n");
	    rc = ERROR_CODE;
	}
    }
    /* for debug */
    if ((rc == 0) && verbose) {
	irc = X509_print_fp(messageFile, *x509Certificate);
	if (irc != 1) {
	    if (verbose) fprintf(messageFile,
				 "Ossl_CertRead: Error in certificate print X509_print_fp()\n");
	    rc = ERROR_CODE;
	}
    }
    free(certStream);		/* @1 */
    return rc;
}

/* Ossl_Cert_Write() writes the X509 certificate to the file in DER format
   
 */

int Ossl_Cert_Write(const char *outputAttachmentFileName,
		    X509* platformCertificate)
{
    int			rc = 0;
    int			irc = 0;
    FILE		*outputAttachmentFile = NULL;	/* closed @1 */

    if (rc == 0) {
	rc = File_Open(&outputAttachmentFile,	/* closed @1 */
		       outputAttachmentFileName,
		       "wb");
    }
    /* convert X509 to DER and write */
    if (rc == 0) {
	irc = i2d_X509_fp(outputAttachmentFile, platformCertificate);
	if (irc != 1) {
	    if (verbose) fprintf(messageFile,
				 "Ossl_Cert_Write: Error in certificate i2d_X509_fp()\n");
	    rc = ERROR_CODE;
	}
    }
    if (outputAttachmentFile != NULL) {
	fclose(outputAttachmentFile);	/* @1 */
    }
    return rc;
}

/* Ossl_Cert_Create() creates the TCG certificate from the public key, issuer and subject lists, and
   hard coded TCG unique info.

   The TCG info should be table driven.
*/

int Ossl_Cert_Create(X509 **x509Certificate,	/* X509 certificate to be generated, freed by
						   caller */
		     unsigned char 	*nModulus,	/* key to be certified */
		     unsigned int 	nLength,
		     unsigned char 	*eExponent,
		     unsigned int 	eLength,
		     char		**issuerEntries,
		     size_t		issuerEntriesLength,
		     char 		**subjectEntries,
		     size_t 		subjectEntriesLength,
		     CertificateNameRow certificateNameTable[],
		     size_t 		certificateNameTableRows,
		     unsigned int 	validity)
{
    int			rc = 0;

    /* allocate memory for the X509 structure */
    if (rc == 0) {
	*x509Certificate = X509_new();
	if (*x509Certificate == NULL) {
	    if (verbose) fprintf(messageFile,
				 "Ossl_Cert_Create: Error allocating memory for certificate\n");
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
    }
    /* add the public key to be certified */
    if (rc == 0) {
	rc = Ossl_Cert_AddPublicKey(*x509Certificate,
				    nLength, nModulus,
				    eLength, eExponent);
    }
    /* add the TCG unique info */
    if (rc == 0) {
	rc = Ossl_Cert_AddUniqueInfoTCG(*x509Certificate);
    }
    return rc;
}

/* Add X509v3 extension at 'nid' of 'value'
 */

int Ossl_Cert_AddExtension(X509 *x509Certificate, int nid, char *value)
{
    int			rc = 0;			/* general return code */
    int			irc;
    X509_EXTENSION 	*extension = NULL;	/* freed @1 */

    /* create the extension, nid plus value */
    if (rc == 0) {
	extension = X509V3_EXT_conf_nid(NULL, NULL, nid, value);
	if (extension == NULL) {
	    if (verbose) fprintf(messageFile,
				 "Ossl_Cert_AddExtension: Error in X509V3_EXT_conf_nid\n");
	    rc = ERROR_CODE;
	}
    }
    /* append the extension */
    if (rc == 0) {
	irc = X509_add_ext(x509Certificate,	/* the certificate */
			   extension,		/* the extension to add */
			   -1);			/* location - append */
	if (irc != 1) {
	    if (verbose) fprintf(messageFile, "Ossl_Cert_AddExtension: Error in X509_add_ext\n");
	    rc = ERROR_CODE;
	}
    }
    /* cleanup */
    X509_EXTENSION_free(extension);	/* @1 */
    return rc;
}

/* Ossl_AddCertBasicInfo() fills in basic X509 information, such as:
   
   version
   serial number
   issuer
   validity
   subject
   
*/

#define SHA1_DIGEST_SIZE 20	/* FIXME */

int Ossl_Cert_AddBasicInfo(X509 *x509Certificate,	/* X509 certificate to be generated */
			   unsigned int nLength,
			   const unsigned char *nModulus,	/* key to be certified */
			   size_t issuerEntriesSize,
			   char **issuerEntries,		/* certificate issuer */
			   size_t subjectEntriesSize,
			   char **subjectEntries,		/* certificate subject */
			   CertificateNameRow certificateNameTable[],
			   size_t certificateNameTableRows,
			   unsigned int validity)
{
    int			rc = 0;			/* general return code */
    int			irc = 0;		/* integer return code */
    ASN1_TIME 		*arc = 0;		/* return code */
    ASN1_INTEGER 	*x509Serial;		/* certificate serial number in ASN1 */
    BIGNUM 		*x509SerialBN;		/* certificate serial number as a BIGNUM */
    unsigned char 	x509Serialbin[SHA1_DIGEST_SIZE]; /* certificate serial number in binary */
    X509_NAME 		*x509IssuerName;	/* composite issuer name, key/value pairs */
    X509_NAME 		*x509SubjectName;	/* composite subject name, key/value pairs */
  
    x509IssuerName = NULL;	/* freed @1 */
    x509SubjectName = NULL;	/* freed @2 */
    x509SerialBN = NULL;	/* freed @3 */ 
    
    if (verbose) fprintf(messageFile, "Ossl_Cert_AddBasicInfo: Adding basic certificate info\n");
    /* add certificate version X509 v3 */
    if (rc == 0) {
	if (verbose) fprintf(messageFile, "Ossl_Cert_AddBasicInfo: Adding version\n");
	irc = X509_set_version(x509Certificate, 2L);	/* value 2 == v3 */
	if (irc != 1) {
	    if (verbose) fprintf(messageFile, "Ossl_Cert_AddBasicInfo: Error in X509_set_version\n");
	    rc = ERROR_CODE;
	}
    }
    /*
      add certificate serial number
    */
    /* FIXME mix in the date and time so two certificates won't have the same serial number */
    if (rc == 0) {
	if (verbose) fprintf(messageFile,
			     "Ossl_Cert_AddBasicInfo: Adding certificate serial number\n");
	/* to create a unique serial number, hash the key to be certified */
	SHA1(nModulus, nLength, x509Serialbin);
	/* convert the SHA1 digest to a BIGNUM */
	x509SerialBN = BN_bin2bn(x509Serialbin, SHA1_DIGEST_SIZE, x509SerialBN);
	if (x509SerialBN == NULL) {
	    if (verbose) fprintf(messageFile,
				 "Ossl_Cert_AddBasicInfo: Error in serial number BN_bin2bn\n");
	    rc = ERROR_CODE;
	}
    }
    if (rc == 0) {
	/* get the serial number structure member, can't fail */
	x509Serial = X509_get_serialNumber(x509Certificate);
	/* convert the BIGNUM to ASN1 and add to X509 certificate */
	x509Serial = BN_to_ASN1_INTEGER(x509SerialBN, x509Serial);
	if (x509Serial == NULL) {
	    if (verbose) fprintf(messageFile,
				 "Ossl_Cert_AddBasicInfo: Error setting certificate serial number\n");
	    rc = ERROR_CODE;
	}
    }
    /* add issuer */
    if (rc == 0) {
	if (verbose) fprintf(messageFile, "Ossl_Cert_AddBasicInfo: Adding certificate issuer\n");
	rc = Ossl_CreateX509Name(&x509IssuerName,
				 issuerEntriesSize,
				 issuerEntries,
				 certificateNameTable,
				 certificateNameTableRows);
    }
    if (rc == 0) {
	irc = X509_set_issuer_name(x509Certificate, x509IssuerName);
	if (irc != 1) {
	    if (verbose) fprintf(messageFile,
				 "Ossl_Cert_AddBasicInfo: Error setting certificate issuer\n");
	    rc = ERROR_CODE;
	}
    }
    /* add validity */
    if (rc == 0) {
	if (verbose) fprintf(messageFile, "Ossl_Cert_AddBasicInfo: Adding certificate validity\n");
	/* can't fail, just returns a structure member */
	ASN1_TIME *notBefore = X509_get_notBefore(x509Certificate);
	arc = X509_gmtime_adj(notBefore ,0L);			/* set to today */
	if (arc == NULL) {
	    if (verbose) fprintf(messageFile,
				 "Ossl_Cert_AddBasicInfo: Error setting notBefore time\n");
	    rc = ERROR_CODE;
	}
    }
    if (rc == 0) {
	if (verbose) fprintf(messageFile, "Ossl_Cert_AddBasicInfo: Calculating duration\n");
	/* can't fail, just returns a structure member */
	ASN1_TIME *notAfter = X509_get_notAfter(x509Certificate);
	int days = (int)(((float)validity) * 365.25);
	/*  The standard pattern, getting a time_t, converting to a tm struct, adding years, and
	    converting back to time_t fails when compiling for 32-bit on a 64-bit machine.  The
	    32-bit signed time_t wraps in 2038.  In fact, the mktime fails with an error.
	    
	    It's true that the 365.25 is off by one day at times, but it's close enough.  A true
	    conversion from years to days is quite complicated and I don't feels the slight
	    inaccuracy is worth adding the code complexity.
	  
	    ASN1_TIME *X509_time_adj_ex(ASN1_TIME *s,
	    int offset_day, long offset_sec, time_t *in_tm)
	*/
	arc = X509_time_adj_ex(notAfter,
			       days,
			       0,
			       NULL);		/* set to duration */
	if (arc == NULL) {
	    if (verbose) fprintf(messageFile,
				 "Ossl_Cert_AddBasicInfo: Error setting notAfter time\n");
	    rc = ERROR_CODE;
	}
    }
    /* add subject */
    if (rc == 0) {
	if (verbose) fprintf(messageFile, "Ossl_Cert_AddBasicInfo: Adding certificate subject\n");
	rc = Ossl_CreateX509Name(&x509SubjectName,
				 subjectEntriesSize,
				 subjectEntries,
				 certificateNameTable,
				 certificateNameTableRows);
    }
    if (rc == 0) {
	irc = X509_set_subject_name(x509Certificate, x509SubjectName);
	if (irc != 1) {
	    if (verbose) fprintf(messageFile,
				 "Ossl_Cert_AddBasicInfo: Error setting certificate subject\n");
	    rc = ERROR_CODE;
	}
    }
    /* cleanup */
    X509_NAME_free(x509IssuerName);		/* @1 */
    X509_NAME_free(x509SubjectName);		/* @2 */
    BN_free(x509SerialBN);			/* @3 */
    return rc;
}

/* Ossl_Cert_AddSubjectAltNameTCG() adds hard coded TCG specific Subject Alternative Name items
 */

int Ossl_Cert_AddSubjectAltNameTCG(X509 *x509Certificate) /* X509 certificate to be generated */
{
    int			rc = 0;
    int			irc = 0;
    X509_NAME 		*extensionName;
    GENERAL_NAMES 	*subjectAltNames;
    GENERAL_NAME 	*subjectAltName;
 			       
    extensionName  = NULL;	/* freed @1 */
    subjectAltName = NULL;	/* freed @2 */
    subjectAltNames = NULL;	/* freed @3 */
    

    if (verbose) fprintf(messageFile,
			 "Ossl_Cert_AddSubjectAltNameTCG: Adding TCG Subject Alternative Name\n");
    /* add subject extensions */
    if (rc == 0) {
	extensionName = X509_NAME_new();
	if (extensionName == NULL) {
	    if (verbose) fprintf(messageFile,
				 "Ossl_Cert_AddSubjectAltNameTCG: Error in X509_NAME_new()\n");
	    rc = ERROR_CODE;
	}
    }
    /* add manufacturer ID by numerical ID */
    if (rc == 0) {
	irc = X509_NAME_add_entry_by_txt(extensionName,
					 "2.23.133.2.1", 	/* const char *field */
					 MBSTRING_ASC,		/* int type, character encoding */
					 (const unsigned char *)
					 "id:49424d00",	/* const unsigned char *bytes */
					 -1,			/* int len, use strlen(bytes) */
					 -1,			/* location - append */	
					 0);			/* set - not multivalued */
	if (irc == 0) {
	    if (verbose) fprintf(messageFile,
				 "Ossl_Cert_AddSubjectAltNameTCG: "
				 "Error adding manufacturer ID to certificate\n");
	    rc = ERROR_CODE;
	}
    }
    /* add machine class by numerical ID */
    if (rc == 0) {
	irc = X509_NAME_add_entry_by_txt(extensionName,
					 "2.23.133.2.2", 	/* const char *field */
					 MBSTRING_ASC,		/* int type, character encoding */
					 (const unsigned char *)
					 "IBMclass1",		/* const unsigned char *bytes */
					 -1,			/* int len, use strlen(bytes) */
					 -1,			/* location - append */	
					 0);			/* set - not multivalued */
	if (irc == 0) {
	    if (verbose) fprintf(messageFile,
				 "Ossl_Cert_AddSubjectAltNameTCG: "
				 "Error adding machine class to certificate\n");
	    rc = ERROR_CODE;
	}
    }
    /* add machine rev by numerical ID */
    if (rc == 0) {
	irc = X509_NAME_add_entry_by_txt(extensionName,
					 "2.23.133.2.3", 	/* const char *field */
					 MBSTRING_ASC,		/* int type, character encoding */
					 (const unsigned char *)
					 "id:IBMrev0",		/* const unsigned char *bytes */
					 -1,			/* int len, use strlen(bytes) */
					 -1,			/* location - append */	
					 0);			/* set - not multivalued */
	if (irc == 0) {
	    if (verbose) fprintf(messageFile,
				 "Ossl_Cert_AddSubjectAltNameTCG: "
				 "Error adding machine rev to certificate\n");
	    rc = ERROR_CODE;
	}
    }
    if (rc == 0) {
	subjectAltName = GENERAL_NAME_new();		/* freed @5 */
	if (subjectAltName == NULL) {
	    if (verbose) fprintf(messageFile,
				 "Ossl_Cert_AddSubjectAltNameTCG: "
				 "Error adding subjectAltName to certificate\n");
	    rc = ERROR_CODE;
	}
    }
    if (rc == 0) {
	subjectAltNames = GENERAL_NAMES_new();		/* freed @6 */
	if (subjectAltNames == NULL) {
	    if (verbose) fprintf(messageFile,
				 "Ossl_Cert_AddSubjectAltNameTCG: "
				 "Error adding subjectAltNames to certificate\n");
	    rc = ERROR_CODE;
	}
    }
    /* add extensions to general names structure */
    if (rc == 0) {
	subjectAltName->type = GEN_DIRNAME;	/* specify the type of union */
	subjectAltName->d.dirn = extensionName;
	irc = sk_GENERAL_NAME_push(subjectAltNames, subjectAltName);
	if (irc == 0) {
	    if (verbose) fprintf(messageFile,
				 "Ossl_Cert_AddSubjectAltNameTCG: "
				 "Error adding extension sto general names \n");
	    rc = ERROR_CODE;
	}
	else {
	    subjectAltName = NULL;
	}
    }
    /* add subjectAltNames general names extension structure to certificate */
    if (rc == 0) {
	irc = X509_add1_ext_i2d(x509Certificate,	/* certificate */
				NID_subject_alt_name, 	/* nid */
				subjectAltNames,	/* void * value */
				1,			/* crit */
				0); 			/* flags */
	if (irc == 0) {
	    fprintf(messageFile,
		    "Ossl_Cert_AddSubjectAltNameTCG: Error adding subjectAltNames to certificate\n");
	    rc = ERROR_CODE;
	}
	else {
	    subjectAltNames = NULL;
	}
    }
    /* cleanup */
    X509_NAME_free(extensionName);		/* @1 */
    GENERAL_NAME_free(subjectAltName);		/* @2 */
    GENERAL_NAMES_free(subjectAltNames);	/* @3 */
    return rc;
}

/* Ossl_Cert_AddUniqueInfo() adds TCG certificate optional information.

   FIXME This should likely be factored further into TCG and other info, or make the entire function
   table driven
*/

int Ossl_Cert_AddUniqueInfoTCG(X509 *x509Certificate)	/* X509 certificate to be generated */
{
    int			rc = 0;

    /* add subject extensions */
    if (rc == 0) {
	rc =  Ossl_Cert_AddSubjectAltNameTCG(x509Certificate);
    }
    /* add other extensions */
    if (rc == 0) {
	rc = Ossl_Cert_AddExtension(x509Certificate, NID_basic_constraints, "critical,CA:FALSE");
    }
    if (rc == 0) {
	rc = Ossl_Cert_AddExtension(x509Certificate, NID_ext_key_usage, "critical,2.23.133.8.1");
    }
    return rc;
}

/* Ossl_AddCertPublicKey() adds the public key (the key to be certified) to the openssl X509
   certificate

*/

int Ossl_Cert_AddPublicKey(X509 *x509Certificate,
			   unsigned int nLength,
			   unsigned char *nBytes,	/* key to be certified */
			   unsigned int eLength,
			   unsigned char *eBytes)
{
    long		rc = 0;		/* general return code */
    int			irc;		/* integer return code */

    /* public key to be certified */
    RSA 	  	*rsaPubKey;		/* OpenSSL key token */
    EVP_PKEY 		*evpPubkey;		/* EVP format */

    evpPubkey = NULL;		/* freed @1 */
    rsaPubKey = NULL;		/* freed @2 */
    
    if (verbose) fprintf(messageFile, "Ossl_Cert_AddPublicKey: Adding certificate public key\n");
    /* convert from TPM keydata format to openSSL RSA type */
    if (rc == 0) {
	rc = Ossl_Array_to_RSA(&rsaPubKey,
			       nBytes, nLength,
			       eBytes, eLength);
    }
    /* convert from OpenSSL RSA to EVP_PKEY type */
    if (rc == 0) {
	evpPubkey = EVP_PKEY_new();
	if (evpPubkey == NULL) {
	    if (verbose)
		fprintf(messageFile,
			"Ossl_Cert_AddPublicKey: "
			"Error: Cannot allocate EVP public key format key\n");
	    rc = ERROR_CODE;
	}
    }
    if (rc == 0) {
	irc = EVP_PKEY_assign_RSA(evpPubkey, rsaPubKey);
	if (irc != 1) {
	    if (verbose)
		fprintf(messageFile,
			"Ossl_Cert_AddPublicKey: "
			"Error: Cannot convert public key from RSA to EVP format\n");
	    rc = ERROR_CODE;
	}
    }
    /* add the public key to the certificate */
    if (rc == 0) {
	irc = X509_set_pubkey(x509Certificate, evpPubkey);
	if (irc != 1) {
	    if (verbose) fprintf(messageFile,
				 "Ossl_Cert_AddPublicKey: "
				 "Error: Cannot add public key to certificate\n");
	    rc = ERROR_CODE;
	}
    }
    /* cleanup */
    if (evpPubkey != NULL) {
	EVP_PKEY_free(evpPubkey);	/* @1 */
	rsaPubKey = NULL;	/* I think freeing the EVP object implicitly frees the RSA object */
    }
    if (rsaPubKey != NULL) {
	RSA_free(rsaPubKey);		/* @2 */	
    }
    return rc;
}

/* Ossl_Cert_AddSignature() adds the signature and signature algorithm to the certificate

   NOTE Currently hard coded to RSA
*/

int Ossl_Cert_AddSignatureAlgorithm(X509 *x509Certificate,
				    const char *digestAlgorithm)
{
    int		rc = 0;		/* general return code */
    int		nid;
    
    /* X509:
       X509_CINF *cert_info;
       X509_ALGOR *sig_alg;
       ASN1_BIT_STRING *signature;
    */
    /* X509_CINF:
       ASN1_INTEGER *version;
       ASN1_INTEGER *serialNumber;
       X509_ALGOR *signature;
       X509_NAME *issuer;
       X509_VAL *validity;
       X509_NAME *subject;
       X509_PUBKEY *key;
       etc.
    */

    /* set the X509 signature algorithm in two places */
    if (rc == 0) {
	if (strcmp(digestAlgorithm, "SHA-1") == 0) {
	    nid = NID_sha1WithRSAEncryption;
	}
	else if (strcmp(digestAlgorithm, "SHA-256") == 0) {
	    nid = NID_sha256WithRSAEncryption;
	}
	else {
	    if (verbose)
		fprintf(messageFile,
			"Ossl_Cert_AddSignatureAlgorithm: Digest algorithm %s not supported\n",
				 digestAlgorithm);
	    rc = ERROR_CODE;
	}
    }
   if (rc == 0) {
	if (verbose) fprintf(messageFile,
			     "Ossl_Cert_AddSignatureAlgorithm: Adding signature algorithm\n");
	x509Certificate->cert_info->signature->parameter = ASN1_TYPE_new();
	if (x509Certificate->cert_info->signature->parameter == NULL) {
	    fprintf(messageFile,
		    "Ossl_Cert_AddSignatureAlgorithm: Error allocating signature algorithm\n");
	    rc = ERROR_CODE;
	}
    }
    if (rc == 0) {
	x509Certificate->cert_info->signature->parameter->type = V_ASN1_NULL;
	x509Certificate->cert_info->signature->algorithm = OBJ_nid2obj(nid);
	if (x509Certificate->cert_info->signature->algorithm == NULL) {
	    fprintf(messageFile,
		    "Ossl_Cert_AddSignatureAlgorithm: Error getting signature algorithm nid\n");
	    rc = ERROR_CODE;
	}
    }
    if (rc == 0) {
	x509Certificate->sig_alg->parameter = ASN1_TYPE_new();
	if (x509Certificate->sig_alg->parameter == NULL) {
	    fprintf(messageFile,
		    "Ossl_Cert_AddSignatureAlgorithm: Error allocating signature algorithm\n");
	    rc = ERROR_CODE;
	}
    }
    if (rc == 0) {
	x509Certificate->sig_alg->parameter->type = V_ASN1_NULL;
	x509Certificate->sig_alg->algorithm = OBJ_nid2obj(nid);
	if (x509Certificate->sig_alg->algorithm == NULL) {
	    fprintf(messageFile,
		    "Ossl_Cert_AddSignatureAlgorithm: Error getting signature algorithm nid\n");
	    rc = ERROR_CODE;
	}
    }
    return rc;
}

/* Ossl_Cert_AddSignature() adds the signature and signature algorithm to the certificate

   NOTE Currently hard coded to RSA
*/

void Ossl_Cert_AddSignature(X509 	*x509Certificate,	/* certificate to add signature */
			    unsigned char	*signature,	/* signature to be added */
			    unsigned long	signatureLength)
{
    
    /* add the signature to the certificate */
    if (verbose) fprintf(messageFile,
			 "Ossl_Cert_AddSignature: Adding signature to certificate\n");
    x509Certificate->signature->data = signature;
    x509Certificate->signature->length = signatureLength;
    return;
}

/* FIXME fix lengths */

int Ossl_Cert_GetDigest(unsigned char **digest,		/* digest plus OID, freed by caller */
			unsigned int *digestLength,	/* just the digest */
			unsigned int *oidDigestLength,	/* length of digest plus OID */
			const char *digestAlgorithm,
			X509 *x509Certificate)
{
    int		rc = 0;			/* general return code */
    int 	irc = 0;

    /* http://tools.ietf.org/html/draft-ietf-smime-sha2-11 */
    
    /* SHA-1 with RSA OID (Object Identifier) */
    static const unsigned char sha1_rsa_oid[] = {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E,
						 0x03, 0x02, 0x1A, 0x05, 0x00, 0x04, 0x14};
    /* SHA-256 with RSA OID (Object Identifier) */
    static const unsigned char sha256_rsa_oid[] = {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
						   0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
						   0x00, 0x04, 0x20};
    
#if 0	/* future use */
    /* SHA-512 with RSA OID (Object Identifier) */
    static const unsigned char sha512_rsa_oid[] = {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
						   0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
						   0x00, 0x04, 0x40};
#endif
    /* int X509_digest(const X509 *data,
		    const EVP_MD *type,
		    unsigned char *md,
		    unsigned int *len)
    */

    const unsigned char *oid;				/* object identifier */
    unsigned int	oidSize;			/* size of object identifier */
    const EVP_MD	*digestType = NULL;		/* signature digest algorithm */

    /* set the signature digest algorithm */
    if (rc == 0) {
	if (strcmp(digestAlgorithm, "SHA-1") == 0) {
	    oid = sha1_rsa_oid;
	    oidSize = sizeof(sha1_rsa_oid);
	    *digestLength = SHA1_SIZE;
	    *oidDigestLength = sizeof(sha1_rsa_oid) + SHA1_SIZE;
	    digestType = EVP_sha1();	/* hash function */
	}
	else if (strcmp(digestAlgorithm, "SHA-256") == 0) {
	    oid = sha256_rsa_oid;
	    oidSize = sizeof(sha256_rsa_oid);
	    *digestLength = SHA256_SIZE;
	    *oidDigestLength = sizeof(sha256_rsa_oid) + SHA256_SIZE;
	    digestType = EVP_sha256();	/* hash function */
	}
	else {
	    if (verbose) fprintf(messageFile,
				 "Ossl_Cert_GetDigest: Digest algorithm %s not supported\n",
				 digestAlgorithm);
	    rc = ERROR_CODE;
	}
    }
    if (rc == 0) {
	rc = Malloc_Safe(digest,	/* freed by caller */
			 *oidDigestLength,
			 *oidDigestLength);
    }
    /* prepend OID */
    if (rc == 0) {
	if (verbose) fprintf(messageFile,
			     "Ossl_Cert_GetDigest: Prepending OID, length %u\n", oidSize);
	memcpy(*digest, oid, oidSize);
    }
    unsigned int tmpDigestLength;
    if (rc == 0) {
	irc = ASN1_item_digest(ASN1_ITEM_rptr(X509_CINF),	/* type */
			       digestType,			/* digest algorithm */
			       x509Certificate->cert_info,	/* ASN1 to digest */
			       (*digest) + oidSize,		/* digest result */
			       &tmpDigestLength);		/* digest length result */
	if (irc != 1) {
	    if (verbose) fprintf(messageFile,
				 "Ossl_Cert_GetDigestError: Error digesting certificate\n");
	    rc = ERROR_CODE;
	}
    }    
    /* sanity check length returned FIXME */
    if (rc == 0) {
    }
    if (rc == 0) {
	if (verbose) PrintAll(messageFile,
			      "Ossl_Cert_GetDigest: Certificate digest",
			      *digestLength, *digest + *oidDigestLength - *digestLength);
    }
    return rc;
}


/*  Ossl_SignCertificate() uses the openSSL signing key to sign the X509 certificate
 */	

int Ossl_Cert_Sign(X509 *x509Certificate,		/* certificate to be signed */
		   const char *digestAlgorithm,
		   const char *keyFileName,		/* signing key */
		   const char *keyPassword)		/* signing key password */
{
    int			rc = 0;		/* general return code */
    int			irc;		/* integer return code */

    /* signing key */
    RSA 	  	*rsaSignKey;		/* OpenSSL key token */
    const EVP_MD	*digest = NULL;		/* signature digest algorithm */
    EVP_PKEY 		*evpSignkey;		/* EVP format */

    evpSignkey = NULL;		/* freed @1 */
    rsaSignKey = NULL;		/* freed @2 */

    if (verbose) fprintf(messageFile, "Ossl_Cert_Sign: Add certificate signature\n");
    /* convert root CA signing key from .pem to openSSL RSA type */
    if (rc == 0) {
	if (verbose) fprintf(messageFile,
			     "Ossl_Cert_Sign: Reading signing key from file %s\n",
			     keyFileName);
	rc = Ossl_ReadKey(&rsaSignKey,			/* freed @2 */
			  keyFileName,			/* signing key */
			  keyPassword);			/* signing key password */
    }
    /* convert root CA signing key from OpenSSL RSA to EVP_PKEY type */
    if (rc == 0) {
	evpSignkey = EVP_PKEY_new();
	if (evpSignkey == NULL) {
	    if (verbose) fprintf(messageFile,
				 ": Error allocating EVP format signing key\n");
	    rc = ERROR_CODE;
	}
    }
    if (rc == 0) {
	if (verbose) fprintf(messageFile, "Ossl_Cert_Sign: Converting signing key\n");
	irc = EVP_PKEY_assign_RSA(evpSignkey, rsaSignKey);
	if (irc != 1) {
	    if (verbose) fprintf(messageFile,
				 "Ossl_Cert_Sign: "
				 "Error converting signing key from RSA to EVP format\n");
	    rc = ERROR_CODE;
	}
    }
    /* set the signature digest algorithm */
    if (rc == 0) {
	if (strcmp(digestAlgorithm, "SHA-1") == 0) {
	    digest = EVP_sha1();	/* no error return */
	}
	else if (strcmp(digestAlgorithm, "SHA-256") == 0) {
	    digest = EVP_sha256();	/* no error return */
	}
    }
    /* sign the certificate with the root CA signing key */
    if (rc == 0) {
	if (verbose) fprintf(messageFile, "Ossl_Cert_Sign: Signing the certificate\n");
	irc = X509_sign(x509Certificate, evpSignkey, digest);
	if (irc == 0) {	/* returns signature size, 0 on error */
	    if (verbose) printf("Ossl_Cert_Sign: Error signing certificate\n");
	    rc = ERROR_CODE;
	}
    }
    /* verify the signature */
    if (rc == 0) {
	if (verbose) fprintf(messageFile, "Ossl_Cert_Sign: Verifying the certificate\n");
	irc = X509_verify(x509Certificate, evpSignkey);
	if (irc != 1) {
	    if (verbose) fprintf(messageFile, "Ossl_Cert_Sign: Error verifying certificate\n");
	    rc = ERROR_CODE;
	}
    }
    /* cleanup */
    if (evpSignkey != NULL) {
	EVP_PKEY_free(evpSignkey);	/* @1 */
	rsaSignKey = NULL;	/* I think freeing the EVP object implicitly frees the RSA object */
    }
    if (rsaSignKey != NULL) {
	RSA_free(rsaSignKey);		/* @2 */	
    }
    return rc;
}


/* Ossl_CreateX509Name() create an X509 name (issuer or subject) from a pointer to issuer or subject
   entries

*/
/* FIXME needs range check */

int Ossl_CreateX509Name(X509_NAME **x509Name,
			size_t entriesSize,
			char **entries,
			CertificateNameRow certificateNameTable[],
			size_t certificateNameTableRows)
{
    long	rc = 0;		/* general return code */
    int		irc;		/* integer return code */
    size_t  	i;
    X509_NAME_ENTRY 	*nameEntry;			/* single field of the name */

    nameEntry = NULL;
    certificateNameTableRows = certificateNameTableRows;/* FIXME needs range check */
    
    if (rc == 0) {
	*x509Name = X509_NAME_new();
	if (*x509Name == NULL) {
	    if (verbose) fprintf(messageFile, "Ossl_CreateX509Name: Error in X509_NAME_new()\n");
	    rc = ERROR_CODE;
	}
    }
    for (i=0 ; (i < entriesSize) && (rc == 0) ; i++) {
	if (rc == 0) {
	    nameEntry =
		X509_NAME_ENTRY_create_by_NID(NULL,		/* caller creates object */
					      certificateNameTable[i].nid,
					      MBSTRING_ASC,	/* character encoding */
					      (unsigned char *)entries[i],	/* to add */
					      -1);		/* length, -1 is C string */

	    if (nameEntry == NULL) {
		if (verbose) fprintf(messageFile,
			"Ossl_CreateX509Name: Error creating entry for %s\n",
			certificateNameTable[i].key);
		rc = ERROR_CODE;
	    }
	}
	if (rc == 0) {
	    irc = X509_NAME_add_entry(*x509Name,	/* add to issuer */
				      nameEntry,	/* add the entry */
				      -1,		/* location - append */	
				      0);		/* set - not multivalued */
	    if (irc != 1) {
		if (verbose) fprintf(messageFile,
			"Ossl_CreateX509Name: Error adding entry for %s\n",
			certificateNameTable[i].key);
		rc = ERROR_CODE;
	    }
	}
	X509_NAME_ENTRY_free(nameEntry);	/* callee checks for NULL */
	nameEntry = NULL;
    }
    return rc;
}

/* Ossl_Cert_GetParameters() extracts the public key from an X509 certificate.
   
   If needExtensions is TRUE, TCG extensions must be present and are also returned.
*/

int Ossl_Cert_GetParameters(X509 		*x509Certificate,
			    unsigned char 	**modulus,	/* freed by caller */
			    unsigned int 	*nLength,
			    unsigned char 	**exponent,	/* freed by caller */
			    unsigned int 	*eLength,
			    int 		needExtensions)
{
    int			rc = 0;

    /* FIXME return these */
    char 		*commonName = NULL;		/* freed by caller */
    char 		*organizationName = NULL;	/* freed by caller */
    char 		*countryName = NULL;		/* freed by caller */
    ASN1_TIME  		*notBefore;
    ASN1_TIME  		*notAfter;
    char 		*partNumber = NULL;		/* OPENSSL_free() by caller */

    char 		*firwareRevision = NULL;	/* OPENSSL_free() by caller */
    unsigned char 	*binSerialNumber = NULL;	/* freed by caller */
    unsigned int 	binSerialNumberBytes;

    /* get serial number */
    if (rc == 0) {
	rc = Ossl_Cert_GetSerialNumber(&binSerialNumber, &binSerialNumberBytes,
				       x509Certificate);
    }
    if (rc == 0) {
	if (verbose) PrintAll(messageFile, "Ossl_Cert_GetParameters: Serial Number",
			      binSerialNumberBytes, binSerialNumber);
    }
    /* get issuer CN */
    if (rc == 0) {
	rc = Ossl_Cert_GetIssuerName(&commonName,		/* freed by caller */
				     NID_commonName,
				     x509Certificate);
	if (verbose) fprintf(messageFile,
			     "Ossl_Cert_GetParameters: Issuer CN: %s\n",
			     commonName);
    }
    /* get issuer O */
    if (rc == 0) {
	rc = Ossl_Cert_GetIssuerName(&organizationName,		/* freed by caller */
				     NID_organizationName,
				     x509Certificate);
	if (verbose) fprintf(messageFile,
			     "Ossl_Cert_GetParameters: Issuer O: %s\n",
			     organizationName);
    }
    /* get issuer DN */
    if (rc == 0) {
	rc = Ossl_Cert_GetIssuerName(&countryName ,		/* freed by caller */
				     NID_countryName,
				     x509Certificate);
	if (verbose) fprintf(messageFile,
			     "Ossl_Cert_GetParameters: Issuer C: %s\n",
			     countryName);
    }
    /* FIXME factor */
    /* get validity before */
    if (rc == 0) {
	notBefore = X509_get_notBefore(x509Certificate);
	/* two digit year */
	if (notBefore ->type == V_ASN1_UTCTIME) {
	    if (verbose) fprintf(messageFile,
				 "Ossl_Cert_GetParameters: notBefore: YY\n");
	}
	/* four digit year */
	else if (notBefore->type == V_ASN1_GENERALIZEDTIME) {
	    if (verbose) fprintf(messageFile,
				 "Ossl_Cert_GetParameters: notBefore: YYYY\n");
	}	    
	if (verbose) fprintf(messageFile,
			     "Ossl_Cert_GetParameters: notBefore: %s\n",
			     notBefore->data);
    }
    /* get validity after */
    if (rc == 0) {
	notAfter = X509_get_notAfter(x509Certificate);
	/* two digit year */
	if (notAfter ->type == V_ASN1_UTCTIME) {
	    if (verbose) fprintf(messageFile,
				 "Ossl_Cert_GetParameters: notAfter: YY\n");
	}
	/* four digit year */
	else if (notAfter->type == V_ASN1_GENERALIZEDTIME) {
	    if (verbose) fprintf(messageFile,
				 "Ossl_Cert_GetParameters: notAfter: YYYY\n");
	}	    
	if (verbose) fprintf(messageFile,
			     "Ossl_Cert_GetParameters: notAfter: %s\n",
			     notAfter->data);
    }
    /* get public modulus and exponent */
    if (rc == 0) {
	rc = Ossl_Cert_GetPublicKey(modulus, nLength,	/* freed by caller */
				    exponent, eLength,	/* freed by caller */
				    x509Certificate);
    }
    if (rc == 0) {
	if (verbose) PrintAll(messageFile, "Ossl_Cert_GetParameters: public modulus",
			      *nLength, *modulus);
	if (verbose) PrintAll(messageFile, "Ossl_Cert_GetParameters: public exponent",
			      *eLength, *exponent);
    }
    /* get subject alt name */
    if ((rc == 0) && needExtensions) {
	rc = Ossl_Cert_GetExtensions(&partNumber,
				     &firwareRevision,
				     x509Certificate);
    }
    if ((rc == 0) && needExtensions) {
	if (verbose) fprintf(messageFile,
			     "Ossl_Cert_GetParameters: part number %s\n",
			     partNumber);
	if (verbose) fprintf(messageFile,
			     "Ossl_Cert_GetParameters: firmware revision %s\n",
			     firwareRevision);
    }
    return rc;
}

int Ossl_Cert_GetSerialNumber(unsigned char 	**binSerialNumber,	/* freed by caller */
			      unsigned int 	*binSerialNumberBytes,
			      X509 		*x509Certificate)
{
    int			rc = 0;
    ASN1_INTEGER 	*asn1SerialNumber;
    BIGNUM		*bnSerialNumber;

    if (rc == 0) {
	asn1SerialNumber = X509_get_serialNumber(x509Certificate);
	if (asn1SerialNumber == NULL) {
	    if (verbose) fprintf(messageFile,
				 "Ossl_Cert_GetSerialNumber: "
				 "Error in certificate, cannot get serial number\n");
	    rc = ERROR_CODE;
	}
    }
    if (rc == 0) {
	bnSerialNumber = ASN1_INTEGER_to_BN(asn1SerialNumber, NULL);
	if (bnSerialNumber == NULL) {
	    if (verbose) fprintf(messageFile,
				 "Ossl_Cert_GetSerialNumber: "
				 "Error in certificate, cannot get serial number\n");
	    rc = ERROR_CODE;
	}
    }
    if (rc == 0) {
	rc = Ossl_Convertbn2binMalloc(binSerialNumber,	/* freed by caller */
				      binSerialNumberBytes,
				      bnSerialNumber,
				      0);
    }
    return rc;
    
}

int Ossl_Cert_GetIssuerName(char **name,		/* freed by caller */
			    int nid,			/* nid indicates which part of name to get */
			    X509 *x509Certificate)
{
    int		rc = 0;
    X509_NAME 	*x509Name = NULL;
    
    if (rc == 0) {
	x509Name =  X509_get_issuer_name(x509Certificate);
	if (x509Name == NULL) {
	    if (verbose) fprintf(messageFile,
				 "Ossl_Cert_GetIssuerName: "
				 "Error in certificate, cannot get issuer\n");
	    rc = ERROR_CODE;
	}
    }
    if (rc == 0) {
	rc = Ossl_X509_NAME_get_text_by_NID_Malloc(name,		/* freed by caller */
						   nid,
						   x509Name);
    }
    return rc;
}

int Ossl_Cert_GetPublicKey(unsigned char **modulus,	/* freed by caller */
			   unsigned int *nBytes,
			   unsigned char **exponent,	/* freed by caller */
			   unsigned int *eBytes,
			   X509 *x509Certificate)
{
    int 		rc = 0;
    EVP_PKEY 		*pkey = NULL;
    RSA 		*rsa = NULL;
    
    if (rc == 0) {
	pkey = X509_get_pubkey(x509Certificate);
	if (pkey == NULL) {
	    if (verbose) fprintf(messageFile,
				 "Ossl_Cert_GetPublicKey: "
				 "Error, Cannot get certificate public key\n");
	    rc = ERROR_CODE;
	}
    }
    if (rc == 0) {
	rsa = EVP_PKEY_get1_RSA(pkey);
	if (rsa == NULL) {
	    if (verbose) fprintf(messageFile,
				 "Ossl_Cert_GetPublicKey: "
				 "Error: Cannot extract certificate RSA public key\n");
	    rc = ERROR_CODE;
	}
    }
    if (rc == 0) {
	rc = Ossl_Convertbn2binMalloc(modulus,	/* freed by caller */
				      nBytes,
				      rsa->n,
				      0);		/* padBytes */
    }
    if (rc == 0) {
	rc = Ossl_Convertbn2binMalloc(exponent,	/* freed by caller */
				      eBytes,
				      rsa->e,
				      0);		/* padBytes */
    }
    RSA_free(rsa);
    /* FIXME free the pkey? */
    return rc;
}

int Ossl_Cert_GetExtensions(char 	**partNumber,	   /* must be OPENSSL_free() by caller */
			    char 	**firwareRevision, /* must be OPENSSL_free() by caller */
			    X509 	*ekX509Certificate)
{
    int			rc = 0;
    int i;

#if 1	/* for debug only */
    STACK_OF(X509_EXTENSION) *exts;
    int numExtensions;
    
    if (rc == 0) {
	exts = ekX509Certificate->cert_info->extensions;

	numExtensions = sk_X509_EXTENSION_num(exts);
	if (verbose) fprintf(messageFile, "Ossl_Cert_GetExtensions number of extensions %d\n\n",
			     numExtensions);
	if (numExtensions  <= 0) {
	    rc = ERROR_CODE;
	}
    }
    for (i = 0 ; (i < numExtensions) && (rc == 0) ; i++) {
	X509_EXTENSION *ex;
	ASN1_OBJECT *obj;
	char textValue[512];

	ex = sk_X509_EXTENSION_value(exts, i);
	obj = X509_EXTENSION_get_object(ex);
	int nid = OBJ_obj2nid(obj);
	if (verbose) fprintf(messageFile, "Ossl_Cert_GetExtensions extension %d nid %d\n",
			     i + 1,
			     nid);
	const char *sn = OBJ_nid2sn(nid);
	const char *ln = OBJ_nid2ln(nid);
	if (verbose) fprintf(messageFile,
			     "nid %d %s %s\n", nid, sn, ln);
	OBJ_obj2txt(textValue, sizeof(textValue), obj, 1);
	if (verbose) fprintf(messageFile,
			     "OID %s\n",textValue );

	OBJ_obj2txt(textValue, sizeof(textValue), obj, 0);
	if (verbose) fprintf(messageFile,
			     "OID name %s\n\n",textValue );
    }
#endif
    GENERAL_NAMES *subjectAltNames;
    if (rc == 0) {
	// there is alternative code on page 136 of O'Reilly OpenSSL

	/* get  Subject Alternative Name */
	subjectAltNames = (GENERAL_NAMES*) X509_get_ext_d2i(ekX509Certificate,
							    NID_subject_alt_name, NULL, NULL);
	if (subjectAltNames == NULL) {
	    if (verbose)
		fprintf(messageFile,
			"Ossl_Cert_GetExtensions: "
			"Cannot get Subject Alternative Name from certificate\n");
	    rc = ERROR_CODE;
	}
    }
    int numberOfAlts;
    /* get number of names. Supposed to be at least one, but don't count on it */
    if (rc == 0) {
	numberOfAlts = sk_GENERAL_NAME_num (subjectAltNames);
	if (0) fprintf(messageFile, "Number of subject alternative names %d \n", numberOfAlts);
    }
    /* loop through all of the alternate names */
    for ( i = 0; (rc == 0) && (i < numberOfAlts) ; i++) {
	/* get an alternative name */
	const GENERAL_NAME *pName = sk_GENERAL_NAME_value (subjectAltNames, i);
	if (pName->type == GEN_DIRNAME) {
	    X509_NAME *directoryName = (X509_NAME *)pName->d.dirn;
	    if (0) fprintf(messageFile, "subject alternative name %u \n", i + 1);
	    if (0) X509_NAME_print_ex_fp(messageFile, directoryName, 0, XN_FLAG_ONELINE);
	    if (0) fprintf(messageFile, "\n\n");

	    int entryCount = X509_NAME_entry_count(directoryName );
	    if (0) fprintf(messageFile, "entries in this name %u\n", entryCount );

	    for (i = 0 ; (rc == 0) && (i < entryCount) ; i++) {
		char asn1Object[256];
		unsigned char *asn1ObjectValue = NULL;
		X509_NAME_ENTRY *ent = X509_NAME_get_entry(directoryName, i);
		/* get the name, the OID */
		if (rc == 0) {
		    ASN1_OBJECT *fn = X509_NAME_ENTRY_get_object(ent);
		    OBJ_obj2txt(asn1Object, sizeof asn1Object, fn,
				1);	/* alway use numeric form */
		    if (rc != 0) {
			if (verbose) fprintf(messageFile,
					     "Ossl_Cert_GetExtensions: "
					     "Cannot get allocate memory for certificate field\n");
			rc = ERROR_CODE;
		    }
		}
		/* get the value, the text associated with the OID name */
		if (rc == 0) {
		    ASN1_STRING *val = X509_NAME_ENTRY_get_data(ent);	/* ASN1_STRING */
		    int length = ASN1_STRING_to_UTF8(&asn1ObjectValue,	/* freed @2 */
						     val);
		    if (length < 0) {
			if (verbose)
			    fprintf(messageFile,
				    "Ossl_Cert_GetExtensions: "
				    "Cannot get Subject Alternative Name from certificate\n");
			rc = ERROR_CODE;
		    }
		}
		if (rc == 0) {
		    if (0) fprintf(messageFile, "entry %u object %s value %s\n",
				   i + 1,  asn1Object, asn1ObjectValue);
		}
		if (rc == 0) {
		    if (strcmp("2.23.133.2.2", asn1Object) == 0) {
			*partNumber = (char *)asn1ObjectValue;
		    }
		    else if (strcmp("2.23.133.2.3", asn1Object) == 0) {
			*firwareRevision = (char *)asn1ObjectValue;
 		    }
		    else {
			OPENSSL_free(asn1ObjectValue);		/* @2 */
			asn1ObjectValue = NULL;
		    }
		}
	    }
	}
    }
    return rc;
}

int Ossl_X509_NAME_get_text_by_NID_Malloc(char **text,		/* freed by caller */
					  int nid,
					  X509_NAME 	*x509Name)
{
    int		rc = 0;
    size_t 	textLength;
    
    /* get the length */
    if (rc == 0) {
	textLength = X509_NAME_get_text_by_NID(x509Name, nid, NULL, 0);
	textLength++;	/* add for null terminator */
    }
    /* allocate, safe because the overall attachment has already been vetted */
    if (rc == 0) {
	rc = Malloc_Safe((unsigned char **)text,	/* freed by caller */
			 textLength,
			 textLength);
    }
    /* get the text */
    if (rc == 0) {
	textLength = X509_NAME_get_text_by_NID(x509Name, nid , *text, textLength);
    }
    return rc;
}



/* Ossl_VerifyCert() verifies the certificate against the CA certificate.

 */

int Ossl_Cert_Verify(X509 *X509Certificate,
		     X509 *caX509Certificate)
{
    int			rc = 0;
    int			irc = 0;		/* integer return code */
    EVP_PKEY 		*caPublicKey = NULL;	/* freed @1 */

    if (rc == 0) {
	if (verbose) fprintf(messageFile, "Ossl_Cert_Verify: Extract CA certificate public key\n");
	caPublicKey = X509_get_pubkey(caX509Certificate);	/* freed @1 */
	if (caPublicKey == NULL) {
	    if (verbose) fprintf(messageFile,
				 "Ossl_Cert_Verify: Cannot get CA certificate public key\n");
	    rc = ERROR_CODE;
	}
    }
    if (rc == 0) {
	if (verbose) fprintf(messageFile, "Ossl_Cert_Verify: Verify certificate signature\n");
	irc = X509_verify(X509Certificate, caPublicKey);
	if (irc != 1) {
	    if (verbose) fprintf(messageFile,
				 "Ossl_Cert_Verify: "
				 "Error: Cannot verify certificate signature, irc %d\n",
				 irc);
	    rc = ERROR_CODE;
	}
	else {
	    if (verbose) fprintf(messageFile, "Ossl_Cert_Verify: Verified certificate signature\n");
	}
    }
    EVP_PKEY_free(caPublicKey);		/* freed @1 */
    return rc;
}


/* Ossl_Pem_to_bin() takes a PEM format file name and returns the public modulus n and exponent
   e. */

int Ossl_Pem_to_bin(unsigned char **nArray,	/* freed by caller */
		    unsigned int *nLength,
		    unsigned char **eArray,	/* freed by caller */
		    unsigned int *eLength,
		    const char *pemFileName)
{
    int		rc = 0;			/* function return code */
    FILE 	*pemFile = NULL;	/* closed @1 */
    RSA  	*rsa = NULL;		/* freed @2 */

    if (rc == 0) {
	pemFile = fopen(pemFileName,"rb");	/* closed @1 */
	if (pemFile == NULL) {
	    if (verbose) fprintf(messageFile,
				 "Ossl_Pem_to_bin: Error opening %s\n", pemFileName);
	    rc = ERROR_CODE;
	}
    }
    if (rc == 0) {
	rsa = PEM_read_RSA_PUBKEY(pemFile, NULL ,NULL, NULL);
	if (rsa == NULL) {
	    if (verbose) fprintf(messageFile,
				 "Ossl_Pem_to_bin: Error in PEM_read_RSA_PUBKEY() for file %s\n",
		    pemFileName);
	    rc = ERROR_CODE;
	}
    }
    if (rc == 0) {
	rc = Ossl_Convertbn2binMalloc(nArray,	/* freed by caller */
				      nLength,
				      rsa->n,
				      0);	/* padBytes */
	
    }
    if (rc == 0) {
	rc = Ossl_Convertbn2binMalloc(eArray,	/* freed by caller */
				      eLength,
				      rsa->e,
				      0);	/* padBytes */
	
    }
    if (pemFile != NULL) {
	fclose(pemFile);		/* @1 */
    }
    RSA_free(rsa);			/* @2 */
    return rc;
}

/* Ossl_Array_to_RSA takes the public modulus n and exponent e and constructs an RSA key token.
 */

int Ossl_Array_to_RSA(RSA **rsa,			/* freed by caller */
		      unsigned char 	*nbytes,
		      unsigned int 	nLength,
		      unsigned char 	*ebytes,
		      unsigned int 	eLength)
{
    int 		rc = 0;			/* function return code */
    BIGNUM *		n;			/* n in BIGNUM format */
    BIGNUM *		e;			/* e in BIGNUM format */

    n = NULL;					/* freed in RSA structure */
    e = NULL;					/* freed in RSA structure */

    /* construct the openSSL public key object from n and e */
    if (rc == 0) {
	*rsa = RSA_new();			/* freed @1 */
	if (*rsa == NULL) {
	    if (verbose) fprintf(messageFile, "Ossl_Array_to_RSA: Error in RSA_new()\n");
	    rc = ERROR_CODE;
	}
    }
    if (rc == 0) {
	/* convert nModulus to BIGNUM */
	n = BN_bin2bn(nbytes, nLength, n);
	if (n == NULL) {
	    if (verbose) fprintf(messageFile, "Ossl_Array_to_RSA: Error in BN_bin2bn\n");
	    rc = ERROR_CODE;
	}
    }
    if (rc == 0) {
	(*rsa)->n = n;	/* store n in the RSA structure */
	/* convert eArray to BIGNUM */
	e = BN_bin2bn(ebytes, eLength, e);	
	if (e == NULL) {
	    if (verbose) fprintf(messageFile, "Ossl_Array_to_RSA: Error in BN_bin2bn\n");
	    rc = ERROR_CODE;
	}
    }
    if (rc == 0) {
	(*rsa)->e = e;	/* store e in the RSA structure */
    }
    return rc;
}

/* Ossl_ReadKey() reads an RSA private key from a PEM file into the openSSL RSA structure
   
   RSA *PEM_read_RSAPrivateKey(FILE *fp, RSA **x,
   pem_password_cb *cb, void *u);
*/


int Ossl_ReadKey(RSA **rsa,				/* freed by the caller */
		 const char *filename,			/* key file name */
		 const char *password)			/* key password */
{
    long	rc = 0;
    FILE 	*fp = NULL;

    if (verbose) fprintf(messageFile, "Ossl_ReadKey: reading key from %s\n",
			 filename);
    /* open the file */
    if (rc == 0) {
	fp = fopen(filename,"r");
	if (fp == NULL) {
	    if (verbose) fprintf(messageFile, "Ossl_ReadKey: Error, Cannot open %s\n", filename);
	    rc = ERROR_CODE;
	}
    }
    /* read the file.  openSSL supplies a function to deserialize the RSA key */
    if (rc == 0) {
	*rsa = PEM_read_RSAPrivateKey(fp,		/* file pointer */
				      NULL,		/* RSA structure */
				      NULL,		/* cb, password callback */
				      (void *)password);
	/* The read routines return either a pointer to the structure read or NULL if an error
	   occurred. */
	if (*rsa == NULL) {
	    if (verbose) fprintf(messageFile,
				 "Ossl_ReadKey: Error calling PEM_read_RSAPrivateKey() from %s\n",
		    filename);
	    rc = ERROR_CODE;
	}
    }
    /* close the file */
    if (fp != NULL) {
	fclose(fp);
    }
    return rc;
}

int Ossl_Random(unsigned char *buffer, size_t bytes)
{
    int rc = 0;
    int irc = 0;

    if (rc == 0) {
	irc = RAND_bytes(buffer, bytes);
	if (irc == 1) {      /* OSSL success */
	    rc = 0;
	}
	else {              /* OSSL failure */
	    if (verbose) fprintf(messageFile, "Ossl_Random: "
				 "Error calling RAND_bytes() for %u bytes\n",
				 (unsigned int)bytes);
	    rc = ERROR_CODE;
	}
    }
    return rc;
}

int Ossl_RSA_PublicEncrypt(unsigned char **encrypt_data,    	/* encrypted data, freed by caller */
			   const unsigned char *decrypt_data,      /* decrypted data */
			   size_t decrypt_data_size,
			   unsigned char *nbytes,           /* public modulus */
			   unsigned int nLength,
			   unsigned char *ebytes,           /* public exponent */
			   unsigned int eLength)
{
    int		rc = 0;
    int         irc;
    RSA 	*rsa_pub_key = NULL;			/* freed @1 */
    unsigned char *padded_data = NULL;		/* freed @2 */

    /* NOTE: Do not trace the decrypted data */

    /* check the key size vs the data size */
    if (rc == 0) {
	if (verbose) fprintf(messageFile, " Ossl_RSA_PublicEncrypt: Decrypt data size %lu\n",
			     (unsigned long)decrypt_data_size);
        if (verbose) fprintf(messageFile, "  Ossl_RSA_PublicEncrypt: Padded data size %u\n",
			     nLength);
	if (decrypt_data_size > nLength) {
	    if (verbose) fprintf(messageFile,
				 "Ossl_RSA_PublicEncrypt: "
				 "Error, Decrypt data size %lu too long for key size %u bytes\n",
		    (unsigned long)decrypt_data_size, nLength);
	    rc = ERROR_CODE;
	}
    }
    /* allocate an array for the encrypted data */
    if (rc == 0) {
	rc = Malloc_Safe(encrypt_data,		/* freed by caller */
			 nLength,
			 nLength);
    }
    /* intermediate buffer for the decrypted but still padded data */
    if (rc == 0) {
	rc = Malloc_Safe(&padded_data,		/* freed @2 */
			 nLength,
			 nLength);
    }
    /* construct the OpenSSL public key object */
    if (rc == 0) {
	rc = Ossl_Array_to_RSA(&rsa_pub_key,			/* freed @1 */
			       nbytes, nLength,
			       ebytes, eLength);
    }
    /* the EK is hard coded to OAEP padding */
    if (rc == 0) {
	irc = RSA_padding_add_PKCS1_OAEP(padded_data,      	/* to */
					 nLength,	    	/* to length */
					 decrypt_data,      	/* from */
					 decrypt_data_size, 	/* from length */
					 tpm_oaep_pad_str,  	/* encoding parameter */
					 sizeof(tpm_oaep_pad_str)); /* encoding parameter length */
	if (irc != 1) {
	    if (verbose) fprintf(messageFile,
				 "Ossl_RSA_PublicEncrypt: Error in RSA_padding_add_PKCS1_OAEP()\n");
	    rc = ERROR_CODE;
	}
    }
    if (rc == 0) {
        /* encrypt with public key.  Must pad first and then encrypt because the encrypt
           call cannot specify an encoding parameter */
	/* returns the size of the encrypted data.  On error, -1 is returned */
	irc = RSA_public_encrypt(nLength,        	/* from length */
				 padded_data,    	/* from - the clear text data */
				 *encrypt_data,  	/* the padded and encrypted data */
				 rsa_pub_key,    	/* key */
				 RSA_NO_PADDING);	/* padding */
	if (irc < 0) {
	    if (verbose) fprintf(messageFile,
				 "Ossl_RSA_PublicEncrypt: Error in RSA_public_encrypt()\n");
	    rc = ERROR_CODE;
	}
    }
    if (rc == 0) {
        if (verbose) fprintf(messageFile, "Ossl_RSA_PublicEncrypt: RSA_public_encrypt() success\n");
    }
    if (rsa_pub_key != NULL) {
        RSA_free(rsa_pub_key);  /* @1 */
    }
    free(padded_data);		/* @2 */
    return rc;
}

/* Convertbn2binMalloc() allocates the bin array, then converts the BIGNUM to bin.

   If requested, the array is zero padded.
*/

int Ossl_Convertbn2binMalloc(unsigned char **bin,	/* freed by caller */
			     unsigned int *bytes,
			     BIGNUM *bn,
			     unsigned int padBytes)
{
    int 		rc = 0;
    int         	i;
    unsigned int 	numBytes;	/* in the bignum */

    /* number of bytes required in the bin array */
    if (rc == 0) {
	i = BN_num_bytes(bn);
	if (i >= 0) {
	    numBytes = (unsigned int)i;
	}
	else {
	    if (verbose) fprintf(messageFile,
				 "Ossl_Convertbn2binMalloc: Error, bytes in BIGNUM is negative\n");
	    rc = ERROR_CODE;
	}
    }
    /* calculate the array size to malloc */
    if (rc == 0) {
        /* padBytes 0 says that no padding is required */
        if (padBytes == 0) {
            padBytes = numBytes;  /* setting equal yields no padding */
        }       
	/* if the array with padding is still less than the number of bytes required by the bignum,
	   this function fails */
        if (padBytes < numBytes) {
            if (verbose) fprintf(messageFile,
				 "Ossl_Convertbn2binMalloc: "
				 "Error, padBytes %u less than BN bytes %u\n", padBytes, numBytes);
            rc = ERROR_CODE;
        }
    }
    /* allocate for the padded array */
    if (rc == 0) {
        rc = Malloc_Safe(bin, padBytes, padBytes);
	*bytes = padBytes;
    }
    if (rc == 0) {
	/* zero pad */
	memset(*bin, 0, padBytes);
	/* if there are bytes in the bignum (it is not zero) */
	if (numBytes  > 0) {
	    BN_bn2bin(bn, *bin + padBytes - numBytes);
	}
    }
    return rc;
}

