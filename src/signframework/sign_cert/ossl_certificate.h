/********************************************************************************/
/*										*/
/*			OpenSSL Certificate Utilities  				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: ossl_certificate.h 401 2013-10-08 19:48:18Z kgoldman $	*/
/*										*/
/*			       IBM Confidential					*/
/*			     OCO Source Materials				*/
/*			 (c) Copyright IBM Corp. 2012				*/
/*			      All Rights Reserved			        */
/*										*/
/*	   The source code for this program is not published or otherwise	*/
/*	   divested of its trade secrets, irrespective of what has been		*/
/*	   deposited with the U.S. Copyright Office.				*/
/*										*/
/********************************************************************************/

#ifndef OSSL_CERTIFICATE_H
#define OSSL_CERTIFICATE_H

#include <stdlib.h>

#include <openssl/x509.h>
#include <openssl/x509v3.h>

#ifndef SHA1_SIZE	
#define SHA1_SIZE	20
#define SHA256_SIZE	32
#define SHA512_SIZE	64
#endif

typedef struct tdCertificateNameRow
{
    const char *key;
    int nid;
} CertificateNameRow;

int Ossl_Cert_Read(X509 **ekX509Certificate,
		   const char *inputAttachmentFileName);
int Ossl_Cert_Write(const char *outputAttachmentFileName,
		    X509* platformCertificate);

int Ossl_Cert_Create(X509 **x509Certificate,
		     unsigned char 	*eKModulus,
		     unsigned int 	eKnLength,
		     unsigned char 	*eKExponent,
		     unsigned int 	eKeLength,
		     char		**issuerEntries,
		     size_t		issuerEntriesLength,
		     char 		**subjectEntries,
		     size_t 		subjectEntriesLength,
		     CertificateNameRow certificateNameTable[],
		     size_t 		certificateNameTableRows,
		     unsigned int 	validity);

int Ossl_Cert_AddBasicInfo(X509 *x509Certificate,
			   unsigned int nLength,
			   const unsigned char *nModulus,
			   size_t issuerEntriesSize,
			   char **issuerEntries,
			   size_t subjectEntriesSize,
			   char **subjectEntries,
			   CertificateNameRow certificateNameTable[],
			   size_t certificateNameTableRows,
			   unsigned int validity);

int Ossl_Cert_AddSubjectAltNameTCG(X509 *x509Certificate);
int Ossl_Cert_AddUniqueInfoTCG(X509 *x509Certificate);

int Ossl_Cert_AddPublicKey(X509 *x509Certificate,
			   unsigned int nLength,
			   unsigned char *nBytes,
			   unsigned int eLength,
			   unsigned char *eBytes);

int Ossl_Cert_GetDigest(unsigned char **digest,
			unsigned int *digestLength,
			unsigned int *oidDigestLength,
			const char *digestAlgorithm,
			X509 *x509Certificate);

int Ossl_Cert_AddSignatureAlgorithm(X509 *x509Certificate,
				    const char *digestAlgorithm);

void Ossl_Cert_AddSignature(X509 *x509Certificate,
			    unsigned char *signature,
			    unsigned long signatureLength);

int Ossl_Cert_Sign(X509 *x509Certificate,
		   const char *digestAlgorithm,
		   const char *keyFileName,
		   const char *keyPassword);

int Ossl_Cert_AddExtension(X509 *x509Certificate, int nid, char *value);

int Ossl_CreateX509Name(X509_NAME **x509Name,
			size_t entriesSize,
			char **entries,
			CertificateNameRow certificateNameTable[],
			size_t certificateNameTableRows);

int Ossl_Cert_GetParameters(X509 *x509Certificate,
			    unsigned char 	**modulus,
			    unsigned int 	*nLength,
			    unsigned char 	**exponent,
			    unsigned int 	*eLength,
			    int needExtensions);

int Ossl_Cert_GetSerialNumber(unsigned char 	**binSerialNumber,
			      unsigned int 	*binSerialNumberBytes,
			      X509 		*x509Certificate);
int Ossl_Cert_GetIssuerName(char **commonName,
			    int nid,
			    X509 *x509Certificate);
int Ossl_Cert_GetPublicKey(unsigned char **modulus,
			   unsigned int *nBytes,
			   unsigned char **exponent,
			   unsigned int *eBytes,
			   X509 *x509Certificate);
int Ossl_Cert_GetExtensions(char 		**partNumber,
			    char 		**firwareRevision,
			    X509 		*x509Certificate);

int Ossl_X509_NAME_get_text_by_NID_Malloc(char **text,
					  int nid,
					  X509_NAME 	*x509Name);

int Ossl_Cert_Verify(X509 *ekX509Certificate,
		     X509 *caEkX509Certificate);


int Ossl_Pem_to_bin(unsigned char **nArray,
		    unsigned int *nLength,
		    unsigned char **eArray,
		    unsigned int *eLength,
		    const char *pemFileName);
		    
int Ossl_Array_to_RSA(RSA **rsa,
		      unsigned char 	*nbytes,
		      unsigned int 	nLength,
		      unsigned char 	*ebytes,
		      unsigned int 	eLength);

int Ossl_ReadKey(RSA **rsa,
		 const char *filename,
		 const char *password);

int Ossl_Random(unsigned char *buffer, size_t bytes);

int Ossl_RSA_PublicEncrypt(unsigned char **encrypt_data,
			   const unsigned char *decrypt_data,
			   size_t decrypt_data_size,
			   unsigned char *nbytes,
			   unsigned int nLength,
			   unsigned char *ebytes,
			   unsigned int eLength);

int Ossl_Convertbn2binMalloc(unsigned char **bin,
			     unsigned int *bytes,
			     BIGNUM *bn,
			     unsigned int padBytes);

#endif
