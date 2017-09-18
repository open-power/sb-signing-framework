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

#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/engine.h>

#include "debug.h"
#include "utils.h"

#define SHA1_SIZE	20
#define SHA256_SIZE	32
#define SHA512_SIZE	64

#include "ossl_functions.h"

/* messages are traced here

   All messages, even error messages, are traced only if verbose is set.  There messages are
   'techie' and should not be returned unless the user asks for them.
*/

extern FILE* messageFile;
extern int verbose;

/* AES requires data lengths that are a multiple of the block size */
#define AES_BITS 128
/* The AES block size is always 16 bytes */
#define AES_BLOCK_SIZE 16

/*
  SHA-1 functions
*/

/* Ossl_SHA1() can be called directly to hash a list of streams.

   The ... arguments to be hashed are a list of the form
   size_t length, unsigned char *buffer
   terminated by a 0 length
*/

void Ossl_SHA1(unsigned char *md, ...)
{
    va_list	ap;

    va_start(ap, md);
    Ossl_SHA1_valist(md, 0, NULL, ap);
    va_end(ap);
    return;
}

/* Ossl_SHA1_valist() is the internal function, called with the va_list already created.

   It is called from Ossl_SHA1() to do a simple hash.  Typically length0==0 and buffer0==NULL.

   It can also be called from the HMAC function to hash the variable number of input parameters.  In
   that case, the va_list for the text is already formed.  length0 and buffer0 are used to input the
   padded key.
*/

void Ossl_SHA1_valist(unsigned char *md,
		      size_t length0, unsigned char *buffer0,
		      va_list ap)
{
    uint32_t		length;
    unsigned char	*buffer;
    int			done = FALSE;
    SHA_CTX		context;
    
    SHA1_Init(&context);
    if (length0 !=0) {		/* optional first text block */
	SHA1_Update(&context, buffer0, length0);	/* hash the buffer */
    }
    while (!done) {
	length = va_arg(ap, size_t);		/* first vararg is the length */
	if (length != 0) {			/* loop until a zero length argument terminates */
	    buffer = va_arg(ap, unsigned char *);	/* second vararg is the array */
	    SHA1_Update(&context, buffer, length);	/* hash the buffer */
	}
	else {
	    done = TRUE;
	}
    }
    SHA1_Final(md, &context);
    return;
}

/*
  SHA-256 functions
*/

/* Ossl_SHA256() can be called directly to hash a list of streams.

   The ... arguments to be hashed are a list of the form
   size_t length, unsigned char *buffer
   terminated by a 0 length
*/

void Ossl_SHA256(unsigned char *md, ...)
{
    va_list	ap;

    va_start(ap, md);
    Ossl_SHA256_valist(md, 0, NULL, ap);
    va_end(ap);
    return;
}

/* Ossl_SHA256_valist() is the internal function, called with the va_list already created.

   It is called from Ossl_SHA256() to do a simple hash.  Typically length0==0 and buffer0==NULL.

   It can also be called from the HMAC function to hash the variable number of input parameters.  In
   that case, the va_list for the text is already formed.  length0 and buffer0 are used to input the
   padded key.
*/

void Ossl_SHA256_valist(unsigned char *md,
			size_t length0, unsigned char *buffer0,
			va_list ap)
{
    uint32_t		length;
    unsigned char	*buffer;
    int			done = FALSE;
    SHA256_CTX		context;
    
    SHA256_Init(&context);
    if (length0 !=0) {		/* optional first text block */
	SHA256_Update(&context, buffer0, length0);	/* hash the buffer */
    }
    while (!done) {
	length = va_arg(ap, size_t);		/* first vararg is the length */
	if (length != 0) {			/* loop until a zero length argument terminates */
	    buffer = va_arg(ap, unsigned char *);	/* second vararg is the array */
	    SHA256_Update(&context, buffer, length);	/* hash the buffer */
	}
	else {
	    done = TRUE;
	}
    }
    SHA256_Final(md, &context);
    return;
}

/*
  SHA-512 functions
*/

/* Ossl_SHA512() can be called directly to hash a list of streams.

   The ... arguments to be hashed are a list of the form
   size_t length, unsigned char *buffer
   terminated by a 0 length
*/

void Ossl_SHA512(unsigned char *md, ...)
{
    va_list	ap;

    va_start(ap, md);
    Ossl_SHA512_valist(md, 0, NULL, ap);
    va_end(ap);
    return;
}

/* Ossl_SHA512_valist() is the internal function, called with the va_list already created.

   It is called from Ossl_SHA512() to do a simple hash.  Typically length0==0 and buffer0==NULL.

   It can also be called from the HMAC function to hash the variable number of input parameters.  In
   that case, the va_list for the text is already formed.  length0 and buffer0 are used to input the
   padded key.
*/

void Ossl_SHA512_valist(unsigned char *md,
			size_t length0, unsigned char *buffer0,
			va_list ap)
{
    uint32_t		length;
    unsigned char	*buffer;
    int			done = FALSE;
    SHA512_CTX		context;
    
    SHA512_Init(&context);
    if (length0 !=0) {		/* optional first text block */
	SHA512_Update(&context, buffer0, length0);	/* hash the buffer */
    }
    while (!done) {
	length = va_arg(ap, size_t);		/* first vararg is the length */
	if (length != 0) {			/* loop until a zero length argument terminates */
	    buffer = va_arg(ap, unsigned char *);	/* second vararg is the array */
	    SHA512_Update(&context, buffer, length);	/* hash the buffer */
	}
	else {
	    done = TRUE;
	}
    }
    SHA512_Final(md, &context);
    return;
}

/* File_HashBinaryFile() reads filename, storing a SHA-256 hash in digest
 */

int Ossl_HashBinaryFile(unsigned char *digest,
			size_t length_max,
			const char *filename)
{
    int rc = 0;
    unsigned char *data = NULL;		/* freed @1 */
    size_t length;


    if (rc == 0) {
	rc = File_ReadBinaryFile(&data,		/* freed @1 */
				 &length,
				 length_max,
				 filename);
    }
    if (rc == 0) {
	Ossl_SHA256(digest,
		    length, data,
		    0, NULL);
    }
    free(data);	/* @1 */
    return rc;
}

/*
  HMAC functions based on SHA-256
*/

/* Ossl_HMAC_Generate() can be called directly to HMAC a list of streams.
   
   The ... arguments are a message list of the form
   size_t length, unsigned char *buffer
   terminated by a 0 length
*/

void Ossl_HMAC_Generate(unsigned char *hmac,
		       const unsigned char *hmac_key,
		       ...)
{
    va_list	ap;
    
    va_start(ap, hmac_key);
    Ossl_HMAC_Generatevalist(hmac, hmac_key, ap);
    va_end(ap);
    return;
}

/* Ossl_HMAC_Generatevalist() is the internal function, called with the va_list already created.

   It is called from Ossl_HMAC_Generate() and Ossl_HMAC_Check() with the va_list for the text
   already formed.
*/

#define Ossl_HMAC_BLOCK_SIZE 64
#define Ossl_HMAC_KEY_SIZE 32
#define Ossl_SHA256_BLOCK_SIZE 32

void Ossl_HMAC_Generatevalist(unsigned char *hmac,
			      const unsigned char *hmac_key,
			      va_list ap)
{
    unsigned char	ipad[Ossl_HMAC_BLOCK_SIZE];
    unsigned char	opad[Ossl_HMAC_BLOCK_SIZE];
    size_t		i;
    unsigned char	inner_hash[Ossl_SHA256_BLOCK_SIZE];

    /* calculate key XOR ipad and key XOR opad */
    /* first part, key XOR pad */
    for (i = 0 ; i < Ossl_HMAC_KEY_SIZE  ; i++) {
	ipad[i] = hmac_key[i] ^ 0x36;	/* magic numbers from RFC 2104 */
	opad[i] = hmac_key[i] ^ 0x5c;
    }
    /* second part, 0x00 XOR pad */
    memset(ipad + Ossl_HMAC_KEY_SIZE , 0x36, Ossl_HMAC_BLOCK_SIZE - Ossl_HMAC_KEY_SIZE);
    memset(opad + Ossl_HMAC_KEY_SIZE , 0x5c, Ossl_HMAC_BLOCK_SIZE - Ossl_HMAC_KEY_SIZE);
    /* calculate the inner hash, hash the key XOR ipad and the text */
    Ossl_SHA256_valist(inner_hash,
		       Ossl_HMAC_BLOCK_SIZE, ipad, ap);
    /* hash the key XOR opad and the previous hash */
    Ossl_SHA256(hmac,
		Ossl_HMAC_BLOCK_SIZE, opad,
		Ossl_SHA256_BLOCK_SIZE, inner_hash,
		0, NULL);
    return;
}

/* Ossl_HMAC_Check() can be called directly to check the HMAC of a list of streams.
   
   The ... arguments are a list of the form
   size_t length, unsigned char *buffer
   terminated by a 0 length
*/

void Ossl_HMAC_Check(int *valid,
		     unsigned char *expect,
		     const unsigned char *hmac_key,
		     ...)
{
    int			result;
    va_list		ap;
    unsigned char	actual[Ossl_SHA256_BLOCK_SIZE];

    va_start(ap, hmac_key);
    Ossl_HMAC_Generatevalist(actual, hmac_key, ap);
    result = memcmp(expect, actual, Ossl_SHA256_BLOCK_SIZE);
    if (result == 0) {
	*valid = TRUE;
    }
    else {
	*valid = FALSE;
    }
    va_end(ap);
    return;
}


/*
  AES Functions
*/

/* Ossl_AES_Encrypt() is AES non-portable code to encrypt 'decrypt_data' to 'encrypt_data'

   The stream is padded as per PKCS#7 / RFC2630

   'encrypt_data' must be free by the caller
*/

int Ossl_AES_Encrypt(unsigned char **encrypt_data,   		/* output, caller frees */
		     size_t *encrypt_length,				/* output */
		     const unsigned char *decrypt_data,			/* input */
		     size_t decrypt_length,				/* input */
		     const unsigned char *initialization_vector,	/* input */
		     const unsigned char *aes_key) 			/* input */
{
    int          	rc = 0;
    size_t              pad_length;
    unsigned char       *decrypt_data_pad = NULL;    /* freed @1 */
    AES_KEY 		aes_enc_key;
    unsigned char       ivec[AES_BLOCK_SIZE];       /* initial chaining vector */

    if (rc == 0) {
	rc = AES_set_encrypt_key(aes_key,
				 AES_BITS,
				 &aes_enc_key);
	if (rc != 0) {
	    rc = ERROR_CODE;
	}
    }
    if (rc == 0) {
        /* calculate the pad length and padded data length */
        pad_length = AES_BLOCK_SIZE - (decrypt_length % AES_BLOCK_SIZE);
        *encrypt_length = decrypt_length + pad_length;
        /* allocate memory for the encrypted response */
        rc = Malloc_Safe(encrypt_data, *encrypt_length, *encrypt_length);
    }
    /* allocate memory for the padded decrypted data */
    if (rc == 0) {
        rc = Malloc_Safe(&decrypt_data_pad, *encrypt_length, *encrypt_length);
    }
    /* pad the decrypted clear text data */
    if (rc == 0) {
        /* unpadded original data */
        memcpy(decrypt_data_pad, decrypt_data, decrypt_length);
        /* last gets pad = pad length */
        memset(decrypt_data_pad + decrypt_length, pad_length, pad_length);
	/* make a copy of the initialization vector */
	memcpy(ivec, initialization_vector, sizeof(ivec));
        /* encrypt the padded input to the output */
        AES_cbc_encrypt(decrypt_data_pad,
                        *encrypt_data,
                        *encrypt_length,
                        &(aes_enc_key),
			ivec,
                        AES_ENCRYPT);
    }
    free(decrypt_data_pad);     /* @1 */
    return rc;
}

/* Ossl_AES_Decrypt() is AES non-portable code to decrypt 'encrypt_data' to
   'decrypt_data'

   The stream must be padded as per PKCS#7 / RFC2630

   decrypt_data must be free by the caller
*/

int Ossl_AES_Decrypt(unsigned char **decrypt_data,   		/* output, caller frees */
		     size_t *decrypt_length,				/* output */
		     const unsigned char *encrypt_data,			/* input */
		     size_t encrypt_length,				/* input */
		     const unsigned char *initialization_vector,	/* input */
		     const unsigned char *aes_key) 			/* input */
{
    int          	rc = 0;
    size_t		pad_length;
    size_t		i;
    unsigned char       *pad_data;
    AES_KEY 		aes_dec_key;
    unsigned char       ivec[AES_BLOCK_SIZE];       /* initial chaining vector */
   
    if (rc == 0) {
	rc = AES_set_decrypt_key(aes_key,
				 AES_BITS,
				 &aes_dec_key);
	if (rc != 0) {
	    rc = ERROR_CODE;
	}
    }
    /* sanity check encrypted length */
    if (rc == 0) {
        if (encrypt_length < AES_BLOCK_SIZE) {
            if (verbose) fprintf(messageFile, "Ossl_AES_Decrypt: Error, bad length\n");
            rc = ERROR_CODE;
        }
    }
    /* allocate memory for the padded decrypted data */
    if (rc == 0) {
        rc = Malloc_Safe(decrypt_data, encrypt_length, encrypt_length);
    }
    /* decrypt the input to the padded output */
    if (rc == 0) {
	/* make a copy of the initialization vector */
	memcpy(ivec, initialization_vector, sizeof(ivec));
         /* decrypt the padded input to the output */
        AES_cbc_encrypt(encrypt_data,
                        *decrypt_data,
                        encrypt_length,
                        &(aes_dec_key),
			ivec,
                        AES_DECRYPT);
    }
    /* get the pad length */
    if (rc == 0) {
        /* get the pad length from the last byte */
        pad_length = (size_t)*(*decrypt_data + encrypt_length - 1);
        /* sanity check the pad length */
        if ((pad_length == 0) ||
            (pad_length > AES_BLOCK_SIZE)) {
            if (verbose) fprintf(messageFile, "Ossl_AES_Decrypt: Error, illegal pad length\n");
            rc = ERROR_CODE;
        }
    }
    if (rc == 0) {
        /* get the unpadded length */
        *decrypt_length = encrypt_length - pad_length;
        /* pad starting point */
        pad_data = *decrypt_data + *decrypt_length;
        /* sanity check the pad */
        for (i = 0 ; i < pad_length ; i++, pad_data++) {
            if (*pad_data != pad_length) {
                if (verbose) fprintf(messageFile,
				     "Ossl_AES_Decrypt: Error, bad pad %02x at index %u\n",
				     *pad_data, (unsigned int)i);
                rc = ERROR_CODE;
            }
        }
    }
    return rc;
}

/*
  RSA functions
*/

long osslBinToRSA(RSA **rsaPubKey,		/* freed by caller */
		  unsigned char *eArray,
		  unsigned long eLength,
		  unsigned char *nArray,
		  unsigned long nLength)
{
    long 		rc = 0;			/* function return code */
    BIGNUM *		n;			/* n in BIGNUM format */
    BIGNUM *		e;			/* e in BIGNUM format */

    *rsaPubKey = NULL;				/* freed by caller */
    n = NULL;					/* freed in RSA structure */
    e = NULL;					/* freed in RSA structure */

    /* construct the openSSL public key object from n and e */
    if (rc == 0) {
	*rsaPubKey = RSA_new();			/* freed @1 */
	if (*rsaPubKey == NULL) {
	    fprintf(messageFile, "osslBinToRSA: Error in RSA_new()\n");
	    rc = ERROR_CODE;
	}
    }
    if (rc == 0) {
	/* convert nArray to BIGNUM */
	n = BN_bin2bn(nArray, nLength, n);
	if (n == NULL) {
	    fprintf(messageFile, "osslBinToRSA: Error in BN_bin2bn\n");
	    rc = ERROR_CODE;
	}
    }
    if (rc == 0) {
	(*rsaPubKey)->n = n;	/* store n in the RSA structure */
	/* convert eArray to BIGNUM */
	e = BN_bin2bn(eArray, eLength, e);	
	if (e == NULL) {
	    fprintf(messageFile, "osslBinToRSA: Error in BN_bin2bn\n");
	    rc = ERROR_CODE;
	}
    }
    if (rc == 0) {
	(*rsaPubKey)->e = e;	/* store e in the RSA structure */
    }
    return rc;
}

/* osslVerify() verifies the digital 'signature' over 'digest' using the public key modulus
   'nArray' and exponent 'eArray'.  'digest' is the SHA-1 digest of the data.

   The modulus and exponent are pure binary streams, with no formatting envelope.
*/

long osslVerify(int *valid,			/* output boolean */
		unsigned char *digest,
		unsigned char *eArray,
		unsigned long eLength,
		unsigned char *nArray,
		unsigned long nLength,
		unsigned char *signature,
		unsigned long signature_size)
{
    long 		rc = 0;			/* function return code */
    RSA *		rsaPubKey;		/* public key in OpenSSL structure format */
    BIGNUM *		n;			/* n in BIGNUM format */
    BIGNUM *		e;			/* e in BIGNUM format */

    rsaPubKey = NULL;				/* freed @1 */
    n = NULL;					/* freed in RSA structure */
    e = NULL;					/* freed in RSA structure */

    if (verbose) fprintf(messageFile, "osslVerify: Verifying using key parts\n");
    if (verbose) PrintAll(messageFile, "osslVerify: public key", nLength, nArray);
    /* construct the openSSL public key object from n and e */
    if (rc == 0) {
	rsaPubKey = RSA_new();			/* freed @1 */
	if (rsaPubKey == NULL) {
	    fprintf(messageFile, "osslVerify: Error in RSA_new()\n");
	    rc = ERROR_CODE;
	}
    }
    if (rc == 0) {
	/* convert nArray to BIGNUM */
	n = BN_bin2bn(nArray, nLength, n);
	if (n == NULL) {
	    fprintf(messageFile, "osslVerify: Error in BN_bin2bn\n");
	    rc = ERROR_CODE;
	}
    }
    if (rc == 0) {
	rsaPubKey->n = n;	/* store n in the RSA structure */
	/* convert eArray to BIGNUM */
	e = BN_bin2bn(eArray, eLength, e);	
	if (e == NULL) {
	    fprintf(messageFile, "osslVerify: Error in BN_bin2bn\n");
	    rc = ERROR_CODE;
	}
    }
    if (rc == 0) {
	rsaPubKey->e = e;	/* store e in the RSA structure */
    }
    if (rc == 0) {
	rc = osslVerifyRSA(valid,		/* output boolean */
			   digest,		/* input digest */
			   rsaPubKey, 		/* OpenSSL RSA key token */
			   signature,		/* input signature */
			   signature_size);
    }
    if (rsaPubKey != NULL) {
	RSA_free(rsaPubKey);		/* @1 */
    }
    return rc;
}

/* osslVerifyRSA() verifies the digital 'signature' over 'digest' using the OpenSSL RSA key token.
   'digest' is the SHA-1 digest of the data.
*/

long osslVerifyRSA(int *valid,			/* output boolean */
		   unsigned char *digest,
		   RSA *rsaPubKey, 		/* OpenSSL RSA key token */
		   unsigned char *signature,
		   unsigned long signature_size)
{
    long 		rc = 0;			/* function return code */
    int			irc;			/* OpenSSL return code */
    unsigned char 	rawDecrypt[signature_size];	/* for debug */

    if (verbose) fprintf(messageFile, "osslVerifyRSA: Verifying using key token\n");
    if (verbose) PrintAll(messageFile, "osslVerifyRSA: digest", SHA1_SIZE, digest);
    if (rc == 0) {
	/* RSA_verify() returns 1 on successful verification, 0 otherwise. */
	*valid = RSA_verify(NID_sha1,
			    digest, SHA1_SIZE,
			    signature, signature_size, rsaPubKey);
	if (verbose) fprintf(messageFile, "\tosslVerifyRSA: RSA_verify valid %d (should be 1)\n",
			     *valid);
    }
    /*
      for debug, do a raw decrypt and print the result

      The result should be:

      PKCS#1 padding	00 01 FF ... FF 00
      SHA1 with RSA OID	15 bytes
      SHA-1 hash	20 bytes
    */
    if (rc == 0) {
	/* int RSA_public_decrypt(int flen, unsigned char *from,
	   unsigned char *to, RSA *rsa, int padding);
	*/
	irc = RSA_public_decrypt(signature_size, signature,
				 rawDecrypt,
				 rsaPubKey,
				 RSA_NO_PADDING);
	if (verbose) fprintf(messageFile,
			     "\tosslVerifyRSA: raw decrypt irc %d (should be key length)\n", irc);
	if (irc == -1) {
	    fprintf(messageFile, "osslVerifyRSA: Error in RSA_public_decrypt\n");
	    rc = ERROR_CODE;
	}
    }    
    if (rc == 0) {
	if (verbose) PrintAll(messageFile, "osslVerifyRSA: Raw decrypt", irc, rawDecrypt);
    }    
    return rc;
}

/* osslVerify256() verifies the digital 'signature' over 'digest' using the public key modulus
   'nArray' and exponent 'eArray'.  'digest' the SHA-256 digest of the data.

   The modulus and exponent are pure binary streams, with no formatting envelope.
*/

long osslVerify256(int *valid,			/* output boolean */
		   unsigned char *digest,
		   unsigned char *eArray,
		   unsigned long eLength,
		   unsigned char *nArray,
		   unsigned long nLength,
		   unsigned char *signature,
		   unsigned long signature_size)
{
    long 		rc = 0;			/* function return code */
    RSA *		rsaPubKey;		/* public key in OpenSSL structure format */
    BIGNUM *		n;			/* n in BIGNUM format */
    BIGNUM *		e;			/* e in BIGNUM format */

    rsaPubKey = NULL;				/* freed @1 */
    n = NULL;					/* freed in RSA structure */
    e = NULL;					/* freed in RSA structure */

    if (verbose) fprintf(messageFile, "osslVerify256: Verifying using key parts\n");
    if (verbose) PrintAll(messageFile, "osslVerify256: public key", nLength, nArray);
    /* construct the openSSL public key object from n and e */
    if (rc == 0) {
	rsaPubKey = RSA_new();			/* freed @1 */
	if (rsaPubKey == NULL) {
	    fprintf(messageFile, "osslVerify256: Error in RSA_new()\n");
	    rc = ERROR_CODE;
	}
    }
    if (rc == 0) {
	/* convert nArray to BIGNUM */
	n = BN_bin2bn(nArray, nLength, n);
	if (n == NULL) {
	    fprintf(messageFile, "osslVerify256: Error in BN_bin2bn\n");
	    rc = ERROR_CODE;
	}
    }
    if (rc == 0) {
	rsaPubKey->n = n;	/* store n in the RSA structure */
	/* convert eArray to BIGNUM */
	e = BN_bin2bn(eArray, eLength, e);	
	if (e == NULL) {
	    fprintf(messageFile, "osslVerify256: Error in BN_bin2bn\n");
	    rc = ERROR_CODE;
	}
    }
    if (rc == 0) {
	rsaPubKey->e = e;	/* store e in the RSA structure */
    }
    if (rc == 0) {
	rc = osslVerifyRSA256(valid,		/* output boolean */
			      digest,		/* input digest */
			      rsaPubKey, 		/* OpenSSL RSA key token */
			      signature,		/* input signature */
			      signature_size);
    }
    if (rsaPubKey != NULL) {
	RSA_free(rsaPubKey);		/* @1 */
    }
    return rc;
}

/* osslVerifyRSA256() verifies the digital 'signature' over 'digest' using the OpenSSL RSA key
   token.  'digest' is the SHA-256 digest of the data.  */

long osslVerifyRSA256(int *valid,			/* output boolean */
		      unsigned char *digest,
		      RSA *rsaPubKey, 		/* OpenSSL RSA key token */
		      unsigned char *signature,
		      unsigned long signature_size)
{
    long 		rc = 0;			/* function return code */
    int			irc;			/* OpenSSL return code */
    unsigned char 	rawDecrypt[signature_size];	/* for debug */

    if (verbose) fprintf(messageFile, "osslVerifyRSA256: Verifying using key token\n");
    if (verbose) PrintAll(messageFile, "osslVerifyRSA256: digest", SHA256_SIZE, digest);
    if (rc == 0) {
	/* RSA_verify() returns 1 on successful verification, 0 otherwise. */
	*valid = RSA_verify(NID_sha256,
			    digest, SHA256_SIZE,
			    signature, signature_size, rsaPubKey);
	if (verbose) fprintf(messageFile, "\tosslVerifyRSA256: RSA_verify valid %d (should be 1)\n",
			     *valid);
    }
    /*
      for debug, do a raw decrypt and print the result

      The result should be:

      PKCS#1 padding		00 01 FF ... FF 00
      SHA256 with RSA OID	19 bytes
      SHA-256 hash		32 bytes
    */
    if (rc == 0) {
	/* int RSA_public_decrypt(int flen, unsigned char *from,
	   unsigned char *to, RSA *rsa, int padding);
	*/
	irc = RSA_public_decrypt(signature_size, signature,
				 rawDecrypt,
				 rsaPubKey,
				 RSA_NO_PADDING);
	if (verbose) fprintf(messageFile,
			     "\tosslVerifyRSA256: raw decrypt irc %d (should be key length)\n", irc);
	if (irc == -1) {
	    fprintf(messageFile, "tosslVerifyRSA256: Error in RSA_public_decrypt\n");
	    rc = ERROR_CODE;
	}
    }    
    if (rc == 0) {
	if (verbose) PrintAll(messageFile, "osslVerifyRSA256: Raw decrypt", irc, rawDecrypt);
    }    
    return rc;
}

/* osslVerify512() verifies the digital 'signature' over 'digest' using the public key modulus
   'nArray' and exponent 'eArray'.  'digest' the SHA-512 digest of the data.

   The modulus and exponent are pure binary streams, with no formatting envelope.
*/

long osslVerify512(int *valid,			/* output boolean */
		   unsigned char *digest,
		   unsigned char *eArray,
		   unsigned long eLength,
		   unsigned char *nArray,
		   unsigned long nLength,
		   unsigned char *signature,
		   unsigned long signature_size)
{
    long 		rc = 0;			/* function return code */
    RSA *		rsaPubKey;		/* public key in OpenSSL structure format */
    BIGNUM *		n;			/* n in BIGNUM format */
    BIGNUM *		e;			/* e in BIGNUM format */

    rsaPubKey = NULL;				/* freed @1 */
    n = NULL;					/* freed in RSA structure */
    e = NULL;					/* freed in RSA structure */

    if (verbose) fprintf(messageFile, "osslVerify512: Verifying using key parts\n");
    if (verbose) PrintAll(messageFile, "osslVerify512: public key", nLength, nArray);
    /* construct the openSSL public key object from n and e */
    if (rc == 0) {
	rsaPubKey = RSA_new();			/* freed @1 */
	if (rsaPubKey == NULL) {
	    fprintf(messageFile, "osslVerify512: Error in RSA_new()\n");
	    rc = ERROR_CODE;
	}
    }
    if (rc == 0) {
	/* convert nArray to BIGNUM */
	n = BN_bin2bn(nArray, nLength, n);
	if (n == NULL) {
	    fprintf(messageFile, "osslVerify512: Error in BN_bin2bn\n");
	    rc = ERROR_CODE;
	}
    }
    if (rc == 0) {
	rsaPubKey->n = n;	/* store n in the RSA structure */
	/* convert eArray to BIGNUM */
	e = BN_bin2bn(eArray, eLength, e);	
	if (e == NULL) {
	    fprintf(messageFile, "osslVerify512: Error in BN_bin2bn\n");
	    rc = ERROR_CODE;
	}
    }
    if (rc == 0) {
	rsaPubKey->e = e;	/* store e in the RSA structure */
    }
    if (rc == 0) {
	rc = osslVerifyRSA512(valid,		/* output boolean */
			      digest,		/* input digest */
			      rsaPubKey, 		/* OpenSSL RSA key token */
			      signature,		/* input signature */
			      signature_size);
    }
    if (rsaPubKey != NULL) {
	RSA_free(rsaPubKey);		/* @1 */
    }
    return rc;
}

/* osslVerifyRSA512() verifies the digital 'signature' over 'digest' using the OpenSSL RSA key
   token.  'digest' is the SHA-512 digest of the data.  */

long osslVerifyRSA512(int *valid,			/* output boolean */
		      unsigned char *digest,
		      RSA *rsaPubKey, 		/* OpenSSL RSA key token */
		      unsigned char *signature,
		      unsigned long signature_size)
{
    long 		rc = 0;			/* function return code */
    int			irc;			/* OpenSSL return code */
    unsigned char 	rawDecrypt[signature_size];	/* for debug */

    if (verbose) fprintf(messageFile, "osslVerifyRSA512: Verifying using key token\n");
    if (verbose) PrintAll(messageFile, "osslVerifyRSA512: digest", SHA512_SIZE, digest);
    if (rc == 0) {
	/* RSA_verify() returns 1 on successful verification, 0 otherwise. */
	*valid = RSA_verify(NID_sha512,
			    digest, SHA512_SIZE,
			    signature, signature_size, rsaPubKey);
	if (verbose) fprintf(messageFile, "\tosslVerifyRSA512: RSA_verify valid %d (should be 1)\n",
			     *valid);
    }
    /*
      for debug, do a raw decrypt and print the result

      The result should be:

      PKCS#1 padding		00 01 FF ... FF 00
      SHA512 with RSA OID	19 bytes
      SHA-512 hash		64 bytes
    */
    if (rc == 0) {
	/* int RSA_public_decrypt(int flen, unsigned char *from,
	   unsigned char *to, RSA *rsa, int padding);
	*/
	irc = RSA_public_decrypt(signature_size, signature,
				 rawDecrypt,
				 rsaPubKey,
				 RSA_NO_PADDING);
	if (verbose) fprintf(messageFile,
			     "\tosslVerifyRSA512: raw decrypt irc %d (should be key length)\n", irc);
	if (irc == -1) {
	    fprintf(messageFile, "tosslVerifyRSA512: Error in RSA_public_decrypt\n");
	    rc = ERROR_CODE;
	}
    }    
    if (rc == 0) {
	if (verbose) PrintAll(messageFile, "osslVerifyRSA512: Raw decrypt", irc, rawDecrypt);
    }    
    return rc;
}
