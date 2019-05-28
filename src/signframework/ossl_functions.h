/* Copyright 2019 IBM Corp.
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

#ifndef OSSL_FUNCTIONS_H
#define OSSL_FUNCTIONS_H

#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>

#include <openssl/crypto.h>

void Ossl_SHA1(unsigned char *md, ...);
void Ossl_SHA1_valist(unsigned char *md,
		      size_t length0, unsigned char *buffer0,
		      va_list ap);

void Ossl_SHA256(unsigned char *md, ...);
void Ossl_SHA256_valist(unsigned char *md,
			size_t length0, unsigned char *buffer0,
			va_list ap);

void Ossl_SHA384(unsigned char *md, ...);
void Ossl_SHA384_valist(unsigned char *md,
			size_t length0, unsigned char *buffer0,
			va_list ap);

void Ossl_SHA512(unsigned char *md, ...);
void Ossl_SHA512_valist(unsigned char *md,
			size_t length0, unsigned char *buffer0,
			va_list ap);

int Ossl_HashBinaryFile(unsigned char *digest,
			size_t length_max,
			const char *filename);

void Ossl_HMAC_Generate(unsigned char *hmac,
			const  unsigned char *hmac_key,
			...);
void Ossl_HMAC_Generatevalist(unsigned char *hmac,
			     const unsigned char *hmac_key,
			     va_list ap);
void Ossl_HMAC_Check(int *valid,
		     unsigned char *expect,
		     const unsigned char *hmac_key,
		     ...);

int Ossl_AES_Encrypt(unsigned char **encrypt_data,
		     size_t *encrypt_length,
		     const unsigned char *decrypt_data,
		     size_t decrypt_length,
		     const unsigned char *initialization_vector,
		     const unsigned char *aes_key);
int Ossl_AES_Decrypt(unsigned char **decrypt_data,
		     size_t *decrypt_length,
		     const unsigned char *encrypt_data,
		     size_t encrypt_length,
		     const unsigned char *initialization_vector,
		     const unsigned char *aes_key);

long osslBinToRSA(RSA **rsaPubKey,
		  unsigned char *eArray,
		  unsigned long eLength,
		  unsigned char *nArray,
		  unsigned long nLength);

long osslVerify(int *valid,
		unsigned char *digest,
		unsigned char *eArray,
		unsigned long eLength,
		unsigned char *nArray,
		unsigned long nLength,
		unsigned char *signature,
		unsigned long signature_size);
long osslVerifyRSA(int *valid,
		   unsigned char *digest,
		   RSA *rsaPubKey,
		   unsigned char *signature,
		   unsigned long signature_size);
long osslVerify256(int *valid,
		   unsigned char *digest,
		   unsigned char *eArray,
		   unsigned long eLength,
		   unsigned char *nArray,
		   unsigned long nLength,
		   unsigned char *signature,
		   unsigned long signature_size);
long osslVerifyRSA256(int *valid,
		      unsigned char *digest,
		      RSA *rsaPubKey,
		      unsigned char *signature,
		      unsigned long signature_size);
long osslVerify384(int *valid,
		   unsigned char *digest,
		   unsigned char *eArray,
		   unsigned long eLength,
		   unsigned char *nArray,
		   unsigned long nLength,
		   unsigned char *signature,
		   unsigned long signature_size);
long osslVerifyRSA384(int *valid,
		      unsigned char *digest,
		      RSA *rsaPubKey,
		      unsigned char *signature,
		      unsigned long signature_size);
long osslVerify512(int *valid,
		   unsigned char *digest,
		   unsigned char *eArray,
		   unsigned long eLength,
		   unsigned char *nArray,
		   unsigned long nLength,
		   unsigned char *signature,
		   unsigned long signature_size);
long osslVerifyRSA512(int *valid,
		      unsigned char *digest,
		      RSA *rsaPubKey,
		      unsigned char *signature,
		      unsigned long signature_size);
#endif
