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

#ifndef CCA_FUNCTIONS_H
#define CCA_FUNCTIONS_H

#define CCA_KEY_IDENTIFIER_LENGTH 64	/* See CCA manual Key_Generate */

int Login_Control(int logIn,
		   const char *userName,
		   const char *password);
int Access_Control_Initialization(const char *profileID,
				  unsigned int passwordExpire,
				  const char *password);
int Crypto_Facility_SetClock(void);
int Password_ToMechanism(unsigned char 	**mechanism,
			 size_t 	*mechanismLength,
			 unsigned int 	passwordExpire,
			 const char 	*password);

int Key_Generate(unsigned char *generated_key_identifier_1);
int PKA_Key_Token_Build(long *token_length,
			unsigned char *token,
			unsigned int bitSize,
			int encrypt);
int Random_Number_Generate_Long(unsigned char *random_number,
				size_t random_number_length_in);
int PKA_Decrypt(unsigned long *cleartext_length,
		unsigned char *cleartext,
		unsigned long PKA_private_key_length,
		unsigned char *PKA_private_key,
		unsigned long ciphertext_length,
		unsigned char *ciphertext);
int PKA_Encrypt(unsigned long *ciphertext_length,
		unsigned char *ciphertext,
		unsigned long PKA_public_key_length,
		unsigned char *PKA_public_key,
		unsigned long cleartext_length,
		unsigned char *cleartext);

int Symmetric_Algorithm_Encipher(long *ciphertext_length,
				 unsigned char **ciphertext,
				 long cleartext_length,
				 unsigned char *cleartext,
				 unsigned char *initialization_vector,
				 const unsigned char *key_identifier);
int Symmetric_Algorithm_Decipher(long *cleartext_length,
				 unsigned char **cleartext,
				 long ciphertext_length,
				 unsigned char *ciphertext,
				 unsigned char *initialization_vector,
				 const unsigned char *key_identifier);
int PKA_Key_Generate(long *generated_key_identifier_length,
		     unsigned char *generated_key_identifier,
		     long skeleton_key_token_length,
		     unsigned char *skeleton_key_token);
int Digital_Signature_Generate(unsigned long *signature_field_length,
			       unsigned long *signature_bit_length,
			       unsigned char *signature_field,
			       unsigned long PKA_private_key_length,
			       unsigned char *PKA_private_key,
			       unsigned long hash_length,
			       unsigned char *hash);
int Digital_Signature_Verify(unsigned long signature_field_length,
			     unsigned char *signature_field,
			     unsigned long key_token_length,
			     unsigned char *key_token,
			     unsigned long hash_length,
			     unsigned char *hash);

void CCA_PrintError(long return_code,
		    long reason_code);
void CCA_PrintReturn00(long reason_code);
void CCA_PrintReturn04(long reason_code);
void CCA_PrintReturn08(long reason_code);
void CCA_PrintReturn0c(long reason_code);
void CCA_PrintReturn10(long reason_code);

#endif
