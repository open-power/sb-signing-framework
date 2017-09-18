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

#ifndef CCA_FUNCTIONS_ECC_H
#define CCA_FUNCTIONS_ECC_H

int PKA_Key_Token_Build_ECCP521(long *token_length,
				unsigned char *token);
int Digital_Signature_Generate_ECC(unsigned long *signature_field_length,
				   unsigned long *signature_bit_length,
				   unsigned char *signature_field,
				   unsigned long PKA_private_key_length,
				   unsigned char *PKA_private_key,
				   unsigned long hash_length,
				   unsigned char *hash);
int Digital_Signature_Verify_ECC(unsigned long signature_field_length,
				 unsigned char *signature_field,
				 unsigned long key_token_length,
				 unsigned char *key_token,
				 unsigned long hash_length,
				 unsigned char *hash);

#endif
