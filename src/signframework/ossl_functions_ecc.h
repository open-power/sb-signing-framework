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

#ifndef OSSL_FUNCTIONS_ECC_H
#define OSSL_FUNCTIONS_ECC_H

#include <stdlib.h>

#include <openssl/crypto.h>
#include <openssl/ecdsa.h>

long Ossl_VerifyECC(int *valid,
		    const unsigned char *digest,
		    size_t digestLength,
		    const unsigned char *publicKey,
		    size_t publicKeyLength,
		    const unsigned char *signature,
		    unsigned long signatureLength);

long Ossl_SetPubKey_ECC(EC_KEY **ecPubKey,
			const unsigned char *publicKey,
			size_t publicKeyLength);

#endif
