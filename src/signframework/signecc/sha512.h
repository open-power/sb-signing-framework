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

#ifndef SHA512_H
#define SHA512_H

#include "types_t.h"

#define SHA512_DIGEST_SIZE  64

typedef struct {
  uint64_t     M[16];
  uint64_t     H[8];
  uint64_t     Q;
  uint64_t     L;
} SHA512;

extern void SHA512_Init   (SHA512* sha);
extern void SHA512_Update (SHA512* sha, uint8_t* M, uint64_t len);
extern void SHA512_Finish (SHA512* sha, uint8_t* H);
extern void SHA512_Hash   (SHA512* sha, uint8_t* M, uint64_t len, uint8_t* H);

#endif
