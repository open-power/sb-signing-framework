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

#ifndef _TYPES_T_H
#define _TYPES_T_H

#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <stdio.h>

#ifdef linux
#include <asm/types.h>
typedef __u8  uint8_t;
typedef __u16 uint16_t;
typedef __u32 uint32_t;
#ifndef _STDINT_H
typedef __u64 uint64_t;
#endif
#endif

#ifdef __unix__
#define INLINE inline
#else
#define INLINE __inline
#endif

#if defined(BYTE_ORDER) && defined(BIG_ENDIAN) && BYTE_ORDER == BIG_ENDIAN
#define HO2BE_8(_x)  (_x)
#define HO2BE_4(_x)  (_x)
#else
#define HO2BE_8(_x)  ((_x<<56)|((_x<<40)&0xff000000000000ull)|((_x<<24)&0xff0000000000ull)|((_x<<8)&0xff00000000ull)|\
                     ((_x>>8)&0xff000000ull)|((_x>>24)&0xff0000ull)|((_x>>40)&0xff00ull)|(_x>>56))
#define HO2BE_4(_x)  ((_x<<24)|((_x<<8)&0xff0000)|((_x>>8)&0xff00)|(_x>>24))
#endif
#define BE2HO_8(_x)  HO2BE_8(_x)
#define BE2HO_4(_x)  HO2BE_4(_x)

#define MAX_UINT64  0xffffffffffffffffull

#endif
