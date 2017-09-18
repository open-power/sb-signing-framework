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
#ifndef HW_UTILS_H
#define HW_UTILS_H

#include "types_t.h"
#include "sha512.h"

#define ECID_SIZE            16

#define HOST_RESET_VECTOR    0x100

#define TEST_SYSTEM_MEMORY   (64*1024*1024)
#define TRUSTED_MEMORY_BASE  (8*1024*1024) // should be 256MB
#define TOTAL_TEST_MEMORY    (TEST_SYSTEM_MEMORY+4*1024)
#define CACHE_LINE           128
#define MEMORY_MASK          0x0fffffffffffffffull
#define CACHE_MASK           0x0fffffffffffff80ull // 128B cache line aligned
#define STACK_MASK           0x0ffffffffffff000ull // 4KB page aligned
#define HRMOR_MASK           0x0ffffffffff00000ull // 1MB aligned
#define HRMOR_IGNORE         0x8000000000000000ull
#define XSCOM_MASK           0x0ffffff800000000ull // 32GB aligned

#define HRMOR_RELATIVE(_a) ((_a)&~HRMOR_IGNORE)
#define ABSOLUTE_ADDR(_a)  ((_a)|HRMOR_IGNORE)
#define PHYSICAL(_a)       ((_a)&MEMORY_MASK)

typedef struct {
  uint64_t     GPR[32];
  uint64_t     SPRG7;
  uint64_t     HRMOR;
  uint64_t     SCRATCH_0;
  struct       {
    uint64_t   value;
    uint64_t   mask;
  }            FSP_BAR;
  uint8_t      ECID[ECID_SIZE];
  uint8_t      OTP_HW_KEY_HASH[SHA512_DIGEST_SIZE];
  uint8_t*     data;    // 64M+4K malloc/mmap
  uint8_t*     memory;  // 64M (4K aligned)
  int          mfd;
} hw_settings;

extern hw_settings HW;

#define r1      HW.GPR[1]
#define r2      HW.GPR[2]
#define r30     HW.GPR[30]

extern void     HW_Init (void);
extern void     HW_Free (void);

extern void     Log        (uint64_t code);
extern void     Error      (uint64_t code);
extern void     Check_Stop (char* msg);
extern void     Error_Stop (uint64_t code, char* msg);

extern void     assem_DCBI  (uint64_t addr);
extern void     assem_DCBZ  (uint64_t addr);
extern void     assem_DCBST (uint8_t* addr);
extern void     assem_ICBI  (uint8_t* addr);
extern void     assem_SYNC  (void);
extern void     assem_ISYNC (void);

extern void     mtspr_SPRG7 (uint64_t addr);
extern uint64_t mfspr_SPRG7 (void);

extern void     mtspr_HRMOR (uint64_t addr);
extern uint64_t mfspr_HRMOR (void);

extern void     mtspr_SCRATCH_0 (uint64_t addr);
extern uint64_t mfspr_SCRATCH_0 (void);

extern uint64_t getscom_FSP_BAR_value (uint64_t base);
extern uint64_t getscom_FSP_BAR_mask (uint64_t base);
extern void     getscom_HW_ECID (uint64_t base, uint8_t* buf);
extern void     getscom_OTP_HW_Key_Hash (uint64_t base, uint8_t* buf);

extern uint64_t physical_addr (uint64_t addr);
extern uint8_t* Convert_Mem_Addr (uint64_t);
extern uint64_t Convert_Mem_Offset (uint8_t*);

#endif
