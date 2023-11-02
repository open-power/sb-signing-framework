/* Copyright 2020 IBM Corp.
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
#include <stdint.h>
#include <string>
#include <vector>

#ifndef _SF_UTILS_H
#define _SF_UTILS_H

bool GetPassword(char*          dstParm,
                 const uint64_t dstSizeParm,
                 uint64_t&      bytesWrittenParm,
                 const bool     verboseParm);

bool IsPathWriteable(const std::string& filePathParm);

bool ReadFile(const std::string& filePathParm, std::vector<uint8_t>& dstParm);

bool WriteFile(const std::string& filePathParm, const std::vector<uint8_t>& srcParm);

std::string GetHexStringFromBinary(const std::vector<uint8_t>& binaryParm);

std::vector<uint8_t> GetBinaryFromHexString(const std::string& hexParm);

// Removes any whitespace in the string
void RemoveAllWhitespace(std::string& strParm);

std::string GetLocalUser();

std::string GetLocalHost();

#endif