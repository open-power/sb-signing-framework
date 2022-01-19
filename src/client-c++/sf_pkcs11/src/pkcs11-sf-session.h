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
class PKCS11_SfToken;

#include <sf_client/sf_client.h>

#ifndef _PKCS11_SF_SESSION_H
#define _PKCS11_SF_SESSION_H

class PKCS11_SfSession
{
  public:
    PKCS11_SfSession(PKCS11_SfToken& tokenParm);

    void initSearch(CK_ATTRIBUTE_PTR templateParm, CK_ULONG templateCountParm);
    void doSearch(CK_OBJECT_HANDLE_PTR dstObjectsParm,
                  CK_ULONG             dstObjectsSizeParm,
                  CK_ULONG&            objectsWrittenParm);
    void endSearch();

    const SfKey* getKey(CK_OBJECT_HANDLE handleParm);

    void initSigning(CK_OBJECT_HANDLE keyParm);
    bool doSigning(CK_BYTE_PTR srcParm,
                   CK_ULONG    srcLengthParm,
                   CK_BYTE_PTR dstParm,
                   CK_ULONG&   dstLengthParm);

  protected:
    PKCS11_SfToken& mToken;

    uint64_t         mFindObjectCurrentIndex;
    CK_ATTRIBUTE_PTR mSearchTemplate;
    CK_ULONG         mNumberOfTemplates;

    uint64_t mSignKey = 0;
};

#endif