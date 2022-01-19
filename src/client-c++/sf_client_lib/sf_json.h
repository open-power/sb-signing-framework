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
#include <sf_client/sf_rc.h>
#include <stdint.h>
#include <string>
#include <vector>

#ifndef _SFJSON_H
#define _SFJSON_H

namespace sf_client
{
    struct Json_CommandRequestV1
    {
        std::string          mProject;
        std::string          mParms;
        std::string          mSelfReportedUser;
        std::string          mComment;
        std::string          mEpwdHex;
        std::vector<uint8_t> mPayload;
    };

    struct Json_CommandResponseV1
    {
        std::vector<uint8_t> mResult;
        std::string          mStandardOut;
        int                  mReturnValue;

        void clear()
        {
            mResult.clear();
            mStandardOut.clear();
            mReturnValue = 0;
        };
    };

    rc createCommandRequestJsonV1(const Json_CommandRequestV1& requestParm,
                                  std::string&                 dstJsonParm);

    rc parseCommandResponseJsonV1(const std::string&      jsonParm,
                                  Json_CommandResponseV1& dstResponseParm);

} // namespace sf_client

#endif