/* Copyright 2022 IBM Corp.
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
#ifndef _SFRC_H
#define _SFRC_H

namespace sf_client
{
    enum rc
    {
        success                     = 0,
        failure                     = 1,
        invalid_parm                = 2,
        password_retry              = 3,
        pkey_not_encrypted          = 4,
        json_new_obj_fail           = 5,
        json_convert_to_string_fail = 6,
        json_invalid_parm           = 7,
        json_invalid_object_type    = 8,
        json_tag_not_found          = 9,
        json_parse_root_fail        = 10,
        epwd_read_fail              = 11,
        curl_failure                = 12,
        curl_init_failure           = 13,
    };

}

#endif