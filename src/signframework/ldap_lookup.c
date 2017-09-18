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

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

// Need to link to ldap libraries -lldap
#include <ldap.h>

#include "ldap_lookup.h"
#include "framework_utils.h"

#define FILTER_BUFFER_SIZE 128
extern FILE* messageFile;

// Returns the number of results, sets *employeeId to the serial number of the first result
int ldapLookupByEmail(FrameworkConfig* configParm, const char* email, char** employeeId, bool verbose)
{
    const int scope = LDAP_SCOPE_SUBTREE;
    const char* rtnAttr = "uid";

    char filter[FILTER_BUFFER_SIZE];
    LDAP* ldap = NULL;
    LDAPMessage* result = NULL;

    int status = 0;

    if(!email)
    {
        status = -1;
    }

    if(status == 0)
    {
        int len = snprintf(filter, FILTER_BUFFER_SIZE, "(mail=%s)", email);
        if(len == -1 || len > FILTER_BUFFER_SIZE)
        {
            status = -1;
        }
    }

    if(status == 0)
    {
        if(verbose) fprintf(messageFile, "Ldap will connect to %s\n", configParm->ldapUrl);
        ldap = NULL;
        int rc = ldap_initialize(&ldap, configParm->ldapUrl);
        if(rc != 0)
        {
            if(verbose) fprintf(messageFile, "ERROR: ldap_init failed\n");
            status = -1;
        }
    }

    if(status == 0)
    {
        int version = LDAP_VERSION3;

        if(verbose) fprintf(messageFile, "Setting ldap to version 3\n");

        int rc = ldap_set_option(ldap, LDAP_OPT_PROTOCOL_VERSION, &version);
        if(rc != LDAP_OPT_SUCCESS)
        {
            if(verbose) fprintf(messageFile, "ERROR: unable to set ldap to version 3\n");
            status = -1;
        }
    }

    if(status == 0)
    {
        // Anonomous authentication
        const char* who = NULL;
        const char* cred = NULL;
        if(verbose) fprintf(messageFile, "Attempting to bind:\n\twho: %s\n\tcredentials: %s\n", who, cred);
        int rc = ldap_sasl_bind_s(ldap, NULL, NULL, NULL, NULL, NULL, NULL);


        if(rc == -1)
        {
            if(verbose) fprintf(messageFile, "ERROR: unable to bind\n");
            status = -1;
        }
    }

    if(status == 0)
    {
        char** attrs = NULL;
        int attrsonly = 0;
        LDAPControl** serverctrls = NULL;
        LDAPControl** clientctrls = NULL;
        struct timeval* timeout = NULL;
        int sizelimit = 0;
        int rc = ldap_search_ext_s(ldap, configParm->ldapBase, scope, filter,
                                   attrs, attrsonly, serverctrls, clientctrls, timeout, sizelimit, &result);
        if(verbose)
        {
            fprintf(messageFile, "Attempting Ldap Search:\n"
                    "\tBase: \t\t %s\n"
                    "\tScope: \t\t %d\n"
                    "\tFilter: \t %s\n", configParm->ldapBase, scope, filter);
        }
        if(rc != 0)
        {
            if(verbose) fprintf(messageFile, "ERROR: ldap search failed %s\n", ldap_err2string(rc));
            status = -1;
        }
    }

    if(status == 0)
    {
        status = ldap_count_entries( ldap, result);
    }

    if(employeeId)
    {
        if(status > 0)
        {
            struct berval** values = ldap_get_values_len(ldap, result, rtnAttr);

            if(values && values[0])
            {
                *employeeId = strndup(values[0]->bv_val, values[0]->bv_len);
            }
            else
            {
                if(verbose) fprintf(messageFile, "ERROR: unable to get serial number\n");
                status = -1;
            }

            ldap_value_free_len(values);
        }
    }

    if(result)
    {
        ldap_msgfree(result);
    }
    if(ldap)
    {
        ldap_unbind_ext_s(ldap, NULL, NULL);
    }
    return status;
}

// Testing code
//int main()
//{
//    {
//        char* id = NULL;
//        int nEntries = ldapLookupByEmail("mtvaught@us.ibm.com", &id, true);
//        printf("Good:\n\t%d entries found.\n\tID: %s\n", nEntries, id);
//        free(id);
//    }
//    {
//        int nEntries = ldapLookupByEmail("mtvaught@us.ibm.com", NULL, true);
//        printf("Good:\n\t%d entries found.\n", nEntries);
//    }
//    {
//        char* id = NULL;
//        int nEntries = ldapLookupByEmail("invalidemail", &id, true);
//        printf("Bad:\n\t%d entries found.\n\tID: %s\n", nEntries, id);
//    }
//    return 0;
//}
