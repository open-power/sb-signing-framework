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


#ifndef ECCUTILS_H
#define ECCUTILS_H

/* some very high maximums, just to prevent resource exhaustion in case of a configuration error */
#define MAX_PROJECT_FILES 		100
#define MAX_SENDERS_PER_PROJECT		4000

int GetAuxArgs(char **signAlgorithm,
	       char **digestAlgorithm,
	       int *checkUnique,
               int *rawHeaderInput,
	       unsigned int *numberOfProjectFiles,
	       char ***projectConfigFilenames,
	       const char *projectAuxConfigFileName);
int GetSendersArray(char 	****senders,
		    unsigned int **numberOfSenders,
		    unsigned int numberOfProjectFiles,
		    char 	**projectConfigFilenames);
int CheckSenders(unsigned int 	numberOfProjectFiles,
		 char 		**projectConfigFilenames,
		 unsigned int *numberOfSenders,
		 char 		***senders);

#endif
