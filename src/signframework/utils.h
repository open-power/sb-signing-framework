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

#ifndef UTILS_H
#define UTILS_H

#include <stdio.h>

#ifdef Linux
#include <./linux/limits.h>
#endif

#ifndef FALSE
#define FALSE   0
#endif
#ifndef TRUE
#define TRUE    1
#endif

/* general purpose error flag, gets mapped at a higher layer */
#define ERROR_CODE 1

/* Email response types */

/* 0 is success, send back email body and attachment */

/* do not send back any email */
#define RESPONSE_NO_EMAIL 1

/* send back email body, no attachment */
#define RESPONSE_BODY_ONLY 2

#if 0
/* fatal framework error, exit.  Don't want to keep looping because it will just fill up the log and
   discard email. */
#define ERROR_FATAL 3
#endif

/* send email body to framework admin, no attachment */
#define RESPONSE_BODY_TO_ADMIN 4

/* file handling */

/* 1024 should accomodate lines with a 2048-bit key, 256 bytes, 512 characters */

#define MAX_LINE_SIZE	1024

int File_Copy(const char *destinationFilename,
	     const char *sourceFilename);
int File_Open(FILE **file,
	      const char *filename,
	      const char *mode);
int File_OpenMessageFile(const char *outputBodyFilename,
			 const char* mode);
int File_CloseMessageFile(void);
int File_ReadLine(int *haveLine,
	     char *line,
	     size_t *lineLength,
	     size_t lineSize,
	     FILE *file);
int File_ReadBinaryFile(unsigned char **data,
			size_t *length,
			size_t length_max,
			const char *filename);
int File_ReadTextFile(char **text,
		      size_t *length,
		      size_t length_max,
		      const char *filename);
int File_GetSize(size_t 	*fileLength,
		 const char 	*filename);
int File_ValidateOpen(const char *filename,
		      const char *mode);
int File_WriteBinaryFile(const unsigned char *data,
			 size_t length,
			 const char *filename); 
int File_WriteBinaryFileVa(const char *filename, ...);
void File_LogTime(FILE *logFile);
void File_Printf(FILE *lFile,
		 FILE *mFile,
		 const char *format,
		 ...);

/* configuration file parsing */

int File_GetNameValue(int 	*haveLine,
		      char 	**name,
		      char 	**value,
		      char 	*lineBuffer,
		      size_t 	lineBufferLength,
		      FILE	*file);
int File_MapNameToValue(char 		**value,
			const char 	*name,
			char 		*lineBuffer,
			size_t 		lineBufferLength,
			FILE		*file);
int File_MapNameToBool(int		*booln,
		       const char 	*name,
		       char 		*lineBuffer,
		       size_t 		lineBufferLength,
		       FILE		*file);
int File_MapNameToUint(unsigned int	*value,
		       const char 	*name,
		       char 		*lineBuffer,
		       size_t 		lineBufferLength,
		       FILE		*file);
int File_GetNameValueArray(char 	***names,
			   char 	***values,
			   size_t 	*length,
			   char 	*lineBuffer,
			   size_t 	lineBufferLength,
			   FILE 	*file);
int File_GetValueArray(char 		***values,
		       size_t 		*length,
		       const char 	*inName,
		       char 		*lineBuffer,
		       size_t 		lineBufferLength,
		       FILE 		*file);

/* argv handling */

/* Number of arguments (not the number of bytes).  Since typical signers take ~10 arguments, this
   should be sufficient.  Note that arguments with a value count as two arguments. */

#define MAX_ARGV_BODY	200

#ifdef Windows
#define ARG_MAX         4000
#endif

typedef struct tdArguments {
    char 	*argv[MAX_ARGV_BODY];
    int   	argc;
    size_t 	argvBytes;
} Arguments;

void Arguments_Init(Arguments *arguments);
void Arguments_Delete(Arguments *arguments);
void Arguments_ClearSecret(const char 	*flag,
			   Arguments *arguments);

int Arguments_AddPairTo(Arguments *arguments,
			const char 	*flag,
			const char 	*value);

int Arguments_AddTo(Arguments 	*arguments,
		    const char 	*data,
		    int 	zero);

int Arguments_GetFrom(const char 	**value,
		      const char 	*flag,
		      Arguments *arguments);

/* character array handling */ 

int Array_GetLine(int *haveLine,
		  char *outLine,
		  const char **nextLine,
		  size_t lineSize,
		  const char *inLines,
		  FILE *logFile);

/* memory allocation */

int Malloc_Safe(unsigned char **ptr, size_t len, size_t max_length);
int Malloc_Strcpy(char 		**out,
		  const char 	*in);
int Realloc_Safe(unsigned char **buffer,
		 size_t size);

/*
  Format Conversion
*/

void Format_ToHexascii(char *string,
		       unsigned char *binary,
		       size_t length);
int Format_FromHexascii(unsigned char *binary,
			const char *string,
			size_t length);
int Format_ByteFromHexascii(unsigned char *byte,
			    const char *string);

#endif
