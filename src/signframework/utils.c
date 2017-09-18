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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <ctype.h>
#include <errno.h>
#include <time.h>

#include "utils.h"

/* messages are traced here

   All messages, even error messages, are traced only if verbose is set.  There messages are
   'techie' and should not be returned unless the user asks for them.
*/

extern FILE* messageFile;
extern int verbose;

#define COPY_BLOCK_SIZE 1024

/* File_Copy() copies the source file to the destination file.
 */

int File_Copy(const char *destinationFilename,
              const char *sourceFilename)
{
    int 	rc = 0;
    char	buffer[COPY_BLOCK_SIZE];
    size_t	bytesRead;
    size_t	bytesWritten;
    FILE	*destination = NULL;	/* freed @1 */
    FILE	*source = NULL;		/* freed @2 */

    /* open the destination for write */
    if (rc == 0) {
        rc = File_Open(&destination, destinationFilename, "w");	/* closed @1 */
    }
    /* open the source for read */
    if (rc == 0) {
        rc = File_Open(&source, sourceFilename, "r");		/* closed @2 */
    }
    /* copy the source to the destination */
    while (rc == 0) {
        bytesRead = fread(buffer, 1, COPY_BLOCK_SIZE, source);
        if (bytesRead == 0) {
            if (feof(source)) {
                break;
            }
            else {
                if (verbose) fprintf(messageFile,
                                     "File_Copy: Error reading from %s\n", sourceFilename);
                rc = ERROR_CODE;
            }
        }
        bytesWritten = fwrite(buffer, 1, bytesRead, destination);
        if (bytesWritten != bytesRead) {
            if (verbose) fprintf(messageFile,
                                 "File_Copy: Error writing to %s\n", destinationFilename);
        }
    }
    /* close the destination */
    if (destination != NULL) {
        fclose(destination);	/* @1 */
    }
    /* close the source */
    if (source != NULL) {
        fclose(source);		/* @2 */
    }
    return rc;
}

/* File_Open() opens the 'filename' for 'mode'
 */

int File_Open(FILE **file,
              const char *filename,
              const char* mode)
{
    int 	rc = 0;

    if (rc == 0) {
        *file = fopen(filename, mode);
        if (*file == NULL) {
            if (verbose) fprintf(messageFile, "File_Open: Error opening %s for %s, %s\n",
                                 filename, mode, strerror(errno));
            rc = ERROR_CODE;
        }
    }
    return rc;
}

/* File_OpenMessageFile() opens the global messageFile.  messageFile is used to fprintf messages to
   the returned output email body.

   For each new email, the framework first opens for write.  Then the signer program can open it for
   append.  Finally, the framework can then open for append to add any final messages.

   Returns responseType
*/

int File_OpenMessageFile(const char *outputBodyFilename,
                         const char* mode)
{
    int 	rc = 0;

    /* Switch messageFile error and trace printing from stdout to the output body.  The design sends
       framework initialization to stdout so the person initiating the program can see errors.  Once
       it's running, everything else goes to the output body and (usually) back to the user.  */
    if (rc == 0) {
        rc = File_Open(&messageFile, outputBodyFilename, mode);
    }
    /* if the open succeeded */
    if (rc == 0) {
        /* turn off buffering as a debug aid, so the file gets updated while stepping with a
           debugger */
        setvbuf(messageFile , 0, _IONBF, 0);
    }
    /* if the open failed */
    else {
        fprintf(messageFile,
                "File_OpenMessageFile: Error cannot open %s\n", outputBodyFilename);
	    /* Since the configuration is validated at startup, this should never fail.  The only
	       possibilty is that something happened to the platform while the framework was
	       running.  No email can be returned and messages go to stdout. */
        messageFile= stdout;
        rc = RESPONSE_NO_EMAIL;
    }
    return rc;
}

/* File_CloseMessageFile() flushes and then closes the global messageFile and them sets it to
   stdout.

   If messageFile is already stdout (or NULL), the function does nothing.
*/

int File_CloseMessageFile(void)
{
    int 	rc = 0;

    if ((messageFile != NULL) &&	/* should never happen after start up */
        (messageFile != stdout)) {
        fflush(messageFile);
        fclose(messageFile);
        messageFile = stdout;	/* should never print after this, but the messages should go
                                   somewhere */
    }
    return rc;
}

/* File_Readline() returns the next non-comment, non-whitespace line from the file.

   It replaces the white space at the end of a line with a NUL terminator.
*/

int File_ReadLine(int *haveLine,	/* TRUE is line returned, otherwise FALSE */
                  char *line,		/* returned line */
                  size_t *lineLength,	/* returned actual length */
                  size_t lineSize,	/* max size of line buffer */
                  FILE *file)		/* opened file to read */
{
    int 	rc = 0;
    char 	*prc = NULL;		/* pointer return code */

    *haveLine = FALSE;
    do {
        /* read the line */
        if (rc == 0) {
            prc = fgets(line, lineSize, file);
        }
        /* skip comment lines */
        if ((rc == 0) && (prc != NULL)) {
            if (line[0] == '#') {
                continue;
            }
        }
        /* skip lines beginning with whitespace */
        if ((rc == 0) && (prc != NULL)) {
            if (isspace(line[0])) {
                continue;
            }
        }
        if ((rc == 0) && (prc != NULL)) {
            /* found a line with text */
            *haveLine = TRUE;
            /* check for line overflow */
            *lineLength = strlen(line);
            if (line[*lineLength -1] != '\n') {	/* last character before NUL should be newline */
                if (verbose) fprintf(messageFile,
                                     "File_ReadLine: Error, Line %s is longer that %u bytes\n",
                                     line, (unsigned int)lineSize);
                rc = ERROR_CODE;
            }
        }
        /* strip off white space at the end of the line */
        if ((rc == 0) && (prc != NULL)) {
            while (*lineLength > 0) {
                if (isspace(line[(*lineLength) - 1])) {
                    line[(*lineLength) - 1] = '\0';
                    (*lineLength)--;
                }
                else {
                    break;
                }
            }
        }
        break;
    }
    while ((rc == 0) && (prc != NULL));
    return rc;
}

/* File_ReadBinaryFile() reads 'filename'.  The results are put into 'data', which must be freed by
   the caller.  'length' indicates the number of bytes read. 'length_max' is the maximum allowed
   length.

   If 'length_max' is zero, the caller trusts the file length.
*/

int File_ReadBinaryFile(unsigned char **data,     /* must be freed by caller */
                        size_t *length,
                        size_t length_max,
                        const char *filename)
{
    int		rc = 0;
    long	lrc;
    size_t	src;
    int		irc;
    FILE	*file = NULL;

    *data = NULL;
    *length = 0;
    /* open the file */
    if (rc == 0) {
        rc = File_Open(&file, filename, "rb");				/* closed @1 */
    }
    /* determine the file length */
    if (rc == 0) {
        irc = fseek(file, 0L, SEEK_END);	/* seek to end of file */
        if (irc == -1L) {
            if (verbose) fprintf(messageFile,
                                 "File_ReadBinaryFile: Error seeking to end of %s\n", filename);
            rc = ERROR_CODE;
        }
    }
    if (rc == 0) {
        lrc = ftell(file);			/* get position in the stream */
        if (lrc == -1L) {
            if (verbose) fprintf(messageFile,
                                 "File_ReadBinaryFile: Error ftell'ing %s\n", filename);
            rc = ERROR_CODE;
        }
        else {
            *length = (size_t)lrc;		/* save the length */
        }
    }
    if (rc == 0) {
        irc = fseek(file, 0L, SEEK_SET);	/* seek back to the beginning of the file */
        if (irc == -1L) {
            if (verbose) fprintf(messageFile,
                                 "File_ReadBinaryFile: Error seeking to beginning of %s\n",
                                 filename);
            rc = ERROR_CODE;
        }
    }
    /* allocate a buffer for the actual data */
    if ((rc == 0) && *length != 0) {
        /* if length_max is zero, the caller trusts the file length */
        if (length_max == 0) {
            length_max = *length;
        }
        rc = Malloc_Safe(data, *length, length_max);
    }
    /* read the contents of the file into the data buffer */
    if ((rc == 0) && *length != 0) {
        src = fread(*data, 1, *length, file);
        if (src != *length) {
            if (verbose) fprintf(messageFile,
                                 "File_ReadBinaryFile: Error reading %s, %u bytes\n",
                                 filename, (unsigned int)*length);
            rc = ERROR_CODE;
        }
    }
    if (file != NULL) {
        irc = fclose(file);		/* @1 */
        if (irc != 0) {
            if (verbose) fprintf(messageFile,
                                 "File_ReadBinaryFile: Error closing %s\n",
                                 filename);
            rc = ERROR_CODE;
        }
    }
    if (rc != 0) {
        if (verbose) fprintf(messageFile, "File_ReadBinaryFile: Error reading %s\n", filename);
        free(*data);
        data = NULL;
    }
    return rc;
}

/* File_ReadTextFile() reads 'filename'.  The results are put into 'text', which must be freed by
   the caller.  'length' indicates the number of bytes read.

   A NUL terminator is added to 'text', but the bytes are not scanned for e.g., printable
   characters.
*/

int File_ReadTextFile(char **text,     /* must be freed by caller */
                      size_t *length,
                      size_t length_max,
                      const char *filename)
{
    int rc = 0;

    /* read the file as raw binary data */
    if (rc == 0) {
        rc = File_ReadBinaryFile((unsigned char **)text, length, length_max, filename);
    }
    /* realloc one more byte for the NULL terminator */
    if (rc == 0) {
        rc = Realloc_Safe((unsigned char **)text, (*length) + 1);
    }
    /* NUL terminate the string */
    if (rc == 0) {
        (*text)[*length] = '\0';
    }
    return rc;
}

/* File_GetSize() opens a file for read and returns its length
 */

int File_GetSize(size_t *fileLength,
                 const char *filename)
{
    int		rc = 0;
    FILE	*file = NULL;		/* freed @1 */
    int         irc;
    long        lrc;

    if (rc == 0) {
        if (filename == NULL) {
            if (verbose) fprintf(messageFile, "File_GetSize: Error, filename is null\n");
            rc = ERROR_CODE;
        }
    }
    if (rc == 0) {
        rc = File_Open(&file, filename, "rb");	/* freed @1 */
    }
    /* determine the file length */
    if (rc == 0) {
        irc = fseek(file, 0L, SEEK_END);        /* seek to end of file */
        if (irc == -1L) {
            if (verbose) fprintf(messageFile, "File_GetSize: Error fseek'ing %s, %s\n",
                                 filename, strerror(errno));
            rc = ERROR_CODE;
        }
    }
    if (rc == 0) {
        lrc = ftell(file);                      /* get position in the stream */
        if (lrc == -1L) {
            if (verbose) fprintf(messageFile, "File_GetSize: Error (fatal) ftell'ing %s, %s\n",
                                 filename, strerror(errno));
            rc = ERROR_CODE;
        }
        else {
            *fileLength = lrc;      		/* save the length */
        }
    }
    if (file != NULL) {
        fclose(file);	/* @1 */
    }
    return rc;
}

/* File_ValidateOpen() validates that a file can be opened for 'mode'.  It then closes the file.
 */

int File_ValidateOpen(const char *filename,
                      const char *mode)
{
    int		rc = 0;
    FILE	*file = NULL;		/* freed @1 */

    if (rc == 0) {
        if (filename == NULL) {
            if (verbose) fprintf(messageFile, "File_ValidateOpen: Error, filename is null\n");
            rc = ERROR_CODE;
        }
    }
    if (rc == 0) {
        rc = File_Open(&file, filename, mode);	/* freed @1 */
    }
    /* immediately close */
    if (file != NULL) {
        fclose(file);		/* @1 */
    }
    return rc;
}

/* File_WriteBinaryFile() writes 'length' bytes of data to filename
 */

int File_WriteBinaryFile(const unsigned char *data,
                         size_t length,
                         const char *filename)
{
    long	rc = 0;
    size_t	src;
    int		irc;
    FILE	*file = NULL;

    /* open the file */
    if (rc == 0) {
        rc = File_Open(&file, filename, "wb");	/* closed @1 */
    }
    /* write the contents of the data buffer into the file */
    if (rc == 0) {
        src = fwrite(data, 1, length, file);
        if (src != length) {
            if (verbose) fprintf(messageFile, "File_WriteBinaryFile: Error writing %s\n",
                                 filename);
            rc = ERROR_CODE;
        }
    }
    if (file != NULL) {
        irc = fclose(file);		/* @1 */
        if (irc != 0) {
            if (verbose) fprintf(messageFile, "File_WriteBinaryFile: Error closing %s\n",
                                 filename);
            rc = ERROR_CODE;
        }
    }
    return rc;
}

/* File_WriteBinaryFileVa() writes filename with a varargs list of length / buffer pairs.  A zero
   length terminates the loop
*/

int File_WriteBinaryFileVa(const char *filename, ...)
{
    long		rc = 0;
    FILE		*file = NULL;		/* closed @1 */
    va_list		ap;
    uint32_t		length;
    unsigned char	*buffer;
    size_t		src;
    int			irc;
    int			done = FALSE;

    /* open the file */
    if (rc == 0) {
        rc = File_Open(&file, filename, "wb");	/* closed @1 */
    }
    if (rc == 0) {
        va_start(ap, filename);
    }
    while ((rc == 0) && !done) {
        length = va_arg(ap, size_t);		/* first vararg is the length */
        if (length != 0) {			/* loop until a zero length argument terminates */
            buffer = va_arg(ap, unsigned char *);	/* second vararg is the array */
            src = fwrite(buffer , 1, length, file);	/* write the buffer */
            if (src != length) {
                if (verbose) fprintf(messageFile, "File_WriteBinaryFileVa: Error writing %s\n",
                                     filename);
                rc = ERROR_CODE;
            }
        }
        else {
            done = TRUE;
        }
    }
    if (file != NULL) {
        irc = fclose(file);		/* @1 */
        if (irc != 0) {
            if (verbose) fprintf(messageFile, "File_WriteBinaryFileVa: Error closing %s\n",
                                 filename);
            rc = ERROR_CODE;
        }
    }
    return rc;
}

/* File_GetNameValue() reads the next non-comment, non-whitespace line from the file.

   If a line is found, it allocates memory and returns the 'name' and 'value'.  name and value are
   separated by a '=' character.
*/

int File_GetNameValue(int 	*haveLine,
                      char 	**name,		/* freed by caller */
                      char	**value,	/* freed by caller */
                      char 	*lineBuffer,
                      size_t	lineBufferLength,
                      FILE	*file)
{
    int		rc = 0;
    size_t 	lineLength;
    char 	*token;

    if (rc == 0) {
        rc = File_ReadLine(haveLine, lineBuffer, &lineLength, lineBufferLength, file);
    }
    /* get first token */
    if ((rc == 0) && *haveLine) {
        token = strtok(lineBuffer, "=");	/* get first token */
        if (token == NULL) {		/* malformed line */
            if (verbose) fprintf(messageFile, "File_GetNameValue: Error, bad format, missing =\n");
            if (verbose) fprintf(messageFile, "File_GetNameValue: Line: %s\n", lineBuffer);
            rc = ERROR_CODE;
        }
    }
    if ((rc == 0) && *haveLine) {
        rc = Malloc_Strcpy(name, token);
    }
    if ((rc == 0) && *haveLine) {
        token = strtok(NULL,"" );	/* get next token, rest of string */
        if (token == NULL) {		/* malformed line */
            if (verbose) fprintf(messageFile, "File_GetNameValue: Error, bad format, missing =\n");
            if (verbose) fprintf(messageFile, "File_GetNameValue: Line: %s\n", lineBuffer);
            rc = ERROR_CODE;
        }
    }
    if ((rc == 0) && *haveLine) {
        rc = Malloc_Strcpy(value, token);
    }
    return rc;
}

/* File_MapNameToValue() scans lines from file of the form

   name=value

   if found, memory is malloc'ed for the value and the value is copied
   if not found, an error is returned
*/

int File_MapNameToValue(char 		**value,		/* freed by caller */
                        const char 	*name,			/* name to search for */
                        char 		*lineBuffer,		/* supplied buffer for lines */
                        size_t 		lineBufferLength,	/* size of the line buffer */
                        FILE		*file)			/* input file stream */
{
    int		rc = 0;
    int		irc = 0;
    int 	haveLine;	/* true if more lines in the file stream */
    size_t 	lineLength;	/* length of the current line */
    char 	*token;		/* tokenizing the line */

    do {
        if (rc == 0) {
            rc = File_ReadLine(&haveLine, lineBuffer, &lineLength, lineBufferLength, file);
        }
        /* out of lines and no match is error */
        if (rc == 0) {
            if (!haveLine) {
                if (verbose) fprintf(messageFile,
                                     "File_MapNameToValue: Error, missing value for %s\n", name);
                rc = ERROR_CODE;
            }
        }
        /* get subject, first token */
        if (rc == 0) {
            token = strtok(lineBuffer, "=");		/* get first token */
            if (token == NULL) {		/* malformed line */
                if (verbose) fprintf(messageFile,
                                     "File_MapNameToValue: Error, bad format, missing =\n");
                rc = ERROR_CODE;
            }
        }
        /* compare name */
        if (rc == 0) {
            irc = strcmp(name, token);
            if (irc == 0) {
                /* match, done */
                break;
            }
        }
    }
    while (rc == 0);

    if (rc == 0) {
        token = strtok(NULL,"" );	/* get next token, rest of string */
        if (token == NULL) {		/* malformed line */
            if (verbose) fprintf(messageFile,
                                 "File_MapNameToValue: Error, bad format, missing value for %s\n",
                                 name);
            rc = ERROR_CODE;
        }
    }
    /* copy token to project file name */
    if (rc == 0) {
        rc = Malloc_Strcpy(value, token);
    }
    return rc;
}

/* File_MapNameToBool() scans lines from file of the form

   name=value

   if found, the value is checked for 'true' or 'false' and the boolean is returned.
   if not found, or the value is not true or false, an error is returned
*/

int File_MapNameToBool(int		*booln,
                       const char 	*name,
                       char 		*lineBuffer,
                       size_t 		lineBufferLength,
                       FILE		*file)
{
    int		rc = 0;
    char 	*booleanString = NULL;		/* freed @1 */

    if (rc == 0) {
        rc = File_MapNameToValue(&booleanString, /* freed by caller */
                                 name,
                                 lineBuffer,
                                 lineBufferLength,
                                 file);
    }
    /* look for true or false, no other string */
    if (rc == 0) {
        if (strcmp(booleanString, "true") == 0) {
            *booln = TRUE;
        }
        else if (strcmp(booleanString, "false") == 0) {
            *booln = FALSE;
        }
        else {
            if (verbose) fprintf(messageFile,
                                 "File_MapNameToBool: Error mapping %s, value is %s\n",
                                 name, booleanString);
            rc = ERROR_CODE;
        }
    }
    free(booleanString);	/* @1 */
    return rc;
}

/* File_MapNameToUint() scans lines from file of the form

   name=value

   if found, the value is checked for an unsigned integer and the integer is returned.
   if not found, or the value is not an unsigned integer, an error is returned
*/

int File_MapNameToUint(unsigned int	*value,
                       const char 	*name,
                       char 		*lineBuffer,
                       size_t 		lineBufferLength,
                       FILE		*file)
{
    int		rc = 0;
    int 	irc;
    char 	*intString = NULL;	/* freed @1 */
    char 	dummy;			/* extra characters at the end of the line */

    if (rc == 0) {
        rc = File_MapNameToValue(&intString, /* freed by caller */
                                 name,
                                 lineBuffer,
                                 lineBufferLength,
                                 file);
    }
    /* look for unsigned int, no other string */
    if (rc == 0) {
        irc = sscanf(intString, "%u%c", value, &dummy);
        if (irc != 1) {
            /* when this function returns an error, set the value to 0 so that the later delete
               doesn't think there are items to free */
            *value = 0;
            if (verbose) fprintf(messageFile,
                                 "File_MapNameToUint: Error mapping %s, value is %s\n",
                                 name, intString);
            rc = ERROR_CODE;
        }
    }
    free(intString);	/* @1 */
    return rc;
}

/* File_GetNameValueArray() parses the rest of 'file' for name=value pairs.

   It allocates the 'names' and 'values' arrays and fills in the elements

   lineBuffer is a temporary, to hold lines.
*/

int File_GetNameValueArray(char ***names,	/* freed by caller */
                           char ***values,	/* freed by caller */
                           size_t *length,	/* final length of the array */
                           char *lineBuffer,
                           size_t lineBufferLength,
                           FILE *file)
{
    int		rc = 0;
    int 	haveLine = TRUE;
    char	*name = NULL;
    char	*value = NULL;
    char 	*tmp;				/* used by realloc */

    *length = 0;

    /* check that names and values are NULL at entry, sanity check for memory leak */
    if (rc == 0) {
        if (names == NULL ||
            values == NULL) {
            if (verbose) fprintf(messageFile,
                                 "File_GetNameValueArray: names %p or values %p are NULL\n",
                                 names, values);
            rc = 1;
        }
        else if ((*names != NULL) || (*values != NULL)) {
            if (verbose) fprintf(messageFile,
                                 "File_GetNameValueArray: names %p or values %p not NULL\n",
                                 *names, *values);
            rc = 1;
        }
    }
    while ((rc == 0) && haveLine) {
        name = NULL;
        value = NULL;
        /* get a name - value pair */
        if (rc == 0) {
            rc = File_GetNameValue(&haveLine,
                                   &name,	/* freed by caller */
                                   &value,	/* freed by caller */
                                   lineBuffer,
                                   lineBufferLength,
                                   file);
        }
        /* if found a pair */
        if ((rc == 0) && haveLine) {
            /* increase the array size */
            (*length)++;
            /* grow the names array */
            tmp = realloc(*names, *length * sizeof(char *));
            if (tmp != NULL) {
                *names = (char **)tmp;
            }
            else {
                if (verbose) fprintf(messageFile,
                                     "File_GetNameValueArray: "
                                     "Error allocating memory for %u names\n",
                                     (unsigned int)*length);
                rc = ERROR_CODE;
            }
        }
        if ((rc == 0) && haveLine) {
            /* grow the values array */
            tmp = realloc(*values, *length * sizeof(char *));
            if (tmp != NULL) {
                *values = (char **)tmp;
            }
            else {
                if (verbose) fprintf(messageFile,
                                     "File_GetNameValueArray: "
                                     "Error allocating memory for %u values\n",
                                     (unsigned int)*length);
                rc = ERROR_CODE;
            }
        }
        if ((rc == 0) && haveLine) {
            /* assign name and value to array */
            (*names)[(*length) - 1] = name;
            (*values)[(*length) - 1] = value;
        }
    }
    return rc;
}

/* File_GetValueArray() parses 'file' for values.

   The number of values is determined by the first line, which is of the form

   'name'=integer

   It allocates the 'values' array and fills in the elements.
*/

int File_GetValueArray(char 		***values,	/* freed by caller */
                       size_t 		*length,	/* items in the array */
                       const char 	*name,
                       char 		*lineBuffer,
                       size_t 		lineBufferLength,
                       FILE 		*file)
{
    int		rc = 0;
    size_t	i;
    int 	haveLine = TRUE;
    size_t 	lineLength;

    *length = 0;

    /* check that values is NULL at entry, sanity check for memory leak */
    if (rc == 0) {
        if (*values != NULL) {
            if (verbose) fprintf(messageFile,
                                 "File_GetNameValueArray: values %p not NULL\n",
                                 *values);
        }
    }
    /* get the count of values in the array */
    if (rc == 0) {
        rc = File_MapNameToUint((unsigned int *)length,
                                name,
                                lineBuffer,
                                lineBufferLength,
                                file);
    }
    /* allocate the array for the values */
    if (rc == 0) {
        rc = Malloc_Safe((unsigned char **)values,	/* freed by caller */
                         *length * sizeof(char *),
                         *length * sizeof(char *));	/* trust the configuration file */
    }
    /* immediately NULL the array so it can be freed */
    for (i = 0 ; (rc == 0) && (i < *length) ; i++) {
        (*values)[i] = NULL;
    }
    /* for each expected value in the array */
    for (i = 0 ; (rc == 0) && (i < *length) ; i++) {
        /* each line is a value */
        if (rc == 0) {
            rc = File_ReadLine(&haveLine, lineBuffer, &lineLength, lineBufferLength, file);
        }
        /* insufficient lines is an error */
        if (rc == 0) {
            if (!haveLine) {
                if (verbose) fprintf(messageFile,
                                     "File_GetValueArray: Error, not %u entries for %s\n",
                                     (unsigned int)*length, name);
                rc = ERROR_CODE;
            }
        }
        /* allocate memory for the value and copy into the array entry */
        if (rc == 0) {
            rc = Malloc_Strcpy(&((*values)[i]), lineBuffer);	/* freed by caller */
        }
    }
    return rc;
}

/* File_LogTime() adds the current date and time to 'logFile'
 */

void File_LogTime(FILE *logFile)
{
    time_t      log_time;
    log_time = time(NULL);
    fprintf(logFile, "\n%s", ctime(&log_time));
    return;
}

/* File_Printf() does an fprintf of the same parameters to both lFile (typically a log file) and
   mfile (typically the messageFile, the output body).

   lFile is prefixed by a tab character.

   If either is NULL, that file is skipped.
*/

void File_Printf(FILE *lFile,
                 FILE *mFile,
                 const char *format,
                 ...)
{
    va_list va;

    va_start(va, format);

    /* print to the log file if it's not NULL */
    if (lFile != NULL) {
        fprintf(lFile,"\t");
        va_start(va, format);
        vfprintf(lFile, format, va);
        va_end(va);
    }
    /* print to the messages file if it's not NULL */
    if (mFile != NULL) {
        va_start(va, format);
        vfprintf(mFile, format, va);
        va_end(va);
    }
    return;
}

/* Arguments_Init() sets all elements of the argv array to NULL.

   This permits the free() to be safe.
*/

void Arguments_Init(Arguments *arguments)
{
    size_t	i;

    arguments->argvBytes = 0;
    for (i = 0 ; i < MAX_ARGV_BODY ; i++) {
        arguments->argv[i] = NULL;
    }
    return;
}

/* Argvuments_Delete() frees all elements of argv and sets them back to NULL.

   Secret values are cleared before the memory is freed.  These are currently:

   -pwd
*/

void Arguments_Delete(Arguments *arguments)
{
    size_t	i;

    /* clear the plaintext password */
    Arguments_ClearSecret("-pwd", arguments);
    /* free allocated memory */
    for (i = 0 ; i < MAX_ARGV_BODY ; i++) {
        free(arguments->argv[i]);
        arguments->argv[i] = NULL;
    }
    return;
}

/* Arguments_ClearSecret() looks for 'flag' and zeros the value associated with the flag
 */

void Arguments_ClearSecret(const char 	*flag,
                           Arguments *arguments)
{
    size_t	i;
    size_t	length;
    int		irc;

    /* start at 1, argvBody[0] is the name of the program, not a flag */
    for (i = 1 ; i < (size_t)arguments->argc ; i++) {
        irc = strcmp(arguments->argv[i], flag);
        if (irc == 0) {		/* found a flag match */
            i++;		/* advance past the flag to the value */
            length = strlen(arguments->argv[i]);
            memset(arguments->argv[i], '\0', length);
        }
    }
    return;
}

/* Arguments_AddPairTo() adds the C strings 'flag' and 'value' pair to argv.  argc and argvBytes are
   updated accordingly.
*/

int Arguments_AddPairTo(Arguments *arguments,
                        const char 	*flag,
                        const char 	*value)
{
    int		rc = 0;

    /* check flag format */
    if (rc == 0) {
    }
    /* add flag */
    if (rc == 0) {
        rc = Arguments_AddTo(arguments,
                             flag, FALSE);
    }
    /* add value */
    if (rc == 0) {
        rc = Arguments_AddTo(arguments,
                             value, FALSE);
    }
    return rc;
}

/* Arguments_AddTo() adds the C string 'data' to argvBody.  argvBytes is updated accordingly.

   If zero is TRUE, the item is added at argv[0].  If FALSE, the item is added at the end and argc
   is updated accordingly.

   'zero' handles the speccial case of the program name.
*/

int Arguments_AddTo(Arguments 	*arguments,
                    const char 	*data,
                    int zero)
{
    int		rc = 0;
    size_t	i;
    size_t	length;

    /* check for NULL argument */
    if (rc == 0) {
        if (data == NULL) {
            if (verbose) fprintf(messageFile,
                                 "Arguments_AddTo: Error, adding NULL argument\n");
            rc = ERROR_CODE;
        }
    }
    /* check for array overflow */
    if (rc == 0) {
        length = strlen(data);
    }
    /* check data for illegal characters */
    for (i = 0 ; (rc == 0) && (i < length) ; i++) {
        if (!isprint(data[i])) {
            if (verbose) fprintf(messageFile,
                                 "Arguments_AddTo: Error, argument not printable at index %u\n",
                                 (unsigned int)i);
            rc = ERROR_CODE;
        }
    }
    /* check for array overflow.  This is a framwork compile time limitation.  The -1 reserves the
       last entry as a NULL, needed by exec() */
    if ((rc == 0) && !zero) {
        if (arguments->argc > (MAX_ARGV_BODY-1)) {
            if (verbose) fprintf(messageFile,
                                 "Arguments_AddTo: Error, overflows array of %u entries\n",
                                 MAX_ARGV_BODY);
            rc = ERROR_CODE;

        }
    }
    /* check for total bytes overflow.  This is a platform OS limitation */
    if (rc == 0) {
        if ((arguments->argvBytes + length) > ARG_MAX) {
            if (verbose) fprintf(messageFile,
                                 "Arguments_AddTo: Error, %s overflows argument list length\n",
                                 data);
            rc = ERROR_CODE;
        }
    }
    /* malloc and copy */
    if (rc == 0) {
        if (!zero) {
            rc = Malloc_Strcpy(&(arguments->argv[arguments->argc]), data);
        }
        else {
            rc = Malloc_Strcpy(&(arguments->argv[0]), data);
        }
    }
    if (rc == 0) {
        if (!zero) {
            arguments->argc++;		/* adjust the argument count */
        }
        arguments->argvBytes += length;	/* adjust the total number of bytes */
    }
    return rc;
}

/* Arguments_GetFrom() iterates through arguments->argv, searching for flag.

   If found, the value is returned.  The value is a pointer into arguments->argv.  It is not
   allocated and should not be freed.

   If not found, an error is returned.
*/

int Arguments_GetFrom(const char 	**value,
                      const char 	*flag,
                      Arguments		*arguments)
{
    int		rc = 0;
    int 	irc;
    int		i;
    int 	found = FALSE;

    /* start with [1], [0] is the program name, not a command line argument */
    for (i = 1 ; !found && (i < arguments->argc) ; i++) {
        irc = strcmp(flag, arguments->argv[i]);
        if ((irc == 0) && ((i+1) < arguments->argc)) {	/* if a flag match */
            *value = arguments->argv[i+1];		/* return the value */
            found = TRUE;
        }
    }
    if (!found) {
        if (verbose) fprintf(messageFile, "Arguments_GetFrom: %s not found\n", flag);
        rc = ERROR_CODE;
    }
    return rc;
}

/*
  character array handling
*/

/* Array_GetLine() acts on a character array.

   It returns the next non-comment, non-whitespace line from the array.

   It replaces the white space at the end of a line with NUL.

   It also returns a pointer to the next line.

   Returns error if the line is too long or contains non-printable characters.
*/

int Array_GetLine(int *haveLine,		/* TRUE if line returned, otherwise FALSE */
                  char *outLine,		/* returned line */
                  const char **nextLine, 	/* returned pointer to next line */
                  size_t lineSize,		/* max size of line buffer */
                  const char *inLines,		/* input character array */
                  FILE *logFile)		/* audit log file */
{
    int 	rc = 0;
    size_t	i = 0;		/* index into outLine */
    const char 	*ptr;

    *haveLine = FALSE;
    ptr = inLines;	/* starting point */

    /* skip comment lines or lines beginning with whitespace */
    if (rc == 0) {
        /* skip comment lines or lines beginning with whitespace */
        while ((*ptr == '#') ||
               (isspace(*ptr))) {

            /* if the line should be ignored, search for next newline, then increment past it */
            for ( ; *ptr != '\0' ; ptr++) {
                if (*ptr == '\n') {
                    ptr++;	/* point to next line and loop back to check for skip */
                    break;
                }
            }
        }
        /* found another line (or at the end of the buffer)  */
        /* scan to the end of the current line or the end of the buffer */
        while ((*ptr != '\0') && (*ptr != '\n')) {

            *haveLine = TRUE;

            /* check for overflow, leave space for NUL */
            if (i == (lineSize-1)) {
                outLine[lineSize-1] = '\0';	/* terminate the line for error message */
                File_Printf(logFile, messageFile,
                            "Error, Line is longer than %u bytes: %s\n",
                            lineSize, outLine);
                if (verbose) fprintf(messageFile,
                                     "Array_GetLine: Error, Line is longer than %u bytes: %s\n",
                                     (unsigned int)lineSize, outLine);
                rc = ERROR_CODE;
                break;
            }
            /* scan for non-printable characters */
            if (!isprint(*ptr)) {
                outLine[i] = '\0';		/* terminate the line for error message */
                File_Printf(logFile, messageFile,
                            "Error, Line %s has non-printable character at index %u\n",
                            outLine, i);
                if (verbose) fprintf(messageFile,
                                     "Array_GetLine: "
                                     "Error, Line %s has non-printable character at index %u\n",
                                     outLine, (unsigned int)i);
                rc = ERROR_CODE;
                break;
            }
            /* character valid, copy from input array to output line */
            outLine[i] = *ptr;
            ptr++;	/* next input character */
            i++;	/* next output character */
        }
    }
    /* set next line */
    if (rc == 0) {
        if (*ptr == '\0') {	/* if finished, just point to NUL terminator for input array */
            *nextLine = ptr;
        }
        else {
            *nextLine = ptr+1;	/* if more lines, point past newline */
        }
    }
    if ((rc == 0) && *haveLine) {
        outLine[i] = '\0';		/* terminate the line */
        i--;	/* search back from last character */
        /* strip off white space at the end of the line */
        for ( ; (i > 0) && isspace(outLine[i]) ; i--) {
            outLine[i] = '\0';
        }
        if (outLine[0] == '\0') {
            if (verbose) fprintf(messageFile,
                                 "Array_GetLine: Error: Line has only whitespace\n");
            rc = ERROR_CODE;	/* this should never occur, line with all whitespace should be
                                   ignored */
        }
    }
    return rc;
}

/* Malloc_Strcpy() malloc's an array for the 'in' string and then copies the string and the
   terminating NUL */

int Malloc_Strcpy(char 		**out,		/* freed by caller */
                  const char 	*in)
{
    int		rc = 0;

    /* malloc for the data */
    if (rc == 0) {
        rc = Malloc_Safe((unsigned char **)out,
                         strlen(in) + 1,
                         strlen(in) + 1);	/* trust configuration files */
    }
    /* copy the data */
    if (rc == 0) {
        strcpy(*out, in);
    }
    return rc;
}

/* Malloc_Safe() is a wrapper around malloc that detects memory leaks, uninitialized pointers, or an
   unreasonably large request */

int Malloc_Safe(unsigned char **ptr, size_t len, size_t max_length)
{
    int rc = 0;

    if (rc == 0) {
        if (len > max_length) {
            if (verbose) fprintf(messageFile,
                                 "Malloc_Safe: Error, length %u too large\n", (unsigned int)len);
            rc = ERROR_CODE;
        }
    }
    if (rc == 0) {
        if (*ptr != NULL) {
            if (verbose) fprintf(messageFile,
                                 "Malloc_Safe: Error, pointer is not NULL : %p\n", *ptr);
            rc = ERROR_CODE;
        }
    }
    if (rc == 0) {
        *ptr = malloc(len);
        if (*ptr == NULL) {
            if (verbose) fprintf(messageFile,
                                 "Malloc_Safe: Error, could not allocate %u bytes : %p\n", (unsigned int)len, *ptr);
            rc = ERROR_CODE;
        }
    }
    return rc;
}

/* Realloc_Safe() is a general purpose wrapper around realloc()

   The caller is responsible for validating that 'size' is reasonable.
*/

int Realloc_Safe(unsigned char **buffer,
                 size_t size)
{
    int 		rc = 0;
    unsigned char       *tmpptr = NULL;

    if (rc == 0) {
        tmpptr = realloc(*buffer, size);
        if (tmpptr == NULL) {
            if (verbose) fprintf(messageFile,
                                 "Realloc_Safe: Error reallocating %u bytes\n", (unsigned int)size);
            rc = ERROR_CODE;
        }
    }
    if (rc == 0) {
        *buffer = tmpptr;
    }
    return rc;
}

/*
  Format Conversion
*/

/* Format_ToHexascii() converts binary to hex ascii and appends a NUL terminator */

void Format_ToHexascii(char *string,
                       unsigned char *binary,
                       size_t length)
{
    size_t	i;

    for (i = 0 ; i < length ; i++, binary++, string += 2) {
        sprintf(string, "%02x", *binary);
    }
    return;
}

/* Format_FromHexAscii() converts 'string' in hex ascii to 'binary' of 'length'

   It assumes that the string has enough bytes to accommodate the length.
*/

int Format_FromHexascii(unsigned char *binary,
                        const char *string,
                        size_t length)
{
    int 	rc = 0;
    size_t	i;

    for (i = 0 ; (rc == 0) && (i < length) ; i++) {
        rc = Format_ByteFromHexascii(binary + i,
                                     string + (i * 2));

    }
    return rc;
}

/* Format_ByteFromHexAscii() converts two bytes of hex ascii to one byte of binary
 */

int Format_ByteFromHexascii(unsigned char *byte,
                            const char *string)
{
    int 	rc = 0;
    size_t	i;
    char	c;
    *byte 	= 0;

    for (i = 0 ; (rc == 0) && (i < 2) ; i++) {
        (*byte) <<= 4;		/* big endian, shift up the nibble */
        c = *(string + i);	/* extract the next character from the string */

        if ((c >= '0') && (c <= '9')) {
            *byte += c - '0';
        }
        else if ((c >= 'a') && (c <= 'f')) {
            *byte += c + 10 - 'a';
        }
        else if ((c >= 'A') && (c <= 'F')) {
            *byte += c + 10 - 'A';
        }
        else {
            if (verbose) fprintf(messageFile,
                                 "Format_ByteFromHexascii: "
                                 "Error: Line has non hex ascii character: %c\n", c);
            rc = ERROR_CODE;
        }
    }
    return rc;
}
