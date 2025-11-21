/**==============================================
 *                 lex_error.h
 *  lex_error header
 *  Author: shirosaaki
 *  Date: 2025-11-21
 *=============================================**/

#ifndef LEX_ERROR_H_
    #define LEX_ERROR_H_
    #include <stddef.h>
    #include <stdlib.h>
    #include <string.h>
    #include <stdio.h>

typedef struct LexError {
    char *message;
    size_t line;
    size_t column;
} LexError;

/* Create and free helpers */
LexError lex_error_create(const char *msg, size_t line, size_t column);
void lex_error_free(LexError *err);

#endif /* !LEX_ERROR_H_ */
