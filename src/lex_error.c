/**==============================================
 *                 lex_error.c
 *  lex_error
 *  Author: shirosaaki
 *  Date: 2025-11-21
 *=============================================**/
#include "../includes/lex_error.h"

LexError lex_error_create(const char *msg, size_t line, size_t column)
{
    LexError e;
    e.message = strdup(msg ? msg : "");
    e.line = line;
    e.column = column;
    return e;
}

void lex_error_free(LexError *err)
{
    if (!err) return;
    free(err->message);
    err->message = NULL;
}
