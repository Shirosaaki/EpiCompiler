/**==============================================
 *                 lexer.h
 *  lexer
 *  Author: shirosaaki
 *  Date: 2025-11-21
 *=============================================**/

#ifndef LEXER_H_
    #define LEXER_H_
    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>
    #include <ctype.h>
    #include "token.h"
    #include "lex_error.h"

/* Tokenize an input file. Returns 0 on success, non-zero on error. */
int lexer_tokenize_file(const char *filename, TokenList *out_tokens, LexError *out_err);

/* Free tokens' internal data (lexemes) */
void lexer_free_tokens(TokenList *list);

#endif /* !LEXER_H_ */
