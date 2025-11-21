/**==============================================
 *                 token.h
 *  token header
 *  Author: shirosaaki
 *  Date: 2025-11-21
 *=============================================**/

#ifndef TOKEN_H_
    #define TOKEN_H_
    #include <stddef.h>
    #include <stdlib.h>
    #include <string.h>
    #include <stdio.h>

typedef enum TokenType {
    TOK_IDENTIFIER,
    TOK_NUMBER,
    TOK_STRING,
    TOK_OPERATOR,
    TOK_SYMBOL,
    TOK_KEYWORD,
    TOK_NEWLINE,
    TOK_INDENT,
    TOK_DEDENT,
    TOK_EOF,
    TOK_UNKNOWN
} TokenType;

typedef struct Token {
    TokenType type;
    char *lexeme;
    size_t line;
    size_t column;
} Token;

typedef struct TokenList {
    Token *items;
    size_t count;
    size_t capacity;
} TokenList;

/* TokenList helpers */
void token_list_init(TokenList *list);
void token_list_free(TokenList *list);
int token_list_push(TokenList *list, Token token);

/* Utility to create token (caller should strdup lexeme when required) */
Token token_create(TokenType type, char *lexeme, size_t line, size_t column);

#endif /* !TOKEN_H_ */
