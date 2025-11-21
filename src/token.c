/**==============================================
 *                 token.c
 *  token
 *  Author: shirosaaki
 *  Date: 2025-11-21
 *=============================================**/
#include "../includes/token.h"

static void ensure_capacity(TokenList *list, size_t min_cap)
{
    if (list->capacity >= min_cap) return;
    size_t newcap = list->capacity ? list->capacity * 2 : 16;
    while (newcap < min_cap) newcap *= 2;
    Token *newitems = realloc(list->items, newcap * sizeof(Token));
    if (!newitems) {
        fprintf(stderr, "Out of memory allocating tokens\n");
        exit(EXIT_FAILURE);
    }
    list->items = newitems;
    list->capacity = newcap;
}

void token_list_init(TokenList *list)
{
    list->items = NULL;
    list->count = 0;
    list->capacity = 0;
}

void token_list_free(TokenList *list)
{
    if (!list) return;
    for (size_t i = 0; i < list->count; ++i) {
        free(list->items[i].lexeme);
    }
    free(list->items);
    list->items = NULL;
    list->count = 0;
    list->capacity = 0;
}

int token_list_push(TokenList *list, Token token)
{
    ensure_capacity(list, list->count + 1);
    list->items[list->count++] = token;
    return 0;
}

Token token_create(TokenType type, char *lexeme, size_t line, size_t column)
{
    Token t;
    t.type = type;
    t.lexeme = lexeme;
    t.line = line;
    t.column = column;
    return t;
}
