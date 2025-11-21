/**==============================================
 *                 main.c
 *  main code of the epiCompiler
 *  Author: shirosaaki
 *  Date: 2025-11-20
 *=============================================**/

#include "../includes/epi_compiler.h"

static const char *tokname(TokenType t)
{
    switch (t) {
        case TOK_IDENTIFIER: return "IDENT";
        case TOK_NUMBER: return "NUMBER";
        case TOK_STRING: return "STRING";
        case TOK_OPERATOR: return "OP";
        case TOK_SYMBOL: return "SYM";
        case TOK_KEYWORD: return "KW";
        case TOK_NEWLINE: return "NEWLINE";
        case TOK_INDENT: return "INDENT";
        case TOK_DEDENT: return "DEDENT";
        case TOK_EOF: return "EOF";
        case TOK_UNKNOWN: return "UNK";
        default: return "?";
    }
}

int main(int ac, char **av)
{
    if (ac != 3) {
        fprintf(stderr, "Usage: %s <source_file> <output_file>\n", av[0]);
        return EXIT_FAILURE;
    }

    const char *source_file = av[1];
    printf("Compiling source file: %s\n", source_file);

    const char *output_file = av[2];
    printf("Output file: %s\n", output_file);

    // Compilation logic would go here
    create_elf_header(output_file);

    TokenList tokens;
    LexError err;
    if (lexer_tokenize_file(source_file, &tokens, &err) != 0) {
        fprintf(stderr, "Lexing error at line %zu, column %zu: %s\n", err.line, err.column, err.message);
        lex_error_free(&err);
        return EXIT_FAILURE;
    }

    /* Print recognized tokens */
    for (size_t i = 0; i < tokens.count; ++i) {
        Token *t = &tokens.items[i];
        printf("%04zu %6s %-20s (%zu:%zu)\n", i, tokname(t->type), t->lexeme ? t->lexeme : "", t->line, t->column);
        if (t->type == TOK_EOF) break;
    }

    lexer_free_tokens(&tokens);

    printf("Compilation finished successfully.\n");
    return EXIT_SUCCESS;
}
