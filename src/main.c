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

static void print_usage(const char *prog)
{
    fprintf(stderr, "Usage: %s [options] <source_file>\n", prog);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -t, --tokens    Print tokens only (no compilation)\n");
    fprintf(stderr, "  -a, --ast       Print AST only (no compilation)\n");
    fprintf(stderr, "  -i, --interpret Interpret the program instead of compiling\n");
    fprintf(stderr, "  -o <file>       Output file for compilation (default: a.out)\n");
    fprintf(stderr, "  -h, --help      Show this help message\n");
}

int main(int ac, char **av)
{
    int print_tokens = 0;
    int print_ast = 0;
    int interpret_mode = 0;
    const char *source_file = NULL;
    const char *output_file = "a.out";

    /* Parse command line arguments */
    for (int i = 1; i < ac; ++i) {
        if (strcmp(av[i], "-t") == 0 || strcmp(av[i], "--tokens") == 0) {
            print_tokens = 1;
        } else if (strcmp(av[i], "-a") == 0 || strcmp(av[i], "--ast") == 0) {
            print_ast = 1;
        } else if (strcmp(av[i], "-i") == 0 || strcmp(av[i], "--interpret") == 0) {
            interpret_mode = 1;
        } else if (strcmp(av[i], "-o") == 0 && i + 1 < ac) {
            output_file = av[++i];
        } else if (strcmp(av[i], "-h") == 0 || strcmp(av[i], "--help") == 0) {
            print_usage(av[0]);
            return EXIT_SUCCESS;
        } else if (av[i][0] != '-') {
            source_file = av[i];
        } else {
            fprintf(stderr, "Unknown option: %s\n", av[i]);
            print_usage(av[0]);
            return EXIT_FAILURE;
        }
    }

    if (!source_file) {
        fprintf(stderr, "Error: No source file specified\n");
        print_usage(av[0]);
        return EXIT_FAILURE;
    }

    printf("EpiCompiler - Source: %s\n", source_file);
    printf("========================================\n");

    /* Lexical analysis */
    TokenList tokens;
    LexError err;
    if (lexer_tokenize_file(source_file, &tokens, &err) != 0) {
        fprintf(stderr, "Lexing error at line %zu, column %zu: %s\n",
                err.line, err.column, err.message);
        lex_error_free(&err);
        return EXIT_FAILURE;
    }

    /* Print tokens if requested */
    if (print_tokens) {
        printf("\n=== TOKENS ===\n");
        for (size_t i = 0; i < tokens.count; ++i) {
            Token *t = &tokens.items[i];
            printf("%04zu %6s %-20s (%zu:%zu)\n",
                   i, tokname(t->type), t->lexeme ? t->lexeme : "",
                   t->line, t->column);
            if (t->type == TOK_EOF) break;
        }
    }

    /* Parsing */
    Parser parser;
    parser_init(&parser, &tokens);

    ASTNode *program = parser_parse(&parser);

    if (parser.error_msg) {
        fprintf(stderr, "Parse error at line %zu, column %zu: %s\n",
                parser.error_line, parser.error_col, parser.error_msg);
        parser_free(&parser);
        lexer_free_tokens(&tokens);
        return EXIT_FAILURE;
    }

    /* Print AST if requested */
    if (print_ast) {
        printf("\n=== AST ===\n");
        ast_print(program, 0);
    }

    int exit_code = 0;

    if (interpret_mode) {
        /* Interpret the program */
        printf("\n=== INTERPRETING ===\n");
        Interpreter interp;
        interpreter_init(&interp);

        exit_code = interpreter_run(&interp, program);

        if (interp.error_msg) {
            fprintf(stderr, "Runtime error: %s\n", interp.error_msg);
        }

        printf("\n=== PROGRAM EXIT CODE: %d ===\n", exit_code);
        interpreter_free(&interp);
    } else if (!print_tokens && !print_ast) {
        /* Compile to ELF */
        printf("\n=== COMPILING ===\n");
        CodeGenerator codegen;
        codegen_init(&codegen);

        if (codegen_compile(&codegen, program) != 0) {
            fprintf(stderr, "Compilation error at line %zu: %s\n",
                    codegen.error_line, codegen.error_msg);
            codegen_free(&codegen);
            ast_free(program);
            parser_free(&parser);
            lexer_free_tokens(&tokens);
            return EXIT_FAILURE;
        }

        if (codegen_write_elf(&codegen, output_file) != 0) {
            fprintf(stderr, "Failed to write output file: %s\n", codegen.error_msg);
            codegen_free(&codegen);
            ast_free(program);
            parser_free(&parser);
            lexer_free_tokens(&tokens);
            return EXIT_FAILURE;
        }

        printf("Successfully compiled to: %s\n", output_file);
        printf("Code size: %zu bytes\n", codegen.code.size);
        printf("Data size: %zu bytes\n", codegen.data.size);
        
        codegen_free(&codegen);
    }

    /* Cleanup */
    ast_free(program);
    parser_free(&parser);
    lexer_free_tokens(&tokens);

    return exit_code;
}
