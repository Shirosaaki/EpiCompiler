/**==============================================
 *                 parser.h
 *  AST and Parser definitions
 *  Author: shirosaaki
 *  Date: 2025-11-27
 *=============================================**/

#ifndef PARSER_H_
    #define PARSER_H_
    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>
    #include "token.h"

/* ========== AST Node Types ========== */
typedef enum ASTNodeType {
    AST_PROGRAM,
    AST_FUNCTION_DEF,
    AST_VAR_DECL,
    AST_ASSIGNMENT,
    AST_RETURN,
    AST_PRINT,
    AST_IF,
    AST_ELSE,
    AST_WHILE,
    AST_FOR,
    AST_BLOCK,
    AST_BINARY_OP,
    AST_UNARY_OP,
    AST_IDENTIFIER,
    AST_NUMBER,
    AST_STRING,
    AST_FUNC_CALL,
    AST_COMMENT
} ASTNodeType;

/* ========== Data Types ========== */
typedef enum DataType {
    TYPE_INT,
    TYPE_FLOAT,
    TYPE_STRING,
    TYPE_VOID,
    TYPE_CHAR,
    TYPE_UNKNOWN
} DataType;

/* ========== AST Node Structure ========== */
typedef struct ASTNode ASTNode;

typedef struct ASTNodeList {
    ASTNode **items;
    size_t count;
    size_t capacity;
} ASTNodeList;

/* Function parameter */
typedef struct FuncParam {
    char *name;
    DataType type;
} FuncParam;

typedef struct FuncParamList {
    FuncParam *items;
    size_t count;
    size_t capacity;
} FuncParamList;

/* AST Node */
struct ASTNode {
    ASTNodeType type;
    size_t line;
    size_t column;

    union {
        /* AST_PROGRAM */
        struct {
            ASTNodeList functions;
        } program;

        /* AST_FUNCTION_DEF */
        struct {
            char *name;
            FuncParamList params;
            DataType return_type;
            ASTNodeList body;
        } func_def;

        /* AST_VAR_DECL */
        struct {
            char *name;
            DataType var_type;
            ASTNode *init_value;  /* can be NULL if no initialization */
        } var_decl;

        /* AST_ASSIGNMENT */
        struct {
            char *var_name;
            ASTNode *value;
        } assignment;

        /* AST_RETURN */
        struct {
            ASTNode *value;
        } return_stmt;

        /* AST_PRINT */
        struct {
            ASTNode *value;
        } print_stmt;

        /* AST_IF, AST_WHILE */
        struct {
            ASTNode *condition;
            ASTNodeList body;
            ASTNodeList else_body;  /* for else clause */
        } conditional;

        /* AST_FOR */
        struct {
            char *var_name;
            ASTNode *start;
            ASTNode *end;
            ASTNode *step;  /* can be NULL, defaults to 1 */
            ASTNodeList body;
        } for_loop;

        /* AST_BLOCK */
        struct {
            ASTNodeList statements;
        } block;

        /* AST_BINARY_OP */
        struct {
            char *op;
            ASTNode *left;
            ASTNode *right;
        } binary_op;

        /* AST_UNARY_OP */
        struct {
            char *op;
            ASTNode *operand;
        } unary_op;

        /* AST_IDENTIFIER */
        struct {
            char *name;
        } identifier;

        /* AST_NUMBER */
        struct {
            double value;
            int is_float;
        } number;

        /* AST_STRING */
        struct {
            char *value;
        } string;

        /* AST_FUNC_CALL */
        struct {
            char *name;
            ASTNodeList args;
        } func_call;

        /* AST_COMMENT */
        struct {
            char *text;
        } comment;
    } data;
};

/* ========== Parser State ========== */
typedef struct Parser {
    TokenList *tokens;
    size_t pos;
    char *error_msg;
    size_t error_line;
    size_t error_col;
} Parser;

/* ========== Parser Functions ========== */
void parser_init(Parser *parser, TokenList *tokens);
void parser_free(Parser *parser);

/* Parse the entire program */
ASTNode *parser_parse(Parser *parser);

/* Free AST nodes */
void ast_free(ASTNode *node);

/* AST Node List helpers */
void ast_list_init(ASTNodeList *list);
void ast_list_free(ASTNodeList *list);
int ast_list_push(ASTNodeList *list, ASTNode *node);

/* Function param list helpers */
void param_list_init(FuncParamList *list);
void param_list_free(FuncParamList *list);
int param_list_push(FuncParamList *list, FuncParam param);

/* Utility to convert type string to DataType */
DataType str_to_datatype(const char *str);
const char *datatype_to_str(DataType type);

/* Debug: print AST */
void ast_print(ASTNode *node, int indent);

#endif /* !PARSER_H_ */
