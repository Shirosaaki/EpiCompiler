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
    AST_CONST_DECL,        /* cz - constant declaration */
    AST_ENUM_DEF,          /* desnum - enum definition */
    AST_STRUCT_DEF,        /* destruct - struct definition */
    AST_ASSIGNMENT,
    AST_ARRAY_ACCESS,      /* Array element access: arr[index] */
    AST_ARRAY_ASSIGN,      /* Array element assignment: arr[index] = value */
    AST_DEREF,             /* Pointer dereference: *ptr */
    AST_DEREF_ASSIGN,      /* Pointer dereference assignment: *ptr = value */
    AST_ADDRESS_OF,        /* Address-of operator: &var */
    AST_STRUCT_ACCESS,     /* Struct field access: struct.field */
    AST_STRUCT_ASSIGN,     /* Struct field assignment: struct.field = value */
    AST_RETURN,
    AST_PRINT,
    AST_IF,
    AST_ELSE,
    AST_WHILE,
    AST_FOR,
    AST_BREAK,             /* deschreak - break out of loop */
    AST_CONTINUE,          /* deschontinue - skip to next iteration */
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
    TYPE_INT_ARRAY,        /* int[] */
    TYPE_FLOAT_ARRAY,      /* float[] */
    TYPE_STRING_ARRAY,     /* string[] */
    TYPE_CHAR_ARRAY,       /* char[] */
    TYPE_INT_PTR,          /* int* */
    TYPE_FLOAT_PTR,        /* float* */
    TYPE_STRING_PTR,       /* string* */
    TYPE_CHAR_PTR,         /* char* */
    TYPE_VOID_PTR,         /* void* */
    TYPE_STRUCT_PTR,       /* StructName* */
    TYPE_UNKNOWN
} DataType;

/* ========== AST Node Structure ========== */
typedef struct ASTNode ASTNode;

typedef struct ASTNodeList {
    ASTNode **items;
    size_t count;
    size_t capacity;
} ASTNodeList;

/* Struct field definition */
typedef struct StructField {
    char *name;
    DataType type;
} StructField;

typedef struct StructFieldList {
    StructField *items;
    size_t count;
    size_t capacity;
} StructFieldList;

/* Function parameter */
typedef struct FuncParam {
    char *name;
    DataType type;
    char *struct_type_name;  /* For struct and struct pointer types */
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
            ASTNodeList constants;  /* Global constants (cz) */
            ASTNodeList enums;      /* Enum definitions (desnum) */
            ASTNodeList structs;    /* Struct definitions (destruct) */
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
            char *struct_type_name;  /* For struct types: name of the struct */
            ASTNode *init_value;  /* can be NULL if no initialization */
        } var_decl;

        /* AST_ASSIGNMENT */
        struct {
            char *var_name;
            ASTNode *value;
        } assignment;

        /* AST_ARRAY_ACCESS: arr[index] */
        struct {
            char *array_name;
            ASTNode *index;
        } array_access;

        /* AST_ARRAY_ASSIGN: arr[index] = value */
        struct {
            char *array_name;
            ASTNode *index;
            ASTNode *value;
        } array_assign;

        /* AST_DEREF: *ptr (read through pointer) */
        struct {
            ASTNode *operand;  /* The pointer expression */
        } deref;

        /* AST_DEREF_ASSIGN: *ptr = value (write through pointer) */
        struct {
            ASTNode *ptr;      /* The pointer expression */
            ASTNode *value;    /* Value to write */
        } deref_assign;

        /* AST_ADDRESS_OF: &var (get address of variable) */
        struct {
            char *var_name;    /* Name of the variable to get address of */
        } address_of;

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

        /* AST_CONST_DECL: cz NAME = value -> type */
        struct {
            char *name;
            DataType const_type;
            ASTNode *value;
        } const_decl;

        /* AST_ENUM_DEF: desnum EnumName: Member1, Member2, ... */
        struct {
            char *name;
            char **members;     /* Array of member names */
            size_t member_count;
        } enum_def;

        /* AST_STRUCT_DEF: destruct StructName: field1 -> type1, field2 -> type2, ... */
        struct {
            char *name;
            StructFieldList fields;
        } struct_def;

        /* AST_STRUCT_ACCESS: struct.field or arr[i].field */
        struct {
            char *struct_name;
            char *field_name;
            ASTNode *array_index;  /* NULL if not array element, otherwise the index expression */
        } struct_access;

        /* AST_STRUCT_ASSIGN: struct.field = value or arr[i].field = value */
        struct {
            char *struct_name;
            char *field_name;
            ASTNode *value;
            ASTNode *array_index;  /* NULL if not array element, otherwise the index expression */
        } struct_assign;
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

/* Create an AST node */
ASTNode *ast_create(ASTNodeType type, size_t line, size_t col);

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

/* Struct field list helpers */
void struct_field_list_init(StructFieldList *list);
void struct_field_list_free(StructFieldList *list);
int struct_field_list_push(StructFieldList *list, StructField field);

/* Utility to convert type string to DataType */
DataType str_to_datatype(const char *str);
const char *datatype_to_str(DataType type);

/* Debug: print AST */
void ast_print(ASTNode *node, int indent);

#endif /* !PARSER_H_ */
