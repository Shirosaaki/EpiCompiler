/**==============================================
 *                 interpreter.h
 *  Interpreter definitions - executes AST
 *  Author: shirosaaki
 *  Date: 2025-11-27
 *=============================================**/

#ifndef INTERPRETER_H_
    #define INTERPRETER_H_
    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>
    #include "parser.h"

/* ========== Runtime Values ========== */
typedef enum ValueType {
    VAL_INT,
    VAL_FLOAT,
    VAL_STRING,
    VAL_VOID,
    VAL_ARRAY,  /* Array type */
    VAL_RETURN  /* Special type for return statements */
} ValueType;

/* Array structure for runtime */
typedef struct ArrayValue {
    struct Value *elements;
    size_t size;
    size_t capacity;
    ValueType element_type;  /* Type of elements in array */
} ArrayValue;

typedef struct Value {
    ValueType type;
    union {
        long int_val;
        double float_val;
        char *string_val;
        ArrayValue *array_val;
    } data;
    int is_return;  /* Flag for return value propagation */
} Value;

/* ========== Variable Storage ========== */
typedef struct Variable {
    char *name;
    Value value;
    DataType declared_type;
} Variable;

typedef struct VarScope {
    Variable *vars;
    size_t count;
    size_t capacity;
    struct VarScope *parent;  /* For nested scopes */
} VarScope;

/* ========== Function Storage ========== */
typedef struct FuncDef {
    char *name;
    ASTNode *ast_node;  /* Points to AST_FUNCTION_DEF */
} FuncDef;

typedef struct FuncRegistry {
    FuncDef *funcs;
    size_t count;
    size_t capacity;
} FuncRegistry;

/* ========== Interpreter State ========== */
typedef struct Interpreter {
    FuncRegistry functions;
    VarScope *current_scope;
    char *error_msg;
    size_t error_line;
    int exit_code;
    int has_returned;
    int has_break;      /* Flag for break statement */
    int has_continue;   /* Flag for continue statement */
} Interpreter;

/* ========== Interpreter Functions ========== */
void interpreter_init(Interpreter *interp);
void interpreter_free(Interpreter *interp);

/* Execute an AST program and return exit code */
int interpreter_run(Interpreter *interp, ASTNode *program);

/* Value utilities */
Value value_create_int(long val);
Value value_create_float(double val);
Value value_create_string(const char *val);
Value value_create_void(void);
Value value_create_array(ValueType element_type);
void value_free(Value *val);
void value_print(Value *val);
char *value_to_string(Value *val);

/* Array utilities */
void array_set_element(ArrayValue *arr, size_t index, Value val);
Value array_get_element(ArrayValue *arr, size_t index);

/* Scope management */
VarScope *scope_create(VarScope *parent);
void scope_free(VarScope *scope);
int scope_set_var(VarScope *scope, const char *name, Value val, DataType type);
Variable *scope_get_var(VarScope *scope, const char *name);

#endif /* !INTERPRETER_H_ */
