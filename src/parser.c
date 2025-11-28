/**==============================================
 *                 parser.c
 *  Parser implementation - converts tokens to AST
 *  Author: shirosaaki
 *  Date: 2025-11-27
 *=============================================**/

#include "../includes/parser.h"

/* ========== Utility Functions ========== */

void ast_list_init(ASTNodeList *list)
{
    list->items = NULL;
    list->count = 0;
    list->capacity = 0;
}

void ast_list_free(ASTNodeList *list)
{
    for (size_t i = 0; i < list->count; ++i) {
        ast_free(list->items[i]);
    }
    free(list->items);
    list->items = NULL;
    list->count = 0;
    list->capacity = 0;
}

int ast_list_push(ASTNodeList *list, ASTNode *node)
{
    if (list->count >= list->capacity) {
        size_t new_cap = list->capacity == 0 ? 8 : list->capacity * 2;
        ASTNode **new_items = realloc(list->items, new_cap * sizeof(ASTNode *));
        if (!new_items) return -1;
        list->items = new_items;
        list->capacity = new_cap;
    }
    list->items[list->count++] = node;
    return 0;
}

void param_list_init(FuncParamList *list)
{
    list->items = NULL;
    list->count = 0;
    list->capacity = 0;
}

void param_list_free(FuncParamList *list)
{
    for (size_t i = 0; i < list->count; ++i) {
        free(list->items[i].name);
    }
    free(list->items);
    list->items = NULL;
    list->count = 0;
    list->capacity = 0;
}

int param_list_push(FuncParamList *list, FuncParam param)
{
    if (list->count >= list->capacity) {
        size_t new_cap = list->capacity == 0 ? 4 : list->capacity * 2;
        FuncParam *new_items = realloc(list->items, new_cap * sizeof(FuncParam));
        if (!new_items) return -1;
        list->items = new_items;
        list->capacity = new_cap;
    }
    list->items[list->count++] = param;
    return 0;
}

void struct_field_list_init(StructFieldList *list)
{
    list->items = NULL;
    list->count = 0;
    list->capacity = 0;
}

void struct_field_list_free(StructFieldList *list)
{
    for (size_t i = 0; i < list->count; ++i) {
        free(list->items[i].name);
    }
    free(list->items);
    list->items = NULL;
    list->count = 0;
    list->capacity = 0;
}

int struct_field_list_push(StructFieldList *list, StructField field)
{
    if (list->count >= list->capacity) {
        size_t new_cap = list->capacity == 0 ? 4 : list->capacity * 2;
        StructField *new_items = realloc(list->items, new_cap * sizeof(StructField));
        if (!new_items) return -1;
        list->items = new_items;
        list->capacity = new_cap;
    }
    list->items[list->count++] = field;
    return 0;
}

DataType str_to_datatype(const char *str)
{
    if (!str) return TYPE_UNKNOWN;
    if (strcmp(str, "int") == 0) return TYPE_INT;
    if (strcmp(str, "float") == 0) return TYPE_FLOAT;
    if (strcmp(str, "string") == 0) return TYPE_STRING;
    if (strcmp(str, "void") == 0) return TYPE_VOID;
    if (strcmp(str, "char") == 0) return TYPE_CHAR;
    if (strcmp(str, "int[]") == 0) return TYPE_INT_ARRAY;
    if (strcmp(str, "float[]") == 0) return TYPE_FLOAT_ARRAY;
    if (strcmp(str, "string[]") == 0) return TYPE_STRING_ARRAY;
    if (strcmp(str, "char[]") == 0) return TYPE_CHAR_ARRAY;
    if (strcmp(str, "int*") == 0) return TYPE_INT_PTR;
    if (strcmp(str, "float*") == 0) return TYPE_FLOAT_PTR;
    if (strcmp(str, "string*") == 0) return TYPE_STRING_PTR;
    if (strcmp(str, "char*") == 0) return TYPE_CHAR_PTR;
    return TYPE_UNKNOWN;
}

const char *datatype_to_str(DataType type)
{
    switch (type) {
        case TYPE_INT: return "int";
        case TYPE_FLOAT: return "float";
        case TYPE_STRING: return "string";
        case TYPE_VOID: return "void";
        case TYPE_CHAR: return "char";
        case TYPE_INT_ARRAY: return "int[]";
        case TYPE_FLOAT_ARRAY: return "float[]";
        case TYPE_STRING_ARRAY: return "string[]";
        case TYPE_CHAR_ARRAY: return "char[]";
        case TYPE_INT_PTR: return "int*";
        case TYPE_FLOAT_PTR: return "float*";
        case TYPE_STRING_PTR: return "string*";
        case TYPE_CHAR_PTR: return "char*";
        default: return "unknown";
    }
}

/* ========== AST Node Creation ========== */

ASTNode *ast_create(ASTNodeType type, size_t line, size_t col)
{
    ASTNode *node = calloc(1, sizeof(ASTNode));
    if (!node) return NULL;
    node->type = type;
    node->line = line;
    node->column = col;
    return node;
}

void ast_free(ASTNode *node)
{
    if (!node) return;

    switch (node->type) {
        case AST_PROGRAM:
            ast_list_free(&node->data.program.functions);
            ast_list_free(&node->data.program.constants);
            ast_list_free(&node->data.program.enums);
            ast_list_free(&node->data.program.structs);
            break;
        case AST_FUNCTION_DEF:
            free(node->data.func_def.name);
            param_list_free(&node->data.func_def.params);
            ast_list_free(&node->data.func_def.body);
            break;
        case AST_VAR_DECL:
            free(node->data.var_decl.name);
            free(node->data.var_decl.struct_type_name);
            ast_free(node->data.var_decl.init_value);
            break;
        case AST_ASSIGNMENT:
            free(node->data.assignment.var_name);
            ast_free(node->data.assignment.value);
            break;
        case AST_ARRAY_ACCESS:
            free(node->data.array_access.array_name);
            ast_free(node->data.array_access.index);
            break;
        case AST_ARRAY_ASSIGN:
            free(node->data.array_assign.array_name);
            ast_free(node->data.array_assign.index);
            ast_free(node->data.array_assign.value);
            break;
        case AST_RETURN:
            ast_free(node->data.return_stmt.value);
            break;
        case AST_PRINT:
            ast_free(node->data.print_stmt.value);
            break;
        case AST_IF:
        case AST_WHILE:
            ast_free(node->data.conditional.condition);
            ast_list_free(&node->data.conditional.body);
            ast_list_free(&node->data.conditional.else_body);
            break;
        case AST_FOR:
            free(node->data.for_loop.var_name);
            ast_free(node->data.for_loop.start);
            ast_free(node->data.for_loop.end);
            ast_free(node->data.for_loop.step);
            ast_list_free(&node->data.for_loop.body);
            break;
        case AST_BLOCK:
            ast_list_free(&node->data.block.statements);
            break;
        case AST_BINARY_OP:
            free(node->data.binary_op.op);
            ast_free(node->data.binary_op.left);
            ast_free(node->data.binary_op.right);
            break;
        case AST_UNARY_OP:
            free(node->data.unary_op.op);
            ast_free(node->data.unary_op.operand);
            break;
        case AST_IDENTIFIER:
            free(node->data.identifier.name);
            break;
        case AST_NUMBER:
            break;
        case AST_STRING:
            free(node->data.string.value);
            break;
        case AST_FUNC_CALL:
            free(node->data.func_call.name);
            ast_list_free(&node->data.func_call.args);
            break;
        case AST_COMMENT:
            free(node->data.comment.text);
            break;
        case AST_STRUCT_DEF: {
            free(node->data.struct_def.name);
            for (size_t i = 0; i < node->data.struct_def.fields.count; ++i) {
                free(node->data.struct_def.fields.items[i].name);
            }
            free(node->data.struct_def.fields.items);
            break;
        }
        case AST_STRUCT_ACCESS:
            free(node->data.struct_access.struct_name);
            free(node->data.struct_access.field_name);
            break;
        case AST_STRUCT_ASSIGN:
            free(node->data.struct_assign.struct_name);
            free(node->data.struct_assign.field_name);
            ast_free(node->data.struct_assign.value);
            break;
        case AST_DEREF:
            ast_free(node->data.deref.operand);
            break;
        case AST_DEREF_ASSIGN:
            ast_free(node->data.deref_assign.ptr);
            ast_free(node->data.deref_assign.value);
            break;
        case AST_ADDRESS_OF:
            free(node->data.address_of.var_name);
            break;
        case AST_CONST_DECL:
            free(node->data.const_decl.name);
            ast_free(node->data.const_decl.value);
            break;
        case AST_ENUM_DEF:
            free(node->data.enum_def.name);
            for (size_t i = 0; i < node->data.enum_def.member_count; ++i) {
                free(node->data.enum_def.members[i]);
            }
            free(node->data.enum_def.members);
            break;
        default:
            break;
    }
    free(node);
}

/* ========== Parser Implementation ========== */

void parser_init(Parser *parser, TokenList *tokens)
{
    parser->tokens = tokens;
    parser->pos = 0;
    parser->error_msg = NULL;
    parser->error_line = 0;
    parser->error_col = 0;
}

void parser_free(Parser *parser)
{
    free(parser->error_msg);
    parser->error_msg = NULL;
}

static Token *current(Parser *p)
{
    if (p->pos >= p->tokens->count) return NULL;
    return &p->tokens->items[p->pos];
}

static Token *peek(Parser *p, size_t ahead)
{
    size_t idx = p->pos + ahead;
    if (idx >= p->tokens->count) return NULL;
    return &p->tokens->items[idx];
}

static void advance(Parser *p)
{
    if (p->pos < p->tokens->count) p->pos++;
}

static void skip_newlines(Parser *p)
{
    while (current(p) && (current(p)->type == TOK_NEWLINE ||
           current(p)->type == TOK_INDENT || current(p)->type == TOK_DEDENT)) {
        if (current(p)->type == TOK_DEDENT) break;  /* Don't skip DEDENT */
        advance(p);
    }
}

static void skip_newlines_only(Parser *p)
{
    while (current(p) && current(p)->type == TOK_NEWLINE) {
        advance(p);
    }
}

static int match_keyword(Parser *p, const char *kw)
{
    Token *t = current(p);
    if (t && t->type == TOK_KEYWORD && t->lexeme && strcasecmp(t->lexeme, kw) == 0) {
        return 1;
    }
    return 0;
}

static int match_operator(Parser *p, const char *op)
{
    Token *t = current(p);
    if (t && t->type == TOK_OPERATOR && t->lexeme && strcmp(t->lexeme, op) == 0) {
        return 1;
    }
    return 0;
}

static void set_error(Parser *p, const char *msg, Token *t)
{
    if (p->error_msg) return;  /* Keep first error */
    p->error_msg = strdup(msg);
    if (t) {
        p->error_line = t->line;
        p->error_col = t->column;
    }
}

/* Forward declarations */
static ASTNode *parse_expression(Parser *p);
static ASTNode *parse_statement(Parser *p);
static void parse_block(Parser *p, ASTNodeList *body);

/* ========== Expression Parsing ========== */

static ASTNode *parse_primary(Parser *p)
{
    Token *t = current(p);
    if (!t) return NULL;

    /* Number */
    if (t->type == TOK_NUMBER) {
        ASTNode *node = ast_create(AST_NUMBER, t->line, t->column);
        node->data.number.value = atof(t->lexeme);
        node->data.number.is_float = (strchr(t->lexeme, '.') != NULL);
        advance(p);
        return node;
    }

    /* String */
    if (t->type == TOK_STRING) {
        ASTNode *node = ast_create(AST_STRING, t->line, t->column);
        node->data.string.value = strdup(t->lexeme);
        advance(p);
        return node;
    }

    /* Identifier or function call or array access */
    if (t->type == TOK_IDENTIFIER) {
        char *name = strdup(t->lexeme);
        size_t line = t->line, col = t->column;
        advance(p);

        /* Check if it's a function call */
        if (match_operator(p, "(")) {
            ASTNode *node = ast_create(AST_FUNC_CALL, line, col);
            node->data.func_call.name = name;
            ast_list_init(&node->data.func_call.args);
            advance(p);  /* consume '(' */

            /* Parse arguments */
            while (!match_operator(p, ")") && current(p)) {
                ASTNode *arg = parse_expression(p);
                if (arg) ast_list_push(&node->data.func_call.args, arg);

                if (match_operator(p, ",")) {
                    advance(p);
                } else {
                    break;
                }
            }

            if (match_operator(p, ")")) {
                advance(p);
            } else {
                set_error(p, "Expected ')' in function call", current(p));
            }
            return node;
        }
        
        /* Check if it's an array access: arr[index] */
        if (match_operator(p, "[")) {
            advance(p);  /* consume '[' */
            ASTNode *index = parse_expression(p);
            if (!match_operator(p, "]")) {
                set_error(p, "Expected ']' after array index", current(p));
                free(name);
                ast_free(index);
                return NULL;
            }
            advance(p);  /* consume ']' */
            
            ASTNode *node = ast_create(AST_ARRAY_ACCESS, line, col);
            node->data.array_access.array_name = name;
            node->data.array_access.index = index;
            return node;
        }

        /* Check for enum member access: EnumName.Member */
        if (match_operator(p, ".")) {
            advance(p);  /* consume '.' */
            if (!current(p) || current(p)->type != TOK_IDENTIFIER) {
                set_error(p, "Expected member name after '.'", current(p));
                free(name);
                return NULL;
            }
            /* Combine into EnumName.Member identifier */
            char *member = current(p)->lexeme;
            size_t full_len = strlen(name) + 1 + strlen(member) + 1;
            char *full_name = malloc(full_len);
            snprintf(full_name, full_len, "%s.%s", name, member);
            free(name);
            advance(p);  /* consume member name */
            
            ASTNode *node = ast_create(AST_IDENTIFIER, line, col);
            node->data.identifier.name = full_name;
            return node;
        }

        /* Just an identifier */
        ASTNode *node = ast_create(AST_IDENTIFIER, line, col);
        node->data.identifier.name = name;
        return node;
    }

    /* Parenthesized expression */
    if (match_operator(p, "(")) {
        advance(p);
        ASTNode *expr = parse_expression(p);
        if (match_operator(p, ")")) {
            advance(p);
        } else {
            set_error(p, "Expected ')'", current(p));
        }
        return expr;
    }

    return NULL;
}

static ASTNode *parse_unary(Parser *p)
{
    if (match_operator(p, "-") || match_operator(p, "+")) {
        Token *t = current(p);
        char *op = strdup(t->lexeme);
        size_t line = t->line, col = t->column;
        advance(p);

        ASTNode *operand = parse_unary(p);
        ASTNode *node = ast_create(AST_UNARY_OP, line, col);
        node->data.unary_op.op = op;
        node->data.unary_op.operand = operand;
        return node;
    }
    /* Address-of operator: &var */
    if (match_operator(p, "&")) {
        Token *t = current(p);
        size_t line = t->line, col = t->column;
        advance(p);  /* consume '&' */
        
        if (current(p) && current(p)->type == TOK_IDENTIFIER) {
            char *var_name = strdup(current(p)->lexeme);
            advance(p);
            ASTNode *node = ast_create(AST_ADDRESS_OF, line, col);
            node->data.address_of.var_name = var_name;
            return node;
        } else {
            set_error(p, "Expected identifier after '&'", current(p));
            return NULL;
        }
    }
    /* Dereference operator: *ptr */
    if (match_operator(p, "*")) {
        Token *t = current(p);
        size_t line = t->line, col = t->column;
        advance(p);  /* consume '*' */
        
        ASTNode *operand = parse_unary(p);
        ASTNode *node = ast_create(AST_DEREF, line, col);
        node->data.deref.operand = operand;
        return node;
    }
    return parse_primary(p);
}

static ASTNode *parse_multiplicative(Parser *p)
{
    ASTNode *left = parse_unary(p);

    while (match_operator(p, "*") || match_operator(p, "/") || match_operator(p, "%")) {
        Token *t = current(p);
        char *op = strdup(t->lexeme);
        size_t line = t->line, col = t->column;
        advance(p);

        ASTNode *right = parse_unary(p);
        ASTNode *node = ast_create(AST_BINARY_OP, line, col);
        node->data.binary_op.op = op;
        node->data.binary_op.left = left;
        node->data.binary_op.right = right;
        left = node;
    }

    return left;
}

static ASTNode *parse_additive(Parser *p)
{
    ASTNode *left = parse_multiplicative(p);

    while (match_operator(p, "+") || match_operator(p, "-")) {
        Token *t = current(p);
        char *op = strdup(t->lexeme);
        size_t line = t->line, col = t->column;
        advance(p);

        ASTNode *right = parse_multiplicative(p);
        ASTNode *node = ast_create(AST_BINARY_OP, line, col);
        node->data.binary_op.op = op;
        node->data.binary_op.left = left;
        node->data.binary_op.right = right;
        left = node;
    }

    return left;
}

static ASTNode *parse_comparison(Parser *p)
{
    ASTNode *left = parse_additive(p);

    while (match_operator(p, "<") || match_operator(p, ">") ||
           match_operator(p, "<=") || match_operator(p, ">=") ||
           match_operator(p, "==") || match_operator(p, "!=")) {
        Token *t = current(p);
        char *op = strdup(t->lexeme);
        size_t line = t->line, col = t->column;
        advance(p);

        ASTNode *right = parse_additive(p);
        ASTNode *node = ast_create(AST_BINARY_OP, line, col);
        node->data.binary_op.op = op;
        node->data.binary_op.left = left;
        node->data.binary_op.right = right;
        left = node;
    }

    return left;
}

static ASTNode *parse_expression(Parser *p)
{
    return parse_comparison(p);
}

/* ========== Statement Parsing ========== */

/* Parse variable declaration: eric x = 5 -> int */
static ASTNode *parse_var_decl(Parser *p)
{
    Token *t = current(p);
    size_t line = t->line, col = t->column;
    advance(p);  /* consume 'eric' */

    /* Variable name */
    if (!current(p) || current(p)->type != TOK_IDENTIFIER) {
        set_error(p, "Expected variable name after 'eric'", current(p));
        return NULL;
    }
    char *var_name = strdup(current(p)->lexeme);
    advance(p);

    ASTNode *init_value = NULL;

    /* Optional initialization: = value */
    if (match_operator(p, "=")) {
        advance(p);
        init_value = parse_expression(p);
    }

    /* Type declaration: -> type or -> type[] */
    if (!match_operator(p, "->")) {
        set_error(p, "Expected '->' for type declaration", current(p));
        free(var_name);
        ast_free(init_value);
        return NULL;
    }
    advance(p);

    if (!current(p) || current(p)->type != TOK_IDENTIFIER) {
        set_error(p, "Expected type name after '->'", current(p));
        free(var_name);
        ast_free(init_value);
        return NULL;
    }
    
    /* Build type string - check for [] suffix for arrays */
    char type_str[64];
    strncpy(type_str, current(p)->lexeme, sizeof(type_str) - 3);
    type_str[sizeof(type_str) - 3] = '\0';
    advance(p);
    
    /* Check for [size] or [] to make it an array type */
    size_t array_size = 0;
    if (match_operator(p, "[")) {
        advance(p);  /* consume '[' */
        
        /* Check for array size (number) */
        if (current(p) && current(p)->type == TOK_NUMBER) {
            array_size = (size_t)atol(current(p)->lexeme);
            advance(p);  /* consume size */
        }
        
        if (match_operator(p, "]")) {
            advance(p);  /* consume ']' */
            strcat(type_str, "[]");
        } else {
            set_error(p, "Expected ']' after '[' in array type", current(p));
            free(var_name);
            ast_free(init_value);
            return NULL;
        }
    }
    
    DataType var_type = str_to_datatype(type_str);

    ASTNode *node = ast_create(AST_VAR_DECL, line, col);
    node->data.var_decl.name = var_name;
    node->data.var_decl.var_type = var_type;
    node->data.var_decl.struct_type_name = NULL;
    
    /* If type is TYPE_UNKNOWN, it might be a struct type */
    if (var_type == TYPE_UNKNOWN) {
        node->data.var_decl.struct_type_name = strdup(type_str);
    }
    
    node->data.var_decl.init_value = init_value;
    
    /* If array with size, create array initialization */
    if (array_size > 0 && !init_value) {
        /* We'll handle array size in the interpreter/codegen */
        /* For now, store size in a special way - use a number node */
        ASTNode *size_node = ast_create(AST_NUMBER, line, col);
        size_node->data.number.value = (double)array_size;
        size_node->data.number.is_float = 0;
        node->data.var_decl.init_value = size_node;
    }
    
    return node;
}

/* Parse assignment: x = 5 or arr[i] = 5 */
static ASTNode *parse_assignment(Parser *p)
{
    Token *t = current(p);
    char *var_name = strdup(t->lexeme);
    size_t line = t->line, col = t->column;
    advance(p);  /* consume identifier */

    /* Check for array indexing: arr[index] = value */
    if (match_operator(p, "[")) {
        advance(p);  /* consume '[' */
        ASTNode *index = parse_expression(p);
        if (!match_operator(p, "]")) {
            set_error(p, "Expected ']' after array index", current(p));
            free(var_name);
            ast_free(index);
            return NULL;
        }
        advance(p);  /* consume ']' */
        
        if (!match_operator(p, "=")) {
            set_error(p, "Expected '=' after array index", current(p));
            free(var_name);
            ast_free(index);
            return NULL;
        }
        advance(p);  /* consume '=' */
        
        ASTNode *value = parse_expression(p);
        
        ASTNode *node = ast_create(AST_ARRAY_ASSIGN, line, col);
        node->data.array_assign.array_name = var_name;
        node->data.array_assign.index = index;
        node->data.array_assign.value = value;
        return node;
    }

    if (!match_operator(p, "=")) {
        free(var_name);
        return NULL;
    }
    advance(p);  /* consume '=' */

    ASTNode *value = parse_expression(p);

    ASTNode *node = ast_create(AST_ASSIGNMENT, line, col);
    node->data.assignment.var_name = var_name;
    node->data.assignment.value = value;
    return node;
}

/* Parse struct field assignment: struct.field = value */
static ASTNode *parse_struct_field_assignment(Parser *p)
{
    Token *t = current(p);
    char *struct_name = strdup(t->lexeme);
    size_t line = t->line, col = t->column;
    advance(p);  /* consume struct name */

    if (!match_operator(p, ".")) {
        set_error(p, "Expected '.' in struct field assignment", current(p));
        free(struct_name);
        return NULL;
    }
    advance(p);  /* consume '.' */

    if (!current(p) || current(p)->type != TOK_IDENTIFIER) {
        set_error(p, "Expected field name after '.'", current(p));
        free(struct_name);
        return NULL;
    }
    char *field_name = strdup(current(p)->lexeme);
    advance(p);  /* consume field name */

    if (!match_operator(p, "=")) {
        set_error(p, "Expected '=' after struct field", current(p));
        free(struct_name);
        free(field_name);
        return NULL;
    }
    advance(p);  /* consume '=' */

    ASTNode *value = parse_expression(p);

    ASTNode *node = ast_create(AST_STRUCT_ASSIGN, line, col);
    node->data.struct_assign.struct_name = struct_name;
    node->data.struct_assign.field_name = field_name;
    node->data.struct_assign.value = value;
    return node;
}

/* Parse return statement: deschodt value */
static ASTNode *parse_return(Parser *p)
{
    Token *t = current(p);
    size_t line = t->line, col = t->column;
    advance(p);  /* consume 'deschodt' */

    ASTNode *value = parse_expression(p);

    ASTNode *node = ast_create(AST_RETURN, line, col);
    node->data.return_stmt.value = value;
    return node;
}

/* Parse constant declaration: cz NAME = value -> type */
static ASTNode *parse_const_decl(Parser *p)
{
    Token *t = current(p);
    size_t line = t->line, col = t->column;
    advance(p);  /* consume 'cz' */

    if (!current(p) || current(p)->type != TOK_IDENTIFIER) {
        set_error(p, "Expected constant name after 'cz'", current(p));
        return NULL;
    }
    char *name = strdup(current(p)->lexeme);
    advance(p);  /* consume name */

    if (!match_operator(p, "=")) {
        set_error(p, "Expected '=' after constant name", current(p));
        free(name);
        return NULL;
    }
    advance(p);  /* consume '=' */

    ASTNode *value = parse_expression(p);
    if (!value) {
        free(name);
        return NULL;
    }

    DataType type = TYPE_UNKNOWN;
    if (match_operator(p, "->")) {
        advance(p);  /* consume '->' */
        if (!current(p) || current(p)->type != TOK_IDENTIFIER) {
            set_error(p, "Expected type after '->'", current(p));
            free(name);
            ast_free(value);
            return NULL;
        }
        type = str_to_datatype(current(p)->lexeme);
        advance(p);  /* consume type */
    } else {
        /* Infer type from value */
        if (value->type == AST_NUMBER) {
            type = value->data.number.is_float ? TYPE_FLOAT : TYPE_INT;
        } else if (value->type == AST_STRING) {
            type = TYPE_STRING;
        }
    }

    ASTNode *node = ast_create(AST_CONST_DECL, line, col);
    node->data.const_decl.name = name;
    node->data.const_decl.const_type = type;
    node->data.const_decl.value = value;
    return node;
}

/* Parse enum definition: desnum EnumName: Member1, Member2, ... */
static ASTNode *parse_enum_def(Parser *p)
{
    Token *t = current(p);
    size_t line = t->line, col = t->column;
    advance(p);  /* consume 'desnum' */

    if (!current(p) || current(p)->type != TOK_IDENTIFIER) {
        set_error(p, "Expected enum name after 'desnum'", current(p));
        return NULL;
    }
    char *name = strdup(current(p)->lexeme);
    advance(p);  /* consume enum name */

    if (!match_operator(p, ":")) {
        set_error(p, "Expected ':' after enum name", current(p));
        free(name);
        return NULL;
    }
    advance(p);  /* consume ':' */

    /* Skip newlines after the colon (for indented block style) */
    skip_newlines(p);

    /* Parse enum members */
    char **members = NULL;
    size_t member_count = 0;
    size_t member_capacity = 0;

    while (current(p) && current(p)->type == TOK_IDENTIFIER) {
        /* Resize array if needed */
        if (member_count >= member_capacity) {
            member_capacity = member_capacity == 0 ? 8 : member_capacity * 2;
            members = realloc(members, member_capacity * sizeof(char *));
        }
        members[member_count++] = strdup(current(p)->lexeme);
        advance(p);  /* consume member name */

        /* Check for comma or newline */
        if (match_operator(p, ",")) {
            advance(p);  /* consume ',' */
            skip_newlines(p);
        } else {
            /* Skip newlines to check for more members (indented block style) */
            skip_newlines(p);
        }
    }

    if (member_count == 0) {
        set_error(p, "Enum must have at least one member", current(p));
        free(name);
        return NULL;
    }

    ASTNode *node = ast_create(AST_ENUM_DEF, line, col);
    node->data.enum_def.name = name;
    node->data.enum_def.members = members;
    node->data.enum_def.member_count = member_count;
    return node;
}

/* Parse struct definition: destruct StructName: field1 -> type1, field2 -> type2 */
static ASTNode *parse_struct_def(Parser *p)
{
    Token *t = current(p);
    size_t line = t->line, col = t->column;
    advance(p);  /* consume 'destruct' or 'Destruct' */

    if (!current(p) || current(p)->type != TOK_IDENTIFIER) {
        set_error(p, "Expected struct name after 'destruct'", current(p));
        return NULL;
    }
    char *name = strdup(current(p)->lexeme);
    advance(p);  /* consume struct name */

    if (!match_operator(p, ":")) {
        set_error(p, "Expected ':' after struct name", current(p));
        free(name);
        return NULL;
    }
    advance(p);  /* consume ':' */

    /* Skip newlines after the colon (for indented block style) */
    skip_newlines(p);

    /* Parse struct fields */
    StructFieldList fields;
    struct_field_list_init(&fields);

    while (current(p) && current(p)->type == TOK_IDENTIFIER) {
        StructField field;
        field.name = strdup(current(p)->lexeme);
        advance(p);  /* consume field name */

        if (!match_operator(p, "->")) {
            set_error(p, "Expected '->' for field type declaration", current(p));
            free(field.name);
            struct_field_list_free(&fields);
            free(name);
            return NULL;
        }
        advance(p);  /* consume '->' */

        if (!current(p) || current(p)->type != TOK_IDENTIFIER) {
            set_error(p, "Expected type name after '->'", current(p));
            free(field.name);
            struct_field_list_free(&fields);
            free(name);
            return NULL;
        }

        /* Parse type */
        char type_str[64];
        strncpy(type_str, current(p)->lexeme, sizeof(type_str) - 3);
        type_str[sizeof(type_str) - 3] = '\0';
        advance(p);

        /* Check for pointer or array suffix */
        if (match_operator(p, "*")) {
            strcat(type_str, "*");
            advance(p);
        } else if (match_operator(p, "[")) {
            strcat(type_str, "[]");
            advance(p);
            if (match_operator(p, "]")) {
                advance(p);
            }
        }

        field.type = str_to_datatype(type_str);
        struct_field_list_push(&fields, field);

        /* Check for comma or newline */
        if (match_operator(p, ",")) {
            advance(p);  /* consume ',' */
            skip_newlines(p);
        } else {
            /* Skip newlines to check for more fields */
            skip_newlines(p);
        }
    }

    if (fields.count == 0) {
        set_error(p, "Struct must have at least one field", current(p));
        free(name);
        return NULL;
    }

    ASTNode *node = ast_create(AST_STRUCT_DEF, line, col);
    node->data.struct_def.name = name;
    node->data.struct_def.fields = fields;
    return node;
}

/* Parse print statement: peric("...") */
static ASTNode *parse_print(Parser *p)
{
    Token *t = current(p);
    size_t line = t->line, col = t->column;
    advance(p);  /* consume 'peric' */

    if (!match_operator(p, "(")) {
        set_error(p, "Expected '(' after 'peric'", current(p));
        return NULL;
    }
    advance(p);

    ASTNode *value = parse_expression(p);

    if (!match_operator(p, ")")) {
        set_error(p, "Expected ')' after print argument", current(p));
        ast_free(value);
        return NULL;
    }
    advance(p);

    ASTNode *node = ast_create(AST_PRINT, line, col);
    node->data.print_stmt.value = value;
    return node;
}

/* Parse if statement: erif (cond): or darius (cond): for while */
static ASTNode *parse_if_or_while(Parser *p, int is_while)
{
    Token *t = current(p);
    size_t line = t->line, col = t->column;
    advance(p);  /* consume 'erif' or 'darius' */

    if (!match_operator(p, "(")) {
        set_error(p, "Expected '(' after conditional keyword", current(p));
        return NULL;
    }
    advance(p);

    ASTNode *condition = parse_expression(p);

    if (!match_operator(p, ")")) {
        set_error(p, "Expected ')' after condition", current(p));
        ast_free(condition);
        return NULL;
    }
    advance(p);

    if (!match_operator(p, ":")) {
        set_error(p, "Expected ':' after condition", current(p));
        ast_free(condition);
        return NULL;
    }
    advance(p);

    ASTNode *node = ast_create(is_while ? AST_WHILE : AST_IF, line, col);
    node->data.conditional.condition = condition;
    ast_list_init(&node->data.conditional.body);
    ast_list_init(&node->data.conditional.else_body);

    /* Parse the body block */
    parse_block(p, &node->data.conditional.body);

    /* Check for else clause */
    skip_newlines_only(p);
    if (!is_while && match_keyword(p, "deschelse")) {
        advance(p);
        if (match_operator(p, ":")) {
            advance(p);
        }
        parse_block(p, &node->data.conditional.else_body);
    }

    return node;
}

/* Parse for loop: aer i in range(0, 5): */
static ASTNode *parse_for(Parser *p)
{
    Token *t = current(p);
    size_t line = t->line, col = t->column;
    advance(p);  /* consume 'aer' */

    /* Loop variable */
    if (!current(p) || current(p)->type != TOK_IDENTIFIER) {
        set_error(p, "Expected loop variable after 'aer'", current(p));
        return NULL;
    }
    char *var_name = strdup(current(p)->lexeme);
    advance(p);

    /* 'in' keyword */
    if (!current(p) || current(p)->type != TOK_IDENTIFIER ||
        strcmp(current(p)->lexeme, "in") != 0) {
        set_error(p, "Expected 'in' after loop variable", current(p));
        free(var_name);
        return NULL;
    }
    advance(p);

    /* 'range' */
    if (!current(p) || current(p)->type != TOK_IDENTIFIER ||
        strcmp(current(p)->lexeme, "range") != 0) {
        set_error(p, "Expected 'range' after 'in'", current(p));
        free(var_name);
        return NULL;
    }
    advance(p);

    if (!match_operator(p, "(")) {
        set_error(p, "Expected '(' after 'range'", current(p));
        free(var_name);
        return NULL;
    }
    advance(p);

    /* Parse range arguments */
    ASTNode *start = parse_expression(p);
    if (!match_operator(p, ",")) {
        set_error(p, "Expected ',' in range arguments", current(p));
        free(var_name);
        ast_free(start);
        return NULL;
    }
    advance(p);

    ASTNode *end = parse_expression(p);
    ASTNode *step = NULL;

    if (match_operator(p, ",")) {
        advance(p);
        step = parse_expression(p);
    }

    if (!match_operator(p, ")")) {
        set_error(p, "Expected ')' after range arguments", current(p));
        free(var_name);
        ast_free(start);
        ast_free(end);
        ast_free(step);
        return NULL;
    }
    advance(p);

    if (!match_operator(p, ":")) {
        set_error(p, "Expected ':' after range(...)", current(p));
        free(var_name);
        ast_free(start);
        ast_free(end);
        ast_free(step);
        return NULL;
    }
    advance(p);

    ASTNode *node = ast_create(AST_FOR, line, col);
    node->data.for_loop.var_name = var_name;
    node->data.for_loop.start = start;
    node->data.for_loop.end = end;
    node->data.for_loop.step = step;
    ast_list_init(&node->data.for_loop.body);

    parse_block(p, &node->data.for_loop.body);

    return node;
}

/* Parse a single statement */
static ASTNode *parse_statement(Parser *p)
{
    Token *t = current(p);
    if (!t || t->type == TOK_EOF) return NULL;

    /* Skip comments (desnote) */
    if (match_keyword(p, "desnote") || match_keyword(p, "Desnote")) {
        /* Skip until newline */
        while (current(p) && current(p)->type != TOK_NEWLINE) {
            advance(p);
        }
        return NULL;
    }

    /* Variable declaration: eric */
    if (match_keyword(p, "eric")) {
        return parse_var_decl(p);
    }

    /* Return statement: deschodt */
    if (match_keyword(p, "deschodt")) {
        return parse_return(p);
    }

    /* Print statement: peric */
    if (match_keyword(p, "peric")) {
        return parse_print(p);
    }

    /* If statement: erif */
    if (match_keyword(p, "erif")) {
        return parse_if_or_while(p, 0);
    }

    /* While loop: darius */
    if (match_keyword(p, "darius")) {
        return parse_if_or_while(p, 1);
    }

    /* For loop: aer */
    if (match_keyword(p, "aer")) {
        return parse_for(p);
    }

    /* Continue statement: deschontinue */
    if (match_keyword(p, "deschontinue")) {
        ASTNode *node = ast_create(AST_CONTINUE, t->line, t->column);
        advance(p);  /* consume 'deschontinue' */
        return node;
    }

    /* Break statement: deschreak */
    if (match_keyword(p, "deschreak")) {
        ASTNode *node = ast_create(AST_BREAK, t->line, t->column);
        advance(p);  /* consume 'deschreak' */
        return node;
    }

    /* Pointer dereference assignment: *ptr = value */
    if (t->type == TOK_OPERATOR && strcmp(t->lexeme, "*") == 0) {
        size_t line = t->line, col = t->column;
        advance(p);  /* consume '*' */
        
        /* Parse the pointer expression (could be *ptr or *arr[i] etc.) */
        ASTNode *ptr_expr = parse_primary(p);
        if (!ptr_expr) {
            set_error(p, "Expected expression after '*'", current(p));
            return NULL;
        }
        
        /* Expect '=' */
        if (!match_operator(p, "=")) {
            /* Not an assignment, treat as expression with dereference */
            ASTNode *deref = ast_create(AST_DEREF, line, col);
            deref->data.deref.operand = ptr_expr;
            return deref;
        }
        advance(p);  /* consume '=' */
        
        /* Parse the value */
        ASTNode *value = parse_expression(p);
        if (!value) {
            set_error(p, "Expected expression after '='", current(p));
            return NULL;
        }
        
        ASTNode *node = ast_create(AST_DEREF_ASSIGN, line, col);
        node->data.deref_assign.ptr = ptr_expr;
        node->data.deref_assign.value = value;
        return node;
    }

    /* Assignment or expression starting with identifier */
    if (t->type == TOK_IDENTIFIER) {
        /* Look ahead for '=' or '[' (for array assignment) or '.' (for struct field access) */
        Token *next = peek(p, 1);
        if (next && next->type == TOK_OPERATOR) {
            if (strcmp(next->lexeme, "=") == 0 || strcmp(next->lexeme, "[") == 0) {
                return parse_assignment(p);
            } else if (strcmp(next->lexeme, ".") == 0) {
                /* Check if it's a struct field assignment */
                Token *after_dot = peek(p, 2);
                if (after_dot && after_dot->type == TOK_IDENTIFIER) {
                    Token *after_field = peek(p, 3);
                    if (after_field && after_field->type == TOK_OPERATOR && 
                        strcmp(after_field->lexeme, "=") == 0) {
                        return parse_struct_field_assignment(p);
                    }
                }
            }
        }
        /* Otherwise it might be a function call or expression */
        return parse_expression(p);
    }

    return NULL;
}

/* Parse a block of statements (indented) */
static void parse_block(Parser *p, ASTNodeList *body)
{
    /* Skip newline after ':' */
    skip_newlines_only(p);

    /* Expect INDENT */
    if (current(p) && current(p)->type == TOK_INDENT) {
        advance(p);
    }

    /* Parse statements until DEDENT */
    while (current(p) && current(p)->type != TOK_DEDENT && current(p)->type != TOK_EOF) {
        skip_newlines_only(p);

        if (current(p) && current(p)->type == TOK_DEDENT) break;

        ASTNode *stmt = parse_statement(p);
        if (stmt) {
            ast_list_push(body, stmt);
        }

        /* Skip to next statement - but only skip if we have trailing garbage */
        /* Don't skip if we're already at a newline, dedent, or statement-starting token */
        while (current(p) && 
               current(p)->type != TOK_NEWLINE &&
               current(p)->type != TOK_DEDENT && 
               current(p)->type != TOK_EOF &&
               current(p)->type != TOK_KEYWORD &&
               current(p)->type != TOK_IDENTIFIER) {
            advance(p);
        }
        if (current(p) && current(p)->type == TOK_NEWLINE) {
            advance(p);
        }
    }

    /* Consume DEDENT */
    if (current(p) && current(p)->type == TOK_DEDENT) {
        advance(p);
    }
}

/* Parse function definition: Deschodt funcname(params) -> type */
static ASTNode *parse_function(Parser *p)
{
    Token *t = current(p);
    size_t line = t->line, col = t->column;
    advance(p);  /* consume 'Deschodt' */

    /* Function name */
    if (!current(p) || current(p)->type != TOK_IDENTIFIER) {
        set_error(p, "Expected function name after 'Deschodt'", current(p));
        return NULL;
    }
    char *func_name = strdup(current(p)->lexeme);
    advance(p);

    /* Parameters */
    if (!match_operator(p, "(")) {
        set_error(p, "Expected '(' after function name", current(p));
        free(func_name);
        return NULL;
    }
    advance(p);

    FuncParamList params;
    param_list_init(&params);

    /* Parse parameters */
    while (!match_operator(p, ")") && current(p)) {
        if (current(p)->type != TOK_IDENTIFIER) break;

        FuncParam param;
        param.name = strdup(current(p)->lexeme);
        param.type = TYPE_UNKNOWN;
        advance(p);

        /* Optional type annotation */
        if (match_operator(p, "->")) {
            advance(p);
            if (current(p) && current(p)->type == TOK_IDENTIFIER) {
                char *type_str = strdup(current(p)->lexeme);
                advance(p);
                
                /* Check for array type: int[] */
                if (match_operator(p, "[")) {
                    advance(p);  /* consume '[' */
                    if (match_operator(p, "]")) {
                        advance(p);  /* consume ']' */
                        /* Combine into array type string */
                        char *arr_type = malloc(strlen(type_str) + 3);
                        sprintf(arr_type, "%s[]", type_str);
                        param.type = str_to_datatype(arr_type);
                        free(arr_type);
                    }
                } else if (match_operator(p, "*")) {
                    advance(p);  /* consume '*' */
                    /* Combine into pointer type string */
                    char *ptr_type = malloc(strlen(type_str) + 2);
                    sprintf(ptr_type, "%s*", type_str);
                    param.type = str_to_datatype(ptr_type);
                    free(ptr_type);
                } else {
                    param.type = str_to_datatype(type_str);
                }
                free(type_str);
            }
        }

        param_list_push(&params, param);

        if (match_operator(p, ",")) {
            advance(p);
        }
    }

    if (!match_operator(p, ")")) {
        set_error(p, "Expected ')' after parameters", current(p));
        free(func_name);
        param_list_free(&params);
        return NULL;
    }
    advance(p);

    /* Return type */
    DataType return_type = TYPE_VOID;
    if (match_operator(p, "->")) {
        advance(p);
        if (current(p) && current(p)->type == TOK_IDENTIFIER) {
            return_type = str_to_datatype(current(p)->lexeme);
            advance(p);
        }
    }

    ASTNode *node = ast_create(AST_FUNCTION_DEF, line, col);
    node->data.func_def.name = func_name;
    node->data.func_def.params = params;
    node->data.func_def.return_type = return_type;
    ast_list_init(&node->data.func_def.body);

    /* Parse function body */
    skip_newlines_only(p);

    /* Expect INDENT */
    if (current(p) && current(p)->type == TOK_INDENT) {
        advance(p);
    }

    /* Parse statements in function body */
    while (current(p) && current(p)->type != TOK_DEDENT && current(p)->type != TOK_EOF) {
        skip_newlines_only(p);

        if (current(p) && current(p)->type == TOK_DEDENT) break;
        if (current(p) && current(p)->type == TOK_EOF) break;

        ASTNode *stmt = parse_statement(p);
        if (stmt) {
            ast_list_push(&node->data.func_def.body, stmt);
        }

        /* Skip to next statement - but only skip if we have trailing garbage */
        /* Don't skip if we're already at a newline, dedent, or statement-starting token */
        while (current(p) && 
               current(p)->type != TOK_NEWLINE &&
               current(p)->type != TOK_DEDENT && 
               current(p)->type != TOK_EOF &&
               current(p)->type != TOK_KEYWORD &&
               current(p)->type != TOK_IDENTIFIER) {
            advance(p);
        }
        if (current(p) && current(p)->type == TOK_NEWLINE) {
            advance(p);
        }
    }

    /* Consume DEDENT */
    if (current(p) && current(p)->type == TOK_DEDENT) {
        advance(p);
    }

    return node;
}

/* Main parse function */
ASTNode *parser_parse(Parser *parser)
{
    ASTNode *program = ast_create(AST_PROGRAM, 0, 0);
    ast_list_init(&program->data.program.functions);
    ast_list_init(&program->data.program.constants);
    ast_list_init(&program->data.program.enums);
    ast_list_init(&program->data.program.structs);

    while (current(parser) && current(parser)->type != TOK_EOF) {
        skip_newlines(parser);

        if (!current(parser) || current(parser)->type == TOK_EOF) break;

        /* Skip comments */
        if (match_keyword(parser, "desnote") || match_keyword(parser, "Desnote")) {
            while (current(parser) && current(parser)->type != TOK_NEWLINE) {
                advance(parser);
            }
            continue;
        }

        /* Constant declaration: cz NAME = value */
        if (match_keyword(parser, "cz")) {
            ASTNode *const_node = parse_const_decl(parser);
            if (const_node) {
                ast_list_push(&program->data.program.constants, const_node);
            }
            continue;
        }

        /* Enum definition: desnum EnumName: Member1, Member2 */
        if (match_keyword(parser, "desnum")) {
            ASTNode *enum_node = parse_enum_def(parser);
            if (enum_node) {
                ast_list_push(&program->data.program.enums, enum_node);
            }
            continue;
        }

        /* Struct definition: destruct StructName: field1 -> type1, field2 -> type2 */
        if (match_keyword(parser, "destruct") || match_keyword(parser, "Destruct")) {
            ASTNode *struct_node = parse_struct_def(parser);
            if (struct_node) {
                ast_list_push(&program->data.program.structs, struct_node);
            }
            continue;
        }

        /* Function definition */
        if (match_keyword(parser, "Deschodt")) {
            ASTNode *func = parse_function(parser);
            if (func) {
                ast_list_push(&program->data.program.functions, func);
            }
            continue;
        }

        /* Skip unknown tokens */
        advance(parser);
    }

    return program;
}

/* ========== Debug Print ========== */

static void print_indent(int indent)
{
    for (int i = 0; i < indent; ++i) printf("  ");
}

void ast_print(ASTNode *node, int indent)
{
    if (!node) return;

    print_indent(indent);

    switch (node->type) {
        case AST_PROGRAM:
            printf("PROGRAM\n");
            /* Print constants */
            if (node->data.program.constants.count > 0) {
                print_indent(indent + 1);
                printf("CONSTANTS:\n");
                for (size_t i = 0; i < node->data.program.constants.count; ++i) {
                    ast_print(node->data.program.constants.items[i], indent + 2);
                }
            }
            /* Print enums */
            if (node->data.program.enums.count > 0) {
                print_indent(indent + 1);
                printf("ENUMS:\n");
                for (size_t i = 0; i < node->data.program.enums.count; ++i) {
                    ast_print(node->data.program.enums.items[i], indent + 2);
                }
            }
            /* Print functions */
            for (size_t i = 0; i < node->data.program.functions.count; ++i) {
                ast_print(node->data.program.functions.items[i], indent + 1);
            }
            break;

        case AST_FUNCTION_DEF:
            printf("FUNCTION %s -> %s\n", node->data.func_def.name,
                   datatype_to_str(node->data.func_def.return_type));
            print_indent(indent + 1);
            printf("PARAMS: ");
            for (size_t i = 0; i < node->data.func_def.params.count; ++i) {
                printf("%s:%s ", node->data.func_def.params.items[i].name,
                       datatype_to_str(node->data.func_def.params.items[i].type));
            }
            printf("\n");
            print_indent(indent + 1);
            printf("BODY:\n");
            for (size_t i = 0; i < node->data.func_def.body.count; ++i) {
                ast_print(node->data.func_def.body.items[i], indent + 2);
            }
            break;

        case AST_VAR_DECL:
            printf("VAR_DECL %s : %s\n", node->data.var_decl.name,
                   datatype_to_str(node->data.var_decl.var_type));
            if (node->data.var_decl.init_value) {
                print_indent(indent + 1);
                printf("INIT:\n");
                ast_print(node->data.var_decl.init_value, indent + 2);
            }
            break;
        case AST_ASSIGNMENT:
            printf("ASSIGN %s =\n", node->data.assignment.var_name);
            ast_print(node->data.assignment.value, indent + 1);
            break;

        case AST_ARRAY_ACCESS:
            printf("ARRAY_ACCESS %s[]\n", node->data.array_access.array_name);
            print_indent(indent + 1);
            printf("INDEX:\n");
            ast_print(node->data.array_access.index, indent + 2);
            break;

        case AST_ARRAY_ASSIGN:
            printf("ARRAY_ASSIGN %s[] =\n", node->data.array_assign.array_name);
            print_indent(indent + 1);
            printf("INDEX:\n");
            ast_print(node->data.array_assign.index, indent + 2);
            print_indent(indent + 1);
            printf("VALUE:\n");
            ast_print(node->data.array_assign.value, indent + 2);
            break;

        case AST_RETURN:
            printf("RETURN\n");
            ast_print(node->data.return_stmt.value, indent + 1);
            break;

        case AST_PRINT:
            printf("PRINT\n");
            ast_print(node->data.print_stmt.value, indent + 1);
            break;

        case AST_IF:
            printf("IF\n");
            print_indent(indent + 1);
            printf("CONDITION:\n");
            ast_print(node->data.conditional.condition, indent + 2);
            print_indent(indent + 1);
            printf("THEN:\n");
            for (size_t i = 0; i < node->data.conditional.body.count; ++i) {
                ast_print(node->data.conditional.body.items[i], indent + 2);
            }
            if (node->data.conditional.else_body.count > 0) {
                print_indent(indent + 1);
                printf("ELSE:\n");
                for (size_t i = 0; i < node->data.conditional.else_body.count; ++i) {
                    ast_print(node->data.conditional.else_body.items[i], indent + 2);
                }
            }
            break;

        case AST_WHILE:
            printf("WHILE\n");
            print_indent(indent + 1);
            printf("CONDITION:\n");
            ast_print(node->data.conditional.condition, indent + 2);
            print_indent(indent + 1);
            printf("BODY:\n");
            for (size_t i = 0; i < node->data.conditional.body.count; ++i) {
                ast_print(node->data.conditional.body.items[i], indent + 2);
            }
            break;

        case AST_FOR:
            printf("FOR %s in range\n", node->data.for_loop.var_name);
            print_indent(indent + 1);
            printf("START:\n");
            ast_print(node->data.for_loop.start, indent + 2);
            print_indent(indent + 1);
            printf("END:\n");
            ast_print(node->data.for_loop.end, indent + 2);
            if (node->data.for_loop.step) {
                print_indent(indent + 1);
                printf("STEP:\n");
                ast_print(node->data.for_loop.step, indent + 2);
            }
            print_indent(indent + 1);
            printf("BODY:\n");
            for (size_t i = 0; i < node->data.for_loop.body.count; ++i) {
                ast_print(node->data.for_loop.body.items[i], indent + 2);
            }
            break;

        case AST_BINARY_OP:
            printf("BINARY_OP %s\n", node->data.binary_op.op);
            ast_print(node->data.binary_op.left, indent + 1);
            ast_print(node->data.binary_op.right, indent + 1);
            break;

        case AST_UNARY_OP:
            printf("UNARY_OP %s\n", node->data.unary_op.op);
            ast_print(node->data.unary_op.operand, indent + 1);
            break;

        case AST_IDENTIFIER:
            printf("IDENT %s\n", node->data.identifier.name);
            break;

        case AST_NUMBER:
            printf("NUMBER %g\n", node->data.number.value);
            break;

        case AST_STRING:
            printf("STRING \"%s\"\n", node->data.string.value);
            break;

        case AST_FUNC_CALL:
            printf("CALL %s\n", node->data.func_call.name);
            for (size_t i = 0; i < node->data.func_call.args.count; ++i) {
                ast_print(node->data.func_call.args.items[i], indent + 1);
            }
            break;

        case AST_BREAK:
            printf("BREAK\n");
            break;

        case AST_CONTINUE:
            printf("CONTINUE\n");
            break;

        case AST_CONST_DECL:
            printf("CONST %s : %s\n", node->data.const_decl.name,
                   datatype_to_str(node->data.const_decl.const_type));
            if (node->data.const_decl.value) {
                print_indent(indent + 1);
                printf("VALUE:\n");
                ast_print(node->data.const_decl.value, indent + 2);
            }
            break;

        case AST_ENUM_DEF:
            printf("ENUM %s\n", node->data.enum_def.name);
            print_indent(indent + 1);
            printf("MEMBERS: ");
            for (size_t i = 0; i < node->data.enum_def.member_count; ++i) {
                printf("%s", node->data.enum_def.members[i]);
                if (i < node->data.enum_def.member_count - 1) printf(", ");
            }
            printf("\n");
            break;

        default:
            printf("UNKNOWN NODE TYPE %d\n", node->type);
            break;
    }
}
