/**==============================================
 *                 interpreter.c
 *  Interpreter implementation - executes AST
 *  Author: shirosaaki
 *  Date: 2025-11-27
 *=============================================**/

#include "../includes/interpreter.h"
#include <ctype.h>

/* ========== Value Functions ========== */

Value value_create_int(long val)
{
    Value v;
    v.type = VAL_INT;
    v.data.int_val = val;
    v.is_return = 0;
    return v;
}

Value value_create_float(double val)
{
    Value v;
    v.type = VAL_FLOAT;
    v.data.float_val = val;
    v.is_return = 0;
    return v;
}

Value value_create_string(const char *val)
{
    Value v;
    v.type = VAL_STRING;
    v.data.string_val = val ? strdup(val) : NULL;
    v.is_return = 0;
    return v;
}

Value value_create_void(void)
{
    Value v;
    v.type = VAL_VOID;
    v.is_return = 0;
    return v;
}

Value value_create_array(ValueType element_type)
{
    Value v;
    v.type = VAL_ARRAY;
    v.data.array_val = calloc(1, sizeof(ArrayValue));
    v.data.array_val->elements = NULL;
    v.data.array_val->size = 0;
    v.data.array_val->capacity = 0;
    v.data.array_val->element_type = element_type;
    v.is_return = 0;
    return v;
}

Value value_create_struct(const char *type_name)
{
    Value v;
    v.type = VAL_STRUCT;
    v.data.struct_val = calloc(1, sizeof(StructValue));
    v.data.struct_val->type_name = type_name ? strdup(type_name) : NULL;
    v.data.struct_val->fields = NULL;
    v.data.struct_val->field_count = 0;
    v.is_return = 0;
    return v;
}

/* Set struct field value */
static void struct_set_field(StructValue *sv, const char *name, Value val)
{
    if (!sv || !name) return;
    
    /* Check if field already exists */
    for (size_t i = 0; i < sv->field_count; ++i) {
        if (strcmp(sv->fields[i].name, name) == 0) {
            value_free(sv->fields[i].value);
            *sv->fields[i].value = val;
            return;
        }
    }
    
    /* Add new field */
    sv->fields = realloc(sv->fields, (sv->field_count + 1) * sizeof(StructField_RT));
    sv->fields[sv->field_count].name = strdup(name);
    sv->fields[sv->field_count].value = malloc(sizeof(Value));
    *sv->fields[sv->field_count].value = val;
    sv->field_count++;
}

/* Get struct field value */
static Value struct_get_field(StructValue *sv, const char *name)
{
    if (!sv || !name) return value_create_void();
    
    for (size_t i = 0; i < sv->field_count; ++i) {
        if (strcmp(sv->fields[i].name, name) == 0) {
            /* Return a copy of the value */
            Value *v = sv->fields[i].value;
            if (v->type == VAL_STRING) {
                return value_create_string(v->data.string_val);
            } else if (v->type == VAL_INT) {
                return value_create_int(v->data.int_val);
            } else if (v->type == VAL_FLOAT) {
                return value_create_float(v->data.float_val);
            }
            return *v;
        }
    }
    return value_create_void();
}

/* Set array element at index, auto-filling intermediate indices with last value */
void array_set_element(ArrayValue *arr, size_t index, Value val)
{
    if (!arr) return;
    
    /* Expand array if needed */
    if (index >= arr->capacity) {
        size_t new_cap = index + 1;
        if (new_cap < 16) new_cap = 16;
        Value *new_elements = realloc(arr->elements, new_cap * sizeof(Value));
        if (!new_elements) return;
        
        /* Initialize new elements to 0 */
        for (size_t i = arr->capacity; i < new_cap; ++i) {
            new_elements[i] = value_create_int(0);
        }
        arr->elements = new_elements;
        arr->capacity = new_cap;
    }
    
    /* Auto-fill from current size to index with the last value */
    if (index > arr->size && arr->size > 0) {
        Value last_val = arr->elements[arr->size - 1];
        for (size_t i = arr->size; i < index; ++i) {
            /* Copy the last value */
            if (last_val.type == VAL_STRING) {
                arr->elements[i] = value_create_string(last_val.data.string_val);
            } else if (last_val.type == VAL_INT) {
                arr->elements[i] = value_create_int(last_val.data.int_val);
            } else if (last_val.type == VAL_FLOAT) {
                arr->elements[i] = value_create_float(last_val.data.float_val);
            } else {
                arr->elements[i] = value_create_int(0);
            }
        }
    }
    
    /* Set the element at index */
    value_free(&arr->elements[index]);
    if (val.type == VAL_STRING) {
        arr->elements[index] = value_create_string(val.data.string_val);
    } else {
        arr->elements[index] = val;
    }
    
    /* Update size */
    if (index >= arr->size) {
        arr->size = index + 1;
    }
}

Value array_get_element(ArrayValue *arr, size_t index)
{
    if (!arr || index >= arr->capacity) {
        return value_create_int(0);  /* Out of bounds returns 0 */
    }
    /* Return a copy */
    Value elem = arr->elements[index];
    if (elem.type == VAL_STRING) {
        return value_create_string(elem.data.string_val);
    }
    return elem;
}

void value_free(Value *val)
{
    if (!val) return;
    if (val->type == VAL_STRING && val->data.string_val) {
        free(val->data.string_val);
        val->data.string_val = NULL;
    } else if (val->type == VAL_ARRAY && val->data.array_val) {
        ArrayValue *arr = val->data.array_val;
        for (size_t i = 0; i < arr->size; ++i) {
            value_free(&arr->elements[i]);
        }
        free(arr->elements);
        free(arr);
        val->data.array_val = NULL;
    } else if (val->type == VAL_STRUCT && val->data.struct_val) {
        StructValue *sv = val->data.struct_val;
        for (size_t i = 0; i < sv->field_count; ++i) {
            free(sv->fields[i].name);
            value_free(sv->fields[i].value);
            free(sv->fields[i].value);
        }
        free(sv->fields);
        free(sv->type_name);
        free(sv);
        val->data.struct_val = NULL;
    }
}

char *value_to_string(Value *val)
{
    char buf[256];
    switch (val->type) {
        case VAL_INT:
            snprintf(buf, sizeof(buf), "%ld", val->data.int_val);
            break;
        case VAL_FLOAT:
            snprintf(buf, sizeof(buf), "%g", val->data.float_val);
            break;
        case VAL_STRING:
            return val->data.string_val ? strdup(val->data.string_val) : strdup("");
        case VAL_VOID:
            return strdup("void");
        default:
            return strdup("<unknown>");
    }
    return strdup(buf);
}

void value_print(Value *val)
{
    switch (val->type) {
        case VAL_INT:
            printf("%ld", val->data.int_val);
            break;
        case VAL_FLOAT:
            printf("%g", val->data.float_val);
            break;
        case VAL_STRING:
            printf("%s", val->data.string_val ? val->data.string_val : "");
            break;
        case VAL_VOID:
            printf("void");
            break;
        default:
            printf("<unknown>");
            break;
    }
}

/* ========== Scope Functions ========== */

VarScope *scope_create(VarScope *parent)
{
    VarScope *scope = calloc(1, sizeof(VarScope));
    scope->parent = parent;
    return scope;
}

void scope_free(VarScope *scope)
{
    if (!scope) return;
    for (size_t i = 0; i < scope->count; ++i) {
        free(scope->vars[i].name);
        if (!scope->vars[i].is_borrowed) {
            value_free(&scope->vars[i].value);
        }
    }
    free(scope->vars);
    free(scope);
}

int scope_set_var(VarScope *scope, const char *name, Value val, DataType type)
{
    /* Check if variable already exists in current scope */
    for (size_t i = 0; i < scope->count; ++i) {
        if (strcmp(scope->vars[i].name, name) == 0) {
            if (!scope->vars[i].is_borrowed) {
                value_free(&scope->vars[i].value);
            }
            scope->vars[i].value = val;
            scope->vars[i].is_borrowed = 0;
            return 0;
        }
    }

    /* Add new variable */
    if (scope->count >= scope->capacity) {
        size_t new_cap = scope->capacity == 0 ? 8 : scope->capacity * 2;
        Variable *new_vars = realloc(scope->vars, new_cap * sizeof(Variable));
        if (!new_vars) return -1;
        scope->vars = new_vars;
        scope->capacity = new_cap;
    }

    scope->vars[scope->count].name = strdup(name);
    scope->vars[scope->count].value = val;
    scope->vars[scope->count].declared_type = type;
    scope->vars[scope->count].is_borrowed = 0;
    scope->count++;
    return 0;
}

Variable *scope_get_var(VarScope *scope, const char *name)
{
    VarScope *s = scope;
    while (s) {
        for (size_t i = 0; i < s->count; ++i) {
            if (strcmp(s->vars[i].name, name) == 0) {
                return &s->vars[i];
            }
        }
        s = s->parent;
    }
    return NULL;
}

/* Update variable in any scope (for assignments) */
static int scope_update_var(VarScope *scope, const char *name, Value val)
{
    VarScope *s = scope;
    while (s) {
        for (size_t i = 0; i < s->count; ++i) {
            if (strcmp(s->vars[i].name, name) == 0) {
                value_free(&s->vars[i].value);
                s->vars[i].value = val;
                return 0;
            }
        }
        s = s->parent;
    }
    return -1;  /* Variable not found */
}

/* ========== Function Registry ========== */

static void func_registry_init(FuncRegistry *reg)
{
    reg->funcs = NULL;
    reg->count = 0;
    reg->capacity = 0;
}

static void func_registry_free(FuncRegistry *reg)
{
    for (size_t i = 0; i < reg->count; ++i) {
        free(reg->funcs[i].name);
    }
    free(reg->funcs);
}

static int func_registry_add(FuncRegistry *reg, const char *name, ASTNode *node)
{
    if (reg->count >= reg->capacity) {
        size_t new_cap = reg->capacity == 0 ? 8 : reg->capacity * 2;
        FuncDef *new_funcs = realloc(reg->funcs, new_cap * sizeof(FuncDef));
        if (!new_funcs) return -1;
        reg->funcs = new_funcs;
        reg->capacity = new_cap;
    }
    reg->funcs[reg->count].name = strdup(name);
    reg->funcs[reg->count].ast_node = node;
    reg->count++;
    return 0;
}

static FuncDef *func_registry_get(FuncRegistry *reg, const char *name)
{
    for (size_t i = 0; i < reg->count; ++i) {
        if (strcmp(reg->funcs[i].name, name) == 0) {
            return &reg->funcs[i];
        }
    }
    return NULL;
}

/* ========== Interpreter ========== */

void interpreter_init(Interpreter *interp)
{
    func_registry_init(&interp->functions);
    interp->structs.defs = NULL;
    interp->structs.count = 0;
    interp->structs.capacity = 0;
    interp->current_scope = NULL;
    interp->error_msg = NULL;
    interp->error_line = 0;
    interp->exit_code = 0;
    interp->has_returned = 0;
    interp->has_break = 0;
    interp->has_continue = 0;
}

void interpreter_free(Interpreter *interp)
{
    func_registry_free(&interp->functions);
    /* Free struct registry */
    for (size_t i = 0; i < interp->structs.count; ++i) {
        free(interp->structs.defs[i].name);
    }
    free(interp->structs.defs);
    free(interp->error_msg);

    /* Free all scopes */
    while (interp->current_scope) {
        VarScope *parent = interp->current_scope->parent;
        scope_free(interp->current_scope);
        interp->current_scope = parent;
    }
}

static void set_runtime_error(Interpreter *interp, const char *msg, size_t line)
{
    if (interp->error_msg) return;
    interp->error_msg = strdup(msg);
    interp->error_line = line;
}

/* Forward declarations */
static Value eval_expression(Interpreter *interp, ASTNode *node);
static Value exec_statement(Interpreter *interp, ASTNode *node);
static Value exec_block(Interpreter *interp, ASTNodeList *stmts);

/* ========== Expression Evaluation ========== */

/* Process format string like "x = {x}, y = {y}" */
static char *process_format_string(Interpreter *interp, const char *format)
{
    size_t len = strlen(format);
    size_t result_cap = len * 2 + 1;
    char *result = malloc(result_cap);
    size_t result_len = 0;
    result[0] = '\0';

    for (size_t i = 0; i < len; ++i) {
        if (format[i] == '{') {
            /* Find closing brace, handling nested parentheses */
            size_t start = i + 1;
            size_t end = start;
            int paren_depth = 0;
            while (end < len && (format[end] != '}' || paren_depth > 0)) {
                if (format[end] == '(') paren_depth++;
                else if (format[end] == ')') paren_depth--;
                ++end;
            }

            if (end < len) {
                /* Extract expression inside braces */
                size_t expr_len = end - start;
                char *expr = malloc(expr_len + 1);
                strncpy(expr, format + start, expr_len);
                expr[expr_len] = '\0';

                char *val_str = NULL;
                
                /* Check if it's a function call: name(...) */
                char *paren = strchr(expr, '(');
                if (paren && !strchr(expr, '[')) {
                    /* Parse function call */
                    size_t name_len = paren - expr;
                    char *func_name = malloc(name_len + 1);
                    strncpy(func_name, expr, name_len);
                    func_name[name_len] = '\0';
                    
                    /* Parse arguments */
                    char *args_start = paren + 1;
                    char *args_end = strrchr(args_start, ')');
                    
                    if (args_end) {
                        /* Create a mini AST for the function call */
                        ASTNode *call_node = ast_create(AST_FUNC_CALL, 0, 0);
                        if (!call_node) {
                            free(func_name);
                            val_str = strdup("<error>");
                        } else {
                            call_node->data.func_call.name = func_name;
                            ast_list_init(&call_node->data.func_call.args);
                            
                            /* Parse arguments (simple: just one arg for now) */
                            size_t args_len = args_end - args_start;
                            if (args_len > 0) {
                                char *arg_expr = malloc(args_len + 1);
                                strncpy(arg_expr, args_start, args_len);
                                arg_expr[args_len] = '\0';
                                
                                /* Check if arg is a variable - if so, get its value and use as number */
                                Variable *arg_var = scope_get_var(interp->current_scope, arg_expr);
                                ASTNode *arg_node = ast_create(AST_NUMBER, 0, 0);
                                if (arg_node) {
                                    if (arg_var) {
                                        /* Use the variable's value directly as a number */
                                        if (arg_var->value.type == VAL_INT) {
                                            arg_node->data.number.value = (double)arg_var->value.data.int_val;
                                            arg_node->data.number.is_float = 0;
                                        } else if (arg_var->value.type == VAL_FLOAT) {
                                            arg_node->data.number.value = arg_var->value.data.float_val;
                                            arg_node->data.number.is_float = 1;
                                        } else {
                                            arg_node->data.number.value = 0;
                                            arg_node->data.number.is_float = 0;
                                        }
                                    } else {
                                        /* Try as number */
                                        arg_node->data.number.value = atof(arg_expr);
                                        arg_node->data.number.is_float = (strchr(arg_expr, '.') != NULL);
                                    }
                                    ast_list_push(&call_node->data.func_call.args, arg_node);
                                }
                                free(arg_expr);
                            }
                            
                            /* Evaluate the function call */
                            Value call_result = eval_expression(interp, call_node);
                            val_str = value_to_string(&call_result);
                            value_free(&call_result);
                            ast_free(call_node);
                        }
                    } else {
                        free(func_name);
                        val_str = strdup("<error>");
                    }
                }
                /* Check if it's an array access: name[index] */
                else if (strchr(expr, '[')) {
                    char *bracket = strchr(expr, '[');
                    /* Parse array access */
                    size_t name_len = bracket - expr;
                    char *arr_name = malloc(name_len + 1);
                    strncpy(arr_name, expr, name_len);
                    arr_name[name_len] = '\0';
                    
                    /* Parse index expression */
                    char *idx_start = bracket + 1;
                    char *idx_end = strchr(idx_start, ']');
                    if (idx_end) {
                        size_t idx_len = idx_end - idx_start;
                        char *idx_expr = malloc(idx_len + 1);
                        strncpy(idx_expr, idx_start, idx_len);
                        idx_expr[idx_len] = '\0';
                        
                        /* Get the array variable */
                        Variable *arr_var = scope_get_var(interp->current_scope, arr_name);
                        if (arr_var && arr_var->value.type == VAL_ARRAY) {
                            /* Evaluate index - could be a variable or a number */
                            long index = 0;
                            Variable *idx_var = scope_get_var(interp->current_scope, idx_expr);
                            if (idx_var && idx_var->value.type == VAL_INT) {
                                index = idx_var->value.data.int_val;
                            } else {
                                /* Try parsing as number */
                                index = atol(idx_expr);
                            }
                            
                            Value elem = array_get_element(arr_var->value.data.array_val, (size_t)index);
                            val_str = value_to_string(&elem);
                            value_free(&elem);
                        } else {
                            val_str = strdup("<undefined>");
                        }
                        free(idx_expr);
                    } else {
                        val_str = strdup("<undefined>");
                    }
                    free(arr_name);
                } else if (strchr(expr, '.')) {
                    /* Struct field access: struct.field (or pointer->field) */
                    char *dot = strchr(expr, '.');
                    size_t struct_name_len = dot - expr;
                    char *struct_name = malloc(struct_name_len + 1);
                    strncpy(struct_name, expr, struct_name_len);
                    struct_name[struct_name_len] = '\0';
                    char *field_name = dot + 1;
                    
                    Variable *var = scope_get_var(interp->current_scope, struct_name);
                    if (var) {
                        if (var->value.type == VAL_STRUCT) {
                            Value field_val = struct_get_field(var->value.data.struct_val, field_name);
                            val_str = value_to_string(&field_val);
                            value_free(&field_val);
                        } else if (var->value.type == VAL_POINTER && var->value.data.ptr_val) {
                            /* Pointer to struct */
                            Variable *target = var->value.data.ptr_val;
                            if (target->value.type == VAL_STRUCT) {
                                Value field_val = struct_get_field(target->value.data.struct_val, field_name);
                                val_str = value_to_string(&field_val);
                                value_free(&field_val);
                            } else {
                                val_str = strdup("<undefined>");
                            }
                        } else {
                            val_str = strdup("<undefined>");
                        }
                    } else {
                        val_str = strdup("<undefined>");
                    }
                    free(struct_name);
                } else {
                    /* Simple variable */
                    Variable *var = scope_get_var(interp->current_scope, expr);
                    if (var) {
                        /* Check if it's a char type - print as character */
                        if (var->declared_type == TYPE_CHAR && var->value.type == VAL_INT) {
                            val_str = malloc(2);
                            val_str[0] = (char)var->value.data.int_val;
                            val_str[1] = '\0';
                        } else {
                            val_str = value_to_string(&var->value);
                        }
                    } else {
                        val_str = strdup("<undefined>");
                    }
                }

                /* Append to result */
                size_t val_len = strlen(val_str);
                if (result_len + val_len >= result_cap) {
                    result_cap = result_cap * 2 + val_len;
                    result = realloc(result, result_cap);
                }
                strcpy(result + result_len, val_str);
                result_len += val_len;

                free(expr);
                free(val_str);
                i = end;  /* Skip past '}' */
                continue;
            }
        }

        /* Regular character */
        if (result_len + 1 >= result_cap) {
            result_cap *= 2;
            result = realloc(result, result_cap);
        }
        result[result_len++] = format[i];
        result[result_len] = '\0';
    }

    return result;
}

static Value eval_expression(Interpreter *interp, ASTNode *node)
{
    if (!node) return value_create_void();

    switch (node->type) {
        case AST_NUMBER:
            if (node->data.number.is_float) {
                return value_create_float(node->data.number.value);
            } else {
                return value_create_int((long)node->data.number.value);
            }

        case AST_STRING:
            return value_create_string(node->data.string.value);

        case AST_IDENTIFIER: {
            Variable *var = scope_get_var(interp->current_scope, node->data.identifier.name);
            if (!var) {
                char msg[256];
                snprintf(msg, sizeof(msg), "Undefined variable '%s'", node->data.identifier.name);
                set_runtime_error(interp, msg, node->line);
                return value_create_void();
            }
            /* Copy the value */
            Value v = var->value;
            if (v.type == VAL_STRING) {
                v.data.string_val = strdup(var->value.data.string_val);
            }
            return v;
        }

        case AST_ARRAY_ACCESS: {
            Variable *var = scope_get_var(interp->current_scope, node->data.array_access.array_name);
            if (!var) {
                char msg[256];
                snprintf(msg, sizeof(msg), "Undefined array '%s'", node->data.array_access.array_name);
                set_runtime_error(interp, msg, node->line);
                return value_create_void();
            }
            if (var->value.type != VAL_ARRAY) {
                char msg[256];
                snprintf(msg, sizeof(msg), "'%s' is not an array", node->data.array_access.array_name);
                set_runtime_error(interp, msg, node->line);
                return value_create_void();
            }
            
            Value idx_val = eval_expression(interp, node->data.array_access.index);
            size_t index = (size_t)idx_val.data.int_val;
            
            return array_get_element(var->value.data.array_val, index);
        }

        case AST_BINARY_OP: {
            Value left = eval_expression(interp, node->data.binary_op.left);
            Value right = eval_expression(interp, node->data.binary_op.right);
            const char *op = node->data.binary_op.op;

            /* String concatenation */
            if (strcmp(op, "+") == 0 && (left.type == VAL_STRING || right.type == VAL_STRING)) {
                char *left_str = value_to_string(&left);
                char *right_str = value_to_string(&right);
                size_t len = strlen(left_str) + strlen(right_str) + 1;
                char *result = malloc(len);
                strcpy(result, left_str);
                strcat(result, right_str);
                free(left_str);
                free(right_str);
                value_free(&left);
                value_free(&right);
                Value v = value_create_string(result);
                free(result);
                return v;
            }

            /* Numeric operations */
            int is_float = (left.type == VAL_FLOAT || right.type == VAL_FLOAT);
            double l = (left.type == VAL_FLOAT) ? left.data.float_val : (double)left.data.int_val;
            double r = (right.type == VAL_FLOAT) ? right.data.float_val : (double)right.data.int_val;

            value_free(&left);
            value_free(&right);

            if (strcmp(op, "+") == 0) {
                return is_float ? value_create_float(l + r) : value_create_int((long)(l + r));
            } else if (strcmp(op, "-") == 0) {
                return is_float ? value_create_float(l - r) : value_create_int((long)(l - r));
            } else if (strcmp(op, "*") == 0) {
                return is_float ? value_create_float(l * r) : value_create_int((long)(l * r));
            } else if (strcmp(op, "/") == 0) {
                if (r == 0) {
                    set_runtime_error(interp, "Division by zero", node->line);
                    return value_create_int(0);
                }
                return is_float ? value_create_float(l / r) : value_create_int((long)(l / r));
            } else if (strcmp(op, "%") == 0) {
                if ((long)r == 0) {
                    set_runtime_error(interp, "Modulo by zero", node->line);
                    return value_create_int(0);
                }
                return value_create_int((long)l % (long)r);
            } else if (strcmp(op, "<") == 0) {
                return value_create_int(l < r ? 1 : 0);
            } else if (strcmp(op, ">") == 0) {
                return value_create_int(l > r ? 1 : 0);
            } else if (strcmp(op, "<=") == 0) {
                return value_create_int(l <= r ? 1 : 0);
            } else if (strcmp(op, ">=") == 0) {
                return value_create_int(l >= r ? 1 : 0);
            } else if (strcmp(op, "==") == 0) {
                return value_create_int(l == r ? 1 : 0);
            } else if (strcmp(op, "!=") == 0) {
                return value_create_int(l != r ? 1 : 0);
            }

            return value_create_void();
        }

        case AST_UNARY_OP: {
            Value operand = eval_expression(interp, node->data.unary_op.operand);
            const char *op = node->data.unary_op.op;

            if (strcmp(op, "-") == 0) {
                if (operand.type == VAL_FLOAT) {
                    return value_create_float(-operand.data.float_val);
                } else {
                    return value_create_int(-operand.data.int_val);
                }
            } else if (strcmp(op, "+") == 0) {
                return operand;
            }
            return operand;
        }

        case AST_DEREF: {
            /* Dereference: *ptr - get value at pointer location */
            Value ptr_val = eval_expression(interp, node->data.deref.operand);
            if (ptr_val.type != VAL_POINTER) {
                set_runtime_error(interp, "Cannot dereference non-pointer", node->line);
                return value_create_void();
            }
            /* Return copied value from the pointer target */
            Variable *target = ptr_val.data.ptr_val;
            if (!target) {
                set_runtime_error(interp, "Null pointer dereference", node->line);
                return value_create_void();
            }
            Value v = target->value;
            if (v.type == VAL_STRING && v.data.string_val) {
                v.data.string_val = strdup(target->value.data.string_val);
            }
            return v;
        }

        case AST_ADDRESS_OF: {
            /* Address-of: &var - get pointer to variable */
            const char *var_name = node->data.address_of.var_name;
            Variable *var = scope_get_var(interp->current_scope, var_name);
            if (!var) {
                char msg[256];
                snprintf(msg, sizeof(msg), "Undefined variable '%s'", var_name);
                set_runtime_error(interp, msg, node->line);
                return value_create_void();
            }
            /* Create a pointer value pointing to this variable */
            Value ptr = { .type = VAL_POINTER, .data.ptr_val = var };
            return ptr;
        }

        case AST_FUNC_CALL: {
            const char *func_name = node->data.func_call.name;
            FuncDef *func = func_registry_get(&interp->functions, func_name);

            if (!func) {
                char msg[256];
                snprintf(msg, sizeof(msg), "Undefined function '%s'", func_name);
                set_runtime_error(interp, msg, node->line);
                return value_create_void();
            }

            ASTNode *func_node = func->ast_node;

            /* Evaluate arguments BEFORE switching scope (in caller's scope) */
            size_t param_count = func_node->data.func_def.params.count;
            size_t arg_count = node->data.func_call.args.count;
            Value *arg_values = NULL;
            if (arg_count > 0) {
                arg_values = malloc(arg_count * sizeof(Value));
                for (size_t i = 0; i < arg_count; ++i) {
                    arg_values[i] = eval_expression(interp, node->data.func_call.args.items[i]);
                }
            }

            /* Create new scope for function */
            VarScope *old_scope = interp->current_scope;
            interp->current_scope = scope_create(NULL);  /* Functions have their own scope */

            /* Bind parameters with pre-evaluated argument values */
            for (size_t i = 0; i < param_count && i < arg_count; ++i) {
                FuncParam *param = &func_node->data.func_def.params.items[i];
                scope_set_var(interp->current_scope, param->name, arg_values[i], param->type);
                
                /* Mark array parameters as borrowed (they belong to caller's scope) */
                if (arg_values[i].type == VAL_ARRAY) {
                    Variable *var = scope_get_var(interp->current_scope, param->name);
                    if (var) var->is_borrowed = 1;
                }
            }
            free(arg_values);

            /* Execute function body */
            interp->has_returned = 0;
            Value result = exec_block(interp, &func_node->data.func_def.body);

            /* Restore scope */
            scope_free(interp->current_scope);
            interp->current_scope = old_scope;
            interp->has_returned = 0;

            return result;
        }

        case AST_STRUCT_ACCESS: {
            /* Access struct field: struct.field (or enum: EnumName.Member, or pointer->field) */
            const char *struct_name = node->data.struct_access.struct_name;
            const char *field_name = node->data.struct_access.field_name;
            
            Variable *var = scope_get_var(interp->current_scope, struct_name);
            if (!var) {
                /* Try as combined identifier (enum access: EnumName.Member) */
                char combined[512];
                snprintf(combined, sizeof(combined), "%s.%s", struct_name, field_name);
                Variable *enum_var = scope_get_var(interp->current_scope, combined);
                if (enum_var) {
                    Value v = enum_var->value;
                    if (v.type == VAL_STRING && v.data.string_val) {
                        v.data.string_val = strdup(enum_var->value.data.string_val);
                    }
                    return v;
                }
                char msg[256];
                snprintf(msg, sizeof(msg), "Undefined variable '%s'", struct_name);
                set_runtime_error(interp, msg, node->line);
                return value_create_void();
            }
            
            /* Check if it's a pointer to struct */
            if (var->value.type == VAL_POINTER) {
                Variable *target = var->value.data.ptr_val;
                if (target && target->value.type == VAL_STRUCT) {
                    return struct_get_field(target->value.data.struct_val, field_name);
                }
                char msg[256];
                snprintf(msg, sizeof(msg), "'%s' pointer does not point to a struct", struct_name);
                set_runtime_error(interp, msg, node->line);
                return value_create_void();
            }
            
            if (var->value.type != VAL_STRUCT) {
                /* Not a struct - try as combined identifier */
                char combined[512];
                snprintf(combined, sizeof(combined), "%s.%s", struct_name, field_name);
                Variable *enum_var = scope_get_var(interp->current_scope, combined);
                if (enum_var) {
                    Value v = enum_var->value;
                    if (v.type == VAL_STRING && v.data.string_val) {
                        v.data.string_val = strdup(enum_var->value.data.string_val);
                    }
                    return v;
                }
                char msg[256];
                snprintf(msg, sizeof(msg), "'%s' is not a struct", struct_name);
                set_runtime_error(interp, msg, node->line);
                return value_create_void();
            }
            
            return struct_get_field(var->value.data.struct_val, field_name);
        }

        default:
            return value_create_void();
    }
}

/* ========== Statement Execution ========== */

static Value exec_statement(Interpreter *interp, ASTNode *node)
{
    if (!node || interp->has_returned) return value_create_void();

    switch (node->type) {
        case AST_VAR_DECL: {
            Value init_val;
            DataType var_type = node->data.var_decl.var_type;
            
            /* Check if this is an array type with size specification */
            int is_array_type = (var_type == TYPE_INT_ARRAY || var_type == TYPE_FLOAT_ARRAY ||
                                 var_type == TYPE_STRING_ARRAY || var_type == TYPE_CHAR_ARRAY);
            
            if (is_array_type && node->data.var_decl.init_value && 
                node->data.var_decl.init_value->type == AST_NUMBER) {
                /* Array with size: int[4] - create array with pre-allocated size */
                size_t size = (size_t)node->data.var_decl.init_value->data.number.value;
                ValueType elem_type = VAL_INT;
                if (var_type == TYPE_FLOAT_ARRAY) elem_type = VAL_FLOAT;
                else if (var_type == TYPE_STRING_ARRAY) elem_type = VAL_STRING;
                
                init_val = value_create_array(elem_type);
                /* Pre-allocate array with zeros */
                for (size_t i = 0; i < size; ++i) {
                    Value zero = value_create_int(0);
                    array_set_element(init_val.data.array_val, i, zero);
                }
            } else if (node->data.var_decl.init_value) {
                init_val = eval_expression(interp, node->data.var_decl.init_value);
            } else {
                /* Default initialization based on type */
                switch (var_type) {
                    case TYPE_INT:
                        init_val = value_create_int(0);
                        break;
                    case TYPE_FLOAT:
                        init_val = value_create_float(0.0);
                        break;
                    case TYPE_STRING:
                        init_val = value_create_string("");
                        break;
                    case TYPE_INT_ARRAY:
                        init_val = value_create_array(VAL_INT);
                        break;
                    case TYPE_FLOAT_ARRAY:
                        init_val = value_create_array(VAL_FLOAT);
                        break;
                    case TYPE_STRING_ARRAY:
                        init_val = value_create_array(VAL_STRING);
                        break;
                    case TYPE_CHAR_ARRAY:
                        init_val = value_create_array(VAL_INT);  /* char stored as int */
                        break;
                    case TYPE_UNKNOWN:
                        /* Check if this is a struct type */
                        if (node->data.var_decl.struct_type_name) {
                            init_val = value_create_struct(node->data.var_decl.struct_type_name);
                        } else {
                            init_val = value_create_void();
                        }
                        break;
                    default:
                        init_val = value_create_void();
                        break;
                }
            }
            scope_set_var(interp->current_scope, node->data.var_decl.name,
                         init_val, var_type);
            return value_create_void();
        }

        case AST_ASSIGNMENT: {
            Value val = eval_expression(interp, node->data.assignment.value);

            /* Try to update existing variable */
            if (scope_update_var(interp->current_scope, node->data.assignment.var_name, val) != 0) {
                char msg[256];
                snprintf(msg, sizeof(msg), "Undefined variable '%s'", node->data.assignment.var_name);
                set_runtime_error(interp, msg, node->line);
                value_free(&val);
            }
            return value_create_void();
        }

        case AST_ARRAY_ASSIGN: {
            Variable *var = scope_get_var(interp->current_scope, node->data.array_assign.array_name);
            if (!var) {
                char msg[256];
                snprintf(msg, sizeof(msg), "Undefined array '%s'", node->data.array_assign.array_name);
                set_runtime_error(interp, msg, node->line);
                return value_create_void();
            }
            if (var->value.type != VAL_ARRAY) {
                char msg[256];
                snprintf(msg, sizeof(msg), "'%s' is not an array", node->data.array_assign.array_name);
                set_runtime_error(interp, msg, node->line);
                return value_create_void();
            }
            
            Value idx_val = eval_expression(interp, node->data.array_assign.index);
            Value val = eval_expression(interp, node->data.array_assign.value);
            
            size_t index = (size_t)idx_val.data.int_val;
            array_set_element(var->value.data.array_val, index, val);
            
            return value_create_void();
        }

        case AST_STRUCT_ASSIGN: {
            /* Struct field assignment: struct.field = value (or struct_ptr.field = value) */
            const char *struct_name = node->data.struct_assign.struct_name;
            const char *field_name = node->data.struct_assign.field_name;
            
            Variable *var = scope_get_var(interp->current_scope, struct_name);
            if (!var) {
                char msg[256];
                snprintf(msg, sizeof(msg), "Undefined struct variable '%s'", struct_name);
                set_runtime_error(interp, msg, node->line);
                return value_create_void();
            }
            
            /* Check if it's a pointer to struct */
            if (var->value.type == VAL_POINTER) {
                Variable *target = var->value.data.ptr_val;
                if (target && target->value.type == VAL_STRUCT) {
                    Value val = eval_expression(interp, node->data.struct_assign.value);
                    struct_set_field(target->value.data.struct_val, field_name, val);
                    return value_create_void();
                }
                char msg[256];
                snprintf(msg, sizeof(msg), "'%s' pointer does not point to a struct", struct_name);
                set_runtime_error(interp, msg, node->line);
                return value_create_void();
            }
            
            if (var->value.type != VAL_STRUCT) {
                char msg[256];
                snprintf(msg, sizeof(msg), "'%s' is not a struct", struct_name);
                set_runtime_error(interp, msg, node->line);
                return value_create_void();
            }
            
            Value val = eval_expression(interp, node->data.struct_assign.value);
            struct_set_field(var->value.data.struct_val, field_name, val);
            
            return value_create_void();
        }

        case AST_DEREF_ASSIGN: {
            /* Pointer assignment: *ptr = value */
            /* First evaluate the pointer expression to get the target variable */
            Value ptr_val = eval_expression(interp, node->data.deref_assign.ptr);
            if (ptr_val.type != VAL_POINTER) {
                set_runtime_error(interp, "Cannot dereference non-pointer for assignment", node->line);
                return value_create_void();
            }
            Variable *target = ptr_val.data.ptr_val;
            if (!target) {
                set_runtime_error(interp, "Null pointer assignment", node->line);
                return value_create_void();
            }
            
            /* Evaluate the value to assign */
            Value val = eval_expression(interp, node->data.deref_assign.value);
            
            /* Free the old value and assign new value */
            value_free(&target->value);
            target->value = val;
            
            return value_create_void();
        }

        case AST_RETURN: {
            Value val = eval_expression(interp, node->data.return_stmt.value);
            interp->has_returned = 1;
            val.is_return = 1;
            return val;
        }

        case AST_PRINT: {
            Value val = eval_expression(interp, node->data.print_stmt.value);

            if (val.type == VAL_STRING && val.data.string_val) {
                /* Process format string */
                char *formatted = process_format_string(interp, val.data.string_val);
                printf("%s\n", formatted);
                free(formatted);
            } else {
                value_print(&val);
                printf("\n");
            }
            value_free(&val);
            return value_create_void();
        }

        case AST_IF: {
            Value cond = eval_expression(interp, node->data.conditional.condition);
            int is_true = 0;

            if (cond.type == VAL_INT) {
                is_true = (cond.data.int_val != 0);
            } else if (cond.type == VAL_FLOAT) {
                is_true = (cond.data.float_val != 0.0);
            }
            value_free(&cond);

            if (is_true) {
                return exec_block(interp, &node->data.conditional.body);
            } else if (node->data.conditional.else_body.count > 0) {
                return exec_block(interp, &node->data.conditional.else_body);
            }
            return value_create_void();
        }

        case AST_WHILE: {
            while (!interp->has_returned && !interp->has_break) {
                Value cond = eval_expression(interp, node->data.conditional.condition);
                int is_true = 0;

                if (cond.type == VAL_INT) {
                    is_true = (cond.data.int_val != 0);
                } else if (cond.type == VAL_FLOAT) {
                    is_true = (cond.data.float_val != 0.0);
                }
                value_free(&cond);

                if (!is_true) break;

                Value result = exec_block(interp, &node->data.conditional.body);
                if (interp->has_returned) {
                    return result;
                }
                if (interp->has_continue) {
                    interp->has_continue = 0;  /* Reset continue flag for next iteration */
                }
                if (interp->has_break) {
                    interp->has_break = 0;  /* Reset break flag */
                    value_free(&result);
                    break;
                }
                value_free(&result);
            }
            return value_create_void();
        }

        case AST_FOR: {
            Value start_val = eval_expression(interp, node->data.for_loop.start);
            Value end_val = eval_expression(interp, node->data.for_loop.end);
            Value step_val;

            if (node->data.for_loop.step) {
                step_val = eval_expression(interp, node->data.for_loop.step);
            } else {
                step_val = value_create_int(1);
            }

            long start = (start_val.type == VAL_INT) ? start_val.data.int_val : (long)start_val.data.float_val;
            long end = (end_val.type == VAL_INT) ? end_val.data.int_val : (long)end_val.data.float_val;
            long step = (step_val.type == VAL_INT) ? step_val.data.int_val : (long)step_val.data.float_val;

            value_free(&start_val);
            value_free(&end_val);
            value_free(&step_val);

            /* Create loop variable */
            scope_set_var(interp->current_scope, node->data.for_loop.var_name,
                         value_create_int(start), TYPE_INT);

            for (long i = start; (step > 0 ? i < end : i > end) && !interp->has_returned && !interp->has_break; i += step) {
                /* Update loop variable */
                scope_update_var(interp->current_scope, node->data.for_loop.var_name,
                                value_create_int(i));

                Value result = exec_block(interp, &node->data.for_loop.body);
                if (interp->has_returned) {
                    return result;
                }
                if (interp->has_continue) {
                    interp->has_continue = 0;  /* Reset continue flag for next iteration */
                }
                if (interp->has_break) {
                    interp->has_break = 0;  /* Reset break flag and exit loop */
                    value_free(&result);
                    break;
                }
                value_free(&result);
            }
            return value_create_void();
        }

        case AST_BREAK: {
            interp->has_break = 1;
            return value_create_void();
        }

        case AST_CONTINUE: {
            interp->has_continue = 1;
            return value_create_void();
        }

        default:
            /* Try to evaluate as expression */
            return eval_expression(interp, node);
    }
}

static Value exec_block(Interpreter *interp, ASTNodeList *stmts)
{
    Value last_val = value_create_void();

    for (size_t i = 0; i < stmts->count && !interp->has_returned && !interp->has_break && !interp->has_continue; ++i) {
        value_free(&last_val);
        last_val = exec_statement(interp, stmts->items[i]);

        if (interp->has_returned || last_val.is_return) {
            return last_val;
        }
    }

    return last_val;
}

/* ========== Main Interpreter Entry Point ========== */

int interpreter_run(Interpreter *interp, ASTNode *program)
{
    if (!program || program->type != AST_PROGRAM) {
        set_runtime_error(interp, "Invalid program AST", 0);
        return 1;
    }

    /* Register all functions */
    for (size_t i = 0; i < program->data.program.functions.count; ++i) {
        ASTNode *func = program->data.program.functions.items[i];
        if (func->type == AST_FUNCTION_DEF) {
            func_registry_add(&interp->functions, func->data.func_def.name, func);
        }
    }

    /* Register all struct definitions */
    for (size_t i = 0; i < program->data.program.structs.count; ++i) {
        ASTNode *struct_node = program->data.program.structs.items[i];
        if (struct_node->type == AST_STRUCT_DEF) {
            if (interp->structs.count >= interp->structs.capacity) {
                size_t new_cap = interp->structs.capacity == 0 ? 8 : interp->structs.capacity * 2;
                interp->structs.defs = realloc(interp->structs.defs, new_cap * sizeof(StructDefRT));
                interp->structs.capacity = new_cap;
            }
            interp->structs.defs[interp->structs.count].name = strdup(struct_node->data.struct_def.name);
            interp->structs.defs[interp->structs.count].ast_node = struct_node;
            interp->structs.count++;
        }
    }

    /* Find and call the main function (Eric) */
    FuncDef *main_func = func_registry_get(&interp->functions, "Eric");
    if (!main_func) {
        set_runtime_error(interp, "No 'Eric' (main) function found", 0);
        return 1;
    }

    /* Create global scope */
    interp->current_scope = scope_create(NULL);

    /* Register global constants */
    for (size_t i = 0; i < program->data.program.constants.count; ++i) {
        ASTNode *const_node = program->data.program.constants.items[i];
        if (const_node->type == AST_CONST_DECL) {
            Value val = eval_expression(interp, const_node->data.const_decl.value);
            scope_set_var(interp->current_scope, const_node->data.const_decl.name, val, const_node->data.const_decl.const_type);
        }
    }

    /* Register enum values as integer constants (EnumName.Member = index) */
    for (size_t i = 0; i < program->data.program.enums.count; ++i) {
        ASTNode *enum_node = program->data.program.enums.items[i];
        if (enum_node->type == AST_ENUM_DEF) {
            for (size_t j = 0; j < enum_node->data.enum_def.member_count; ++j) {
                /* Create variable name: EnumName.MemberName */
                char var_name[256];
                snprintf(var_name, sizeof(var_name), "%s.%s", 
                         enum_node->data.enum_def.name,
                         enum_node->data.enum_def.members[j]);
                Value val = value_create_int((long)j);
                scope_set_var(interp->current_scope, var_name, val, TYPE_INT);
                
                /* Also register just by member name for direct access */
                scope_set_var(interp->current_scope, enum_node->data.enum_def.members[j], val, TYPE_INT);
            }
        }
    }

    /* Execute main function */
    ASTNode *main_node = main_func->ast_node;
    Value result = exec_block(interp, &main_node->data.func_def.body);

    /* Get exit code from return value */
    if (result.type == VAL_INT) {
        interp->exit_code = (int)result.data.int_val;
    } else {
        interp->exit_code = 0;
    }

    value_free(&result);

    if (interp->error_msg) {
        fprintf(stderr, "Runtime error at line %zu: %s\n",
                interp->error_line, interp->error_msg);
        return 1;
    }

    return interp->exit_code;
}
