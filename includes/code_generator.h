/**==============================================
 *                 code_generator.h
 *  Code generator for x86-64 assembly
 *  Author: shirosaaki
 *  Date: 2025-11-27
 *=============================================**/

#ifndef CODE_GENERATOR_H_
    #define CODE_GENERATOR_H_
    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>
    #include <stdint.h>
    #include "parser.h"

/* ========== Code Buffer ========== */
typedef struct {
    uint8_t *data;
    size_t size;
    size_t capacity;
} CodeBuffer;

/* ========== String Table for data section ========== */
typedef struct {
    char *str;
    size_t offset;  /* Offset in data section */
} StringEntry;

typedef struct {
    StringEntry *items;
    size_t count;
    size_t capacity;
    size_t total_size;
} StringTable;

/* ========== Variable for stack management ========== */
typedef struct {
    char *name;
    int stack_offset;  /* Negative offset from RBP */
    DataType type;
    size_t string_data_offset;  /* For TYPE_STRING: offset in data section */
    size_t string_length;       /* For TYPE_STRING: length of the string */
    int is_array;               /* 1 if this is an array */
    int is_pointer_array;       /* 1 if this is an array passed by pointer (function param) */
    size_t array_capacity;      /* Maximum elements in array */
    int array_size_offset;      /* Stack offset for current array size (for auto-fill) */
    int array_last_val_offset;  /* Stack offset for last value (for auto-fill) */
} StackVar;

typedef struct {
    StackVar *items;
    size_t count;
    size_t capacity;
    int current_offset;  /* Current stack offset */
} StackFrame;

/* ========== Function info ========== */
typedef struct {
    char *name;
    size_t code_offset;  /* Offset in code section */
    FuncParamList params;
    DataType return_type;
} FunctionInfo;

typedef struct {
    FunctionInfo *items;
    size_t count;
    size_t capacity;
} FunctionTable;

/* ========== Label for jumps ========== */
typedef struct {
    size_t offset;
    int resolved;
} Label;

/* ========== Patch location for forward references ========== */
typedef struct {
    size_t patch_offset;  /* Where to patch in code */
    int label_id;         /* Which label to patch to */
} PatchEntry;

typedef struct {
    PatchEntry *items;
    size_t count;
    size_t capacity;
} PatchList;

/* ========== String relocation entries ========== */
typedef struct {
    size_t code_offset;   /* Offset in code section where the imm64 starts */
    size_t string_offset; /* Offset in string table */
} StringReloc;

typedef struct {
    StringReloc *items;
    size_t count;
    size_t capacity;
} StringRelocTable;

/* ========== Code Generator State ========== */
typedef struct {
    CodeBuffer code;          /* .text section */
    CodeBuffer data;          /* .data section (strings) */
    StringTable strings;
    StringRelocTable string_relocs;  /* Track string references for patching */
    StackFrame stack;
    FunctionTable functions;
    
    /* Labels for control flow */
    Label *labels;
    size_t label_count;
    size_t label_capacity;
    PatchList patches;
    
    /* Current function being compiled */
    char *current_function;
    
    /* Loop context for break/continue */
    int loop_start_label;     /* Label for continue (start of loop) */
    int loop_end_label;       /* Label for break (end of loop) */
    int in_loop;              /* Whether we're inside a loop */
    
    /* Constants and enums from program */
    ASTNodeList *constants;   /* Pointer to program's constants list */
    ASTNodeList *enums;       /* Pointer to program's enums list */
    
    /* Error handling */
    char *error_msg;
    size_t error_line;
    
    /* Entry point offset */
    size_t entry_point;
} CodeGenerator;

/* ========== Code Generator Functions ========== */

/* Initialize/free the code generator */
void codegen_init(CodeGenerator *gen);
void codegen_free(CodeGenerator *gen);

/* Compile the AST to machine code */
int codegen_compile(CodeGenerator *gen, ASTNode *program);

/* Write the generated code to an ELF file */
int codegen_write_elf(CodeGenerator *gen, const char *filename);

/* Buffer operations */
void buffer_init(CodeBuffer *buf);
void buffer_free(CodeBuffer *buf);
int buffer_write(CodeBuffer *buf, const void *data, size_t size);
int buffer_write_byte(CodeBuffer *buf, uint8_t byte);
int buffer_write_u32(CodeBuffer *buf, uint32_t val);
int buffer_write_u64(CodeBuffer *buf, uint64_t val);

/* String table operations */
void string_table_init(StringTable *st);
void string_table_free(StringTable *st);
size_t string_table_add(StringTable *st, const char *str);

/* Stack frame operations */
void stack_frame_init(StackFrame *sf);
void stack_frame_free(StackFrame *sf);
int stack_frame_push_var(StackFrame *sf, const char *name, DataType type);
int stack_frame_push_array(StackFrame *sf, const char *name, DataType type, size_t capacity);
StackVar *stack_frame_find(StackFrame *sf, const char *name);
void stack_frame_clear(StackFrame *sf);

/* Function table operations */
void func_table_init(FunctionTable *ft);
void func_table_free(FunctionTable *ft);
int func_table_add(FunctionTable *ft, const char *name, size_t offset, 
                   FuncParamList *params, DataType return_type);
FunctionInfo *func_table_find(FunctionTable *ft, const char *name);

/* Label operations */
int codegen_create_label(CodeGenerator *gen);
void codegen_set_label(CodeGenerator *gen, int label_id);
void codegen_patch_label(CodeGenerator *gen, int label_id, size_t patch_offset);

#endif /* !CODE_GENERATOR_H_ */
