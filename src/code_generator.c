/**==============================================
 *                 code_generator.c
 *  x86-64 code generator implementation
 *  Author: shirosaaki
 *  Date: 2025-11-27
 *=============================================**/

#include "../includes/code_generator.h"
#include <elf.h>
#include <sys/stat.h>
#include <ctype.h>

/* Base address for the executable */
#define BASE_ADDR 0x400000
#define PAGE_SIZE 0x1000

/* Trim leading/trailing whitespace in-place */
static void trim_whitespace(char *str)
{
    if (!str) return;
    char *start = str;
    while (*start && isspace((unsigned char)*start)) start++;
    char *end = start + strlen(start);
    while (end > start && isspace((unsigned char)*(end - 1))) end--;
    size_t len = (size_t)(end - start);
    if (start != str) memmove(str, start, len);
    str[len] = '\0';
}

/* ========== Buffer Operations ========== */

void buffer_init(CodeBuffer *buf)
{
    buf->data = NULL;
    buf->size = 0;
    buf->capacity = 0;
}

void buffer_free(CodeBuffer *buf)
{
    free(buf->data);
    buf->data = NULL;
    buf->size = 0;
    buf->capacity = 0;
}

static int buffer_ensure(CodeBuffer *buf, size_t needed)
{
    if (buf->size + needed <= buf->capacity) return 0;
    size_t new_cap = buf->capacity == 0 ? 256 : buf->capacity * 2;
    while (new_cap < buf->size + needed) new_cap *= 2;
    uint8_t *new_data = realloc(buf->data, new_cap);
    if (!new_data) return -1;
    buf->data = new_data;
    buf->capacity = new_cap;
    return 0;
}

int buffer_write(CodeBuffer *buf, const void *data, size_t size)
{
    if (buffer_ensure(buf, size) != 0) return -1;
    memcpy(buf->data + buf->size, data, size);
    buf->size += size;
    return 0;
}

int buffer_write_byte(CodeBuffer *buf, uint8_t byte)
{
    return buffer_write(buf, &byte, 1);
}

int buffer_write_u32(CodeBuffer *buf, uint32_t val)
{
    return buffer_write(buf, &val, 4);
}

int buffer_write_u64(CodeBuffer *buf, uint64_t val)
{
    return buffer_write(buf, &val, 8);
}

/* ========== String Table Operations ========== */

void string_table_init(StringTable *st)
{
    st->items = NULL;
    st->count = 0;
    st->capacity = 0;
    st->total_size = 0;
}

void string_table_free(StringTable *st)
{
    for (size_t i = 0; i < st->count; ++i) {
        free(st->items[i].str);
    }
    free(st->items);
    st->items = NULL;
    st->count = 0;
    st->capacity = 0;
    st->total_size = 0;
}

size_t string_table_add(StringTable *st, const char *str)
{
    /* Check if string already exists */
    for (size_t i = 0; i < st->count; ++i) {
        if (strcmp(st->items[i].str, str) == 0) {
            return st->items[i].offset;
        }
    }

    /* Add new string */
    if (st->count >= st->capacity) {
        size_t new_cap = st->capacity == 0 ? 8 : st->capacity * 2;
        StringEntry *new_items = realloc(st->items, new_cap * sizeof(StringEntry));
        if (!new_items) return (size_t)-1;
        st->items = new_items;
        st->capacity = new_cap;
    }

    size_t offset = st->total_size;
    st->items[st->count].str = strdup(str);
    st->items[st->count].offset = offset;
    st->count++;
    st->total_size += strlen(str) + 1;  /* +1 for null terminator */
    return offset;
}

/* Get length of string given its offset */
size_t string_table_get_length(StringTable *st, size_t offset)
{
    for (size_t i = 0; i < st->count; ++i) {
        if (st->items[i].offset == offset) {
            return strlen(st->items[i].str);
        }
    }
    return 0;
}

/* ========== String Relocation Table Operations ========== */

void string_reloc_init(StringRelocTable *srt)
{
    srt->items = NULL;
    srt->count = 0;
    srt->capacity = 0;
}

void string_reloc_free(StringRelocTable *srt)
{
    free(srt->items);
    srt->items = NULL;
    srt->count = 0;
    srt->capacity = 0;
}

void string_reloc_add(StringRelocTable *srt, size_t code_offset, size_t string_offset)
{
    if (srt->count >= srt->capacity) {
        size_t new_cap = srt->capacity == 0 ? 16 : srt->capacity * 2;
        StringReloc *new_items = realloc(srt->items, new_cap * sizeof(StringReloc));
        if (!new_items) return;
        srt->items = new_items;
        srt->capacity = new_cap;
    }
    srt->items[srt->count].code_offset = code_offset;
    srt->items[srt->count].string_offset = string_offset;
    srt->count++;
}

/* ========== Stack Frame Operations ========== */

void stack_frame_init(StackFrame *sf)
{
    sf->items = NULL;
    sf->count = 0;
    sf->capacity = 0;
    sf->current_offset = 0;
}

void stack_frame_free(StackFrame *sf)
{
    for (size_t i = 0; i < sf->count; ++i) {
        free(sf->items[i].name);
        free(sf->items[i].struct_name);
    }
    free(sf->items);
    sf->items = NULL;
    sf->count = 0;
    sf->capacity = 0;
    sf->current_offset = 0;
}

int stack_frame_push_var(StackFrame *sf, const char *name, DataType type)
{
    /* Check if variable already exists - reuse its slot */
    for (size_t i = 0; i < sf->count; ++i) {
        if (strcmp(sf->items[i].name, name) == 0) {
            /* Variable already exists, just update type if needed */
            sf->items[i].type = type;
            return 0;
        }
    }
    
    if (sf->count >= sf->capacity) {
        size_t new_cap = sf->capacity == 0 ? 8 : sf->capacity * 2;
        StackVar *new_items = realloc(sf->items, new_cap * sizeof(StackVar));
        if (!new_items) return -1;
        sf->items = new_items;
        sf->capacity = new_cap;
    }

    sf->current_offset -= 8;  /* 8 bytes for each variable (64-bit) */
    sf->items[sf->count].name = strdup(name);
    sf->items[sf->count].stack_offset = sf->current_offset;
    sf->items[sf->count].type = type;
    sf->items[sf->count].struct_name = NULL;
    sf->items[sf->count].string_data_offset = 0;
    sf->items[sf->count].string_length = 0;
    sf->items[sf->count].is_array = 0;
    sf->items[sf->count].is_pointer_array = 0;
    sf->items[sf->count].array_capacity = 0;
    sf->items[sf->count].array_size_offset = 0;
    sf->items[sf->count].array_last_val_offset = 0;
    sf->count++;
    return 0;
}

int stack_frame_push_array(StackFrame *sf, const char *name, DataType type, size_t capacity)
{
    if (sf->count >= sf->capacity) {
        size_t new_cap = sf->capacity == 0 ? 8 : sf->capacity * 2;
        StackVar *new_items = realloc(sf->items, new_cap * sizeof(StackVar));
        if (!new_items) return -1;
        sf->items = new_items;
        sf->capacity = new_cap;
    }

    /* Allocate: 8 bytes per element + 8 bytes for size + 8 bytes for last_val */
    size_t array_size = capacity * 8;
    sf->current_offset -= (int)array_size;
    int array_base = sf->current_offset;
    
    /* Allocate space for current size tracker */
    sf->current_offset -= 8;
    int size_offset = sf->current_offset;
    
    /* Allocate space for last value tracker */
    sf->current_offset -= 8;
    int last_val_offset = sf->current_offset;
    
    sf->items[sf->count].name = strdup(name);
    sf->items[sf->count].stack_offset = array_base;  /* Points to base of array */
    sf->items[sf->count].type = type;
    sf->items[sf->count].struct_name = NULL;
    sf->items[sf->count].string_data_offset = 0;
    sf->items[sf->count].string_length = 0;
    sf->items[sf->count].is_array = 1;
    sf->items[sf->count].is_pointer_array = 0;  /* Stack-allocated, not pointer */
    sf->items[sf->count].array_capacity = capacity;
    sf->items[sf->count].array_size_offset = size_offset;
    sf->items[sf->count].array_last_val_offset = last_val_offset;
    sf->count++;
    return 0;
}

StackVar *stack_frame_find(StackFrame *sf, const char *name)
{
    for (size_t i = 0; i < sf->count; ++i) {
        if (strcmp(sf->items[i].name, name) == 0) {
            return &sf->items[i];
        }
    }
    return NULL;
}

void stack_frame_clear(StackFrame *sf)
{
    for (size_t i = 0; i < sf->count; ++i) {
        free(sf->items[i].name);
        free(sf->items[i].struct_name);
    }
    sf->count = 0;
    sf->current_offset = 0;
}

/* ========== Function Table Operations ========== */

void func_table_init(FunctionTable *ft)
{
    ft->items = NULL;
    ft->count = 0;
    ft->capacity = 0;
}

void func_table_free(FunctionTable *ft)
{
    for (size_t i = 0; i < ft->count; ++i) {
        free(ft->items[i].name);
        param_list_free(&ft->items[i].params);
    }
    free(ft->items);
    ft->items = NULL;
    ft->count = 0;
    ft->capacity = 0;
}

int func_table_add(FunctionTable *ft, const char *name, size_t offset,
                   FuncParamList *params, DataType return_type)
{
    if (ft->count >= ft->capacity) {
        size_t new_cap = ft->capacity == 0 ? 8 : ft->capacity * 2;
        FunctionInfo *new_items = realloc(ft->items, new_cap * sizeof(FunctionInfo));
        if (!new_items) return -1;
        ft->items = new_items;
        ft->capacity = new_cap;
    }

    ft->items[ft->count].name = strdup(name);
    ft->items[ft->count].code_offset = offset;
    param_list_init(&ft->items[ft->count].params);
    if (params) {
        for (size_t i = 0; i < params->count; ++i) {
            FuncParam p = {strdup(params->items[i].name), params->items[i].type, 
                          params->items[i].struct_type_name ? strdup(params->items[i].struct_type_name) : NULL};
            param_list_push(&ft->items[ft->count].params, p);
        }
    }
    ft->items[ft->count].return_type = return_type;
    ft->count++;
    return 0;
}

FunctionInfo *func_table_find(FunctionTable *ft, const char *name)
{
    for (size_t i = 0; i < ft->count; ++i) {
        if (strcmp(ft->items[i].name, name) == 0) {
            return &ft->items[i];
        }
    }
    return NULL;
}

/* ========== Struct Definition Table Operations ========== */

void struct_def_table_init(StructDefTable *sdt)
{
    sdt->items = NULL;
    sdt->count = 0;
    sdt->capacity = 0;
}

void struct_def_table_free(StructDefTable *sdt)
{
    for (size_t i = 0; i < sdt->count; ++i) {
        free(sdt->items[i].name);
        struct_field_list_free(&sdt->items[i].fields);
    }
    free(sdt->items);
    sdt->items = NULL;
    sdt->count = 0;
    sdt->capacity = 0;
}

int struct_def_table_add(StructDefTable *sdt, const char *name, StructFieldList *fields)
{
    if (sdt->count >= sdt->capacity) {
        size_t new_cap = sdt->capacity == 0 ? 16 : sdt->capacity * 2;
        StructDefInfo *new_items = realloc(sdt->items, new_cap * sizeof(StructDefInfo));
        if (!new_items) return -1;
        sdt->items = new_items;
        sdt->capacity = new_cap;
    }
    sdt->items[sdt->count].name = strdup(name);
    sdt->items[sdt->count].fields.items = NULL;
    sdt->items[sdt->count].fields.count = 0;
    sdt->items[sdt->count].fields.capacity = 0;
    
    /* Copy fields */
    for (size_t i = 0; i < fields->count; ++i) {
        StructField field;
        field.name = strdup(fields->items[i].name);
        field.type = fields->items[i].type;
        struct_field_list_push(&sdt->items[sdt->count].fields, field);
    }
    
    sdt->count++;
    return 0;
}

StructDefInfo *struct_def_table_find(StructDefTable *sdt, const char *name)
{
    for (size_t i = 0; i < sdt->count; ++i) {
        if (strcmp(sdt->items[i].name, name) == 0) {
            return &sdt->items[i];
        }
    }
    return NULL;
}

/* Helper function to calculate the size of a struct field (handles nested structs) */
static size_t calc_field_size(StructDefTable *sdt, const char *field_name, DataType field_type)
{
    if (field_type == TYPE_STRING) {
        return 16;  /* 8 bytes for address, 8 bytes for length */
    } else if (field_type != TYPE_UNKNOWN) {
        return 8;   /* Basic types are 8 bytes */
    }
    
    /* TYPE_UNKNOWN might be a nested struct - try to find it */
    /* Try capitalized version of field name (e.g., "stats" -> "Stats") */
    char nested_name[64];
    strncpy(nested_name, field_name, sizeof(nested_name) - 1);
    nested_name[0] = toupper(nested_name[0]);
    nested_name[sizeof(nested_name) - 1] = '\0';
    
    StructDefInfo *nested = struct_def_table_find(sdt, nested_name);
    if (!nested) {
        /* Try exact name */
        nested = struct_def_table_find(sdt, field_name);
    }
    
    if (nested) {
        /* Calculate nested struct size recursively */
        size_t nested_size = 0;
        for (size_t i = 0; i < nested->fields.count; i++) {
            nested_size += calc_field_size(sdt, nested->fields.items[i].name, 
                                           nested->fields.items[i].type);
        }
        return nested_size;
    }
    
    /* Unknown type, default to 8 bytes */
    return 8;
}

/* Helper function to calculate total struct size including nested structs */
static size_t calc_struct_size(StructDefTable *sdt, StructDefInfo *struct_def)
{
    size_t total_size = 0;
    for (size_t i = 0; i < struct_def->fields.count; i++) {
        total_size += calc_field_size(sdt, struct_def->fields.items[i].name,
                                      struct_def->fields.items[i].type);
    }
    return total_size;
}

/* Helper function to calculate field offset within a struct (for nested access) */
static int calc_field_offset(StructDefTable *sdt, StructDefInfo *struct_def, 
                             const char *field_path, DataType *out_type)
{
    if (!struct_def || !field_path) return -1;
    char *path_copy = strdup(field_path);
    char *saveptr;
    char *field_token = strtok_r(path_copy, ".", &saveptr);
    
    int total_offset = 0;
    StructDefInfo *current_struct = struct_def;
    DataType final_type = TYPE_UNKNOWN;
    
    while (field_token && current_struct) {
        int field_offset = 0;
        int found = 0;
        StructDefInfo *nested_struct = NULL;
        DataType field_type = TYPE_UNKNOWN;
        
        for (size_t i = 0; i < current_struct->fields.count; ++i) {
            if (strcmp(current_struct->fields.items[i].name, field_token) == 0) {
                found = 1;
                field_type = current_struct->fields.items[i].type;
                
                /* Check if this field is a nested struct */
                char nested_name[64];
                strncpy(nested_name, field_token, sizeof(nested_name) - 1);
                nested_name[0] = toupper(nested_name[0]);
                nested_name[sizeof(nested_name) - 1] = '\0';
                nested_struct = struct_def_table_find(sdt, nested_name);
                if (!nested_struct) {
                    nested_struct = struct_def_table_find(sdt, field_token);
                }
                break;
            }
            /* Calculate offset using field size */
            field_offset += (int)calc_field_size(sdt, current_struct->fields.items[i].name,
                                                  current_struct->fields.items[i].type);
        }
        
        if (!found) {
            free(path_copy);
            return -1;  /* Field not found */
        }
        
        total_offset += field_offset;
        final_type = field_type;
        current_struct = nested_struct;
        field_token = strtok_r(NULL, ".", &saveptr);
    }
    
    if (out_type) *out_type = final_type;
    free(path_copy);
    return total_offset;
}

/* ========== Label Operations ========== */

int codegen_create_label(CodeGenerator *gen)
{
    if (gen->label_count >= gen->label_capacity) {
        size_t new_cap = gen->label_capacity == 0 ? 16 : gen->label_capacity * 2;
        Label *new_labels = realloc(gen->labels, new_cap * sizeof(Label));
        if (!new_labels) return -1;
        gen->labels = new_labels;
        gen->label_capacity = new_cap;
    }
    int id = (int)gen->label_count;
    gen->labels[gen->label_count].offset = 0;
    gen->labels[gen->label_count].resolved = 0;
    gen->label_count++;
    return id;
}

void codegen_set_label(CodeGenerator *gen, int label_id)
{
    if (label_id >= 0 && (size_t)label_id < gen->label_count) {
        gen->labels[label_id].offset = gen->code.size;
        gen->labels[label_id].resolved = 1;
    }
}

void codegen_patch_label(CodeGenerator *gen, int label_id, size_t patch_offset)
{
    if (gen->patches.count >= gen->patches.capacity) {
        size_t new_cap = gen->patches.capacity == 0 ? 16 : gen->patches.capacity * 2;
        PatchEntry *new_patches = realloc(gen->patches.items, new_cap * sizeof(PatchEntry));
        if (!new_patches) return;
        gen->patches.items = new_patches;
        gen->patches.capacity = new_cap;
    }
    gen->patches.items[gen->patches.count].patch_offset = patch_offset;
    gen->patches.items[gen->patches.count].label_id = label_id;
    gen->patches.count++;
}

static void codegen_resolve_patches(CodeGenerator *gen)
{
    for (size_t i = 0; i < gen->patches.count; ++i) {
        int label_id = gen->patches.items[i].label_id;
        size_t patch_offset = gen->patches.items[i].patch_offset;
        
        if (label_id >= 0 && (size_t)label_id < gen->label_count && 
            gen->labels[label_id].resolved) {
            /* Calculate relative offset (target - (patch_location + 4)) */
            int32_t rel = (int32_t)(gen->labels[label_id].offset - (patch_offset + 4));
            memcpy(gen->code.data + patch_offset, &rel, 4);
        }
    }
}

/* ========== Code Generator Init/Free ========== */

void codegen_init(CodeGenerator *gen)
{
    buffer_init(&gen->code);
    buffer_init(&gen->data);
    string_table_init(&gen->strings);
    string_reloc_init(&gen->string_relocs);
    stack_frame_init(&gen->stack);
    func_table_init(&gen->functions);
    struct_def_table_init(&gen->struct_defs);
    
    gen->labels = NULL;
    gen->label_count = 0;
    gen->label_capacity = 0;
    
    gen->patches.items = NULL;
    gen->patches.count = 0;
    gen->patches.capacity = 0;
    
    gen->current_function = NULL;
    gen->loop_start_label = -1;
    gen->loop_end_label = -1;
    gen->in_loop = 0;
    gen->constants = NULL;
    gen->enums = NULL;
    gen->structs = NULL;
    gen->error_msg = NULL;
    gen->error_line = 0;
    gen->entry_point = 0;
}

void codegen_free(CodeGenerator *gen)
{
    buffer_free(&gen->code);
    buffer_free(&gen->data);
    string_table_free(&gen->strings);
    string_reloc_free(&gen->string_relocs);
    stack_frame_free(&gen->stack);
    func_table_free(&gen->functions);
    struct_def_table_free(&gen->struct_defs);
    
    free(gen->labels);
    free(gen->patches.items);
    free(gen->current_function);
    free(gen->error_msg);
}

/* ========== x86-64 Instruction Encoding ========== */

/* REX prefix for 64-bit operations */
static void emit_rex_w(CodeGenerator *gen)
{
    buffer_write_byte(&gen->code, 0x48);
}

/* mov eax, imm32 (for syscall numbers and small constants - won't be patched) */
static void emit_mov_eax_imm32(CodeGenerator *gen, uint32_t val)
{
    buffer_write_byte(&gen->code, 0xB8);  /* mov eax, imm32 */
    buffer_write_u32(&gen->code, val);
}

/* mov edi, imm32 (for fd and small constants - won't be patched) */
static void emit_mov_edi_imm32(CodeGenerator *gen, uint32_t val)
{
    buffer_write_byte(&gen->code, 0xBF);  /* mov edi, imm32 */
    buffer_write_u32(&gen->code, val);
}

/* mov rax, imm64 */
static void emit_mov_rax_imm64(CodeGenerator *gen, uint64_t val)
{
    emit_rex_w(gen);
    buffer_write_byte(&gen->code, 0xB8);  /* mov rax, imm64 */
    buffer_write_u64(&gen->code, val);
}

/* mov rax, string_offset (with relocation tracking) */
static void emit_mov_rax_string_offset(CodeGenerator *gen, size_t str_offset)
{
    emit_rex_w(gen);
    buffer_write_byte(&gen->code, 0xB8);  /* mov rax, imm64 */
    /* Record relocation: the imm64 starts at current position */
    string_reloc_add(&gen->string_relocs, gen->code.size, str_offset);
    buffer_write_u64(&gen->code, str_offset);  /* Will be patched to actual address */
}

/* mov rsi, string_offset (with relocation tracking) */
static void emit_mov_rsi_string_offset(CodeGenerator *gen, size_t str_offset)
{
    emit_rex_w(gen);
    buffer_write_byte(&gen->code, 0xBE);  /* mov rsi, imm64 */
    /* Record relocation: the imm64 starts at current position */
    string_reloc_add(&gen->string_relocs, gen->code.size, str_offset);
    buffer_write_u64(&gen->code, str_offset);  /* Will be patched to actual address */
}

/* mov rdi, imm64 */
__attribute__((unused))
static void emit_mov_rdi_imm64(CodeGenerator *gen, uint64_t val)
{
    emit_rex_w(gen);
    buffer_write_byte(&gen->code, 0xBF);  /* mov rdi, imm64 */
    buffer_write_u64(&gen->code, val);
}

/* mov rsi, imm64 */
static void emit_mov_rsi_imm64(CodeGenerator *gen, uint64_t val)
{
    emit_rex_w(gen);
    buffer_write_byte(&gen->code, 0xBE);  /* mov rsi, imm64 */
    buffer_write_u64(&gen->code, val);
}

/* mov rdx, imm64 */
static void emit_mov_rdx_imm64(CodeGenerator *gen, uint64_t val)
{
    emit_rex_w(gen);
    buffer_write_byte(&gen->code, 0xBA);  /* mov rdx, imm64 */
    buffer_write_u64(&gen->code, val);
}

/* mov [rbp+offset], rax */
static void emit_mov_rbp_offset_rax(CodeGenerator *gen, int32_t offset)
{
    emit_rex_w(gen);
    buffer_write_byte(&gen->code, 0x89);  /* mov r/m64, r64 */
    buffer_write_byte(&gen->code, 0x85);  /* ModRM: [rbp+disp32], rax */
    buffer_write_u32(&gen->code, (uint32_t)offset);
}

/* mov rax, [rbp+offset] */
static void emit_mov_rax_rbp_offset(CodeGenerator *gen, int32_t offset)
{
    emit_rex_w(gen);
    buffer_write_byte(&gen->code, 0x8B);  /* mov r64, r/m64 */
    buffer_write_byte(&gen->code, 0x85);  /* ModRM: rax, [rbp+disp32] */
    buffer_write_u32(&gen->code, (uint32_t)offset);
}

/* push rbp */
static void emit_push_rbp(CodeGenerator *gen)
{
    buffer_write_byte(&gen->code, 0x55);
}

/* pop rbp */
static void emit_pop_rbp(CodeGenerator *gen)
{
    buffer_write_byte(&gen->code, 0x5D);
}

/* mov rax, rsp */
static void emit_mov_rax_rsp(CodeGenerator *gen)
{
    emit_rex_w(gen);
    buffer_write_byte(&gen->code, 0x89);
    buffer_write_byte(&gen->code, 0xE0);
}

/* mov rbp, rsp */
static void emit_mov_rbp_rsp(CodeGenerator *gen)
{
    emit_rex_w(gen);
    buffer_write_byte(&gen->code, 0x89);
    buffer_write_byte(&gen->code, 0xE5);
}

/* mov rsp, rbp */
static void emit_mov_rsp_rbp(CodeGenerator *gen)
{
    emit_rex_w(gen);
    buffer_write_byte(&gen->code, 0x89);
    buffer_write_byte(&gen->code, 0xEC);
}

/* sub rsp, imm32 */
static void emit_sub_rsp_imm32(CodeGenerator *gen, int32_t val)
{
    emit_rex_w(gen);
    buffer_write_byte(&gen->code, 0x81);
    buffer_write_byte(&gen->code, 0xEC);
    buffer_write_u32(&gen->code, (uint32_t)val);
}

/* add rsp, imm32 */
static void emit_add_rsp_imm32(CodeGenerator *gen, int32_t val)
{
    emit_rex_w(gen);
    buffer_write_byte(&gen->code, 0x81);
    buffer_write_byte(&gen->code, 0xC4);
    buffer_write_u32(&gen->code, (uint32_t)val);
}

/* push rax */
static void emit_push_rax(CodeGenerator *gen)
{
    buffer_write_byte(&gen->code, 0x50);
}

/* pop rax */
static void emit_pop_rax(CodeGenerator *gen)
{
    buffer_write_byte(&gen->code, 0x58);
}

/* pop rbx */
static void emit_pop_rbx(CodeGenerator *gen)
{
    buffer_write_byte(&gen->code, 0x5B);
}

/* push rbx */
static void emit_push_rbx(CodeGenerator *gen)
{
    buffer_write_byte(&gen->code, 0x53);
}

/* push r12 */
static void emit_push_r12(CodeGenerator *gen)
{
    buffer_write_byte(&gen->code, 0x41);
    buffer_write_byte(&gen->code, 0x54);
}

/* pop r12 */
static void emit_pop_r12(CodeGenerator *gen)
{
    buffer_write_byte(&gen->code, 0x41);
    buffer_write_byte(&gen->code, 0x5C);
}

/* push r13 */
static void emit_push_r13(CodeGenerator *gen)
{
    buffer_write_byte(&gen->code, 0x41);
    buffer_write_byte(&gen->code, 0x55);
}

/* pop r13 */
static void emit_pop_r13(CodeGenerator *gen)
{
    buffer_write_byte(&gen->code, 0x41);
    buffer_write_byte(&gen->code, 0x5D);
}

/* mov r12, rax */
static void emit_mov_r12_rax(CodeGenerator *gen)
{
    buffer_write_byte(&gen->code, 0x49);  /* REX.WB */
    buffer_write_byte(&gen->code, 0x89);
    buffer_write_byte(&gen->code, 0xC4);  /* rax -> r12 */
}

/* mov r13, rax */
static void emit_mov_r13_rax(CodeGenerator *gen)
{
    buffer_write_byte(&gen->code, 0x49);  /* REX.WB */
    buffer_write_byte(&gen->code, 0x89);
    buffer_write_byte(&gen->code, 0xC5);  /* rax -> r13 */
}

/* mov rax, r12 */
static void emit_mov_rax_r12(CodeGenerator *gen)
{
    buffer_write_byte(&gen->code, 0x4C);  /* REX.WR */
    buffer_write_byte(&gen->code, 0x89);
    buffer_write_byte(&gen->code, 0xE0);  /* r12 -> rax */
}

/* mov rax, r13 */
static void emit_mov_rax_r13(CodeGenerator *gen)
{
    buffer_write_byte(&gen->code, 0x4C);  /* REX.WR */
    buffer_write_byte(&gen->code, 0x89);
    buffer_write_byte(&gen->code, 0xE8);  /* r13 -> rax */
}

/* mov rcx, r13 */
static void emit_mov_rcx_r13(CodeGenerator *gen)
{
    buffer_write_byte(&gen->code, 0x4C);  /* REX.WR */
    buffer_write_byte(&gen->code, 0x89);
    buffer_write_byte(&gen->code, 0xE9);  /* r13 -> rcx */
}

/* mov rcx, r12 */
static void emit_mov_rcx_r12(CodeGenerator *gen)
{
    buffer_write_byte(&gen->code, 0x4C);  /* REX.WR */
    buffer_write_byte(&gen->code, 0x89);
    buffer_write_byte(&gen->code, 0xE1);  /* r12 -> rcx */
}

/* inc r13 */
static void emit_inc_r13(CodeGenerator *gen)
{
    buffer_write_byte(&gen->code, 0x49);  /* REX.WB */
    buffer_write_byte(&gen->code, 0xFF);
    buffer_write_byte(&gen->code, 0xC5);
}

/* cmp r13, r12 */
static void emit_cmp_r13_r12(CodeGenerator *gen)
{
    buffer_write_byte(&gen->code, 0x4D);  /* REX.WRB */
    buffer_write_byte(&gen->code, 0x39);
    buffer_write_byte(&gen->code, 0xE5);  /* cmp r13, r12 */
}

/* ret */
static void emit_ret(CodeGenerator *gen)
{
    buffer_write_byte(&gen->code, 0xC3);
}

/* syscall */
static void emit_syscall(CodeGenerator *gen)
{
    buffer_write_byte(&gen->code, 0x0F);
    buffer_write_byte(&gen->code, 0x05);
}

/* add rax, rbx */
static void emit_add_rax_rbx(CodeGenerator *gen)
{
    emit_rex_w(gen);
    buffer_write_byte(&gen->code, 0x01);
    buffer_write_byte(&gen->code, 0xD8);
}

/* inc rcx */
static void emit_inc_rcx(CodeGenerator *gen)
{
    emit_rex_w(gen);
    buffer_write_byte(&gen->code, 0xFF);
    buffer_write_byte(&gen->code, 0xC1);
}

/* mov rcx, rax */
static void emit_mov_rcx_rax(CodeGenerator *gen)
{
    emit_rex_w(gen);
    buffer_write_byte(&gen->code, 0x89);
    buffer_write_byte(&gen->code, 0xC1);
}

/* mov rax, rcx */
static void emit_mov_rax_rcx(CodeGenerator *gen)
{
    emit_rex_w(gen);
    buffer_write_byte(&gen->code, 0x89);
    buffer_write_byte(&gen->code, 0xC8);
}

/* mov rax, rbx */
static void emit_mov_rax_rbx(CodeGenerator *gen)
{
    emit_rex_w(gen);
    buffer_write_byte(&gen->code, 0x89);
    buffer_write_byte(&gen->code, 0xD8);
}

/* cmp rcx, rbx */
static void emit_cmp_rcx_rbx(CodeGenerator *gen)
{
    emit_rex_w(gen);
    buffer_write_byte(&gen->code, 0x39);
    buffer_write_byte(&gen->code, 0xD9);
}

/* cmp rax, rcx */
static void emit_cmp_rax_rcx(CodeGenerator *gen)
{
    emit_rex_w(gen);
    buffer_write_byte(&gen->code, 0x39);
    buffer_write_byte(&gen->code, 0xC8);
}

/* push rcx */
static void emit_push_rcx(CodeGenerator *gen)
{
    buffer_write_byte(&gen->code, 0x51);
}

/* pop rcx */
static void emit_pop_rcx(CodeGenerator *gen)
{
    buffer_write_byte(&gen->code, 0x59);
}

/* sub rax, rbx */
static void emit_sub_rax_rbx(CodeGenerator *gen)
{
    emit_rex_w(gen);
    buffer_write_byte(&gen->code, 0x29);
    buffer_write_byte(&gen->code, 0xD8);
}

/* imul rax, rbx */
static void emit_imul_rax_rbx(CodeGenerator *gen)
{
    emit_rex_w(gen);
    buffer_write_byte(&gen->code, 0x0F);
    buffer_write_byte(&gen->code, 0xAF);
    buffer_write_byte(&gen->code, 0xC3);
}

/* xor rdx, rdx (for div) */
static void emit_xor_rdx_rdx(CodeGenerator *gen)
{
    emit_rex_w(gen);
    buffer_write_byte(&gen->code, 0x31);
    buffer_write_byte(&gen->code, 0xD2);
}

/* mov rbx, rax */
static void emit_mov_rbx_rax(CodeGenerator *gen)
{
    emit_rex_w(gen);
    buffer_write_byte(&gen->code, 0x89);
    buffer_write_byte(&gen->code, 0xC3);
}

/* imul rbx, rbx, 8 - multiply rbx by 8 */
static void emit_imul_rbx_8(CodeGenerator *gen)
{
    emit_rex_w(gen);
    buffer_write_byte(&gen->code, 0x6B);  /* imul r64, r/m64, imm8 */
    buffer_write_byte(&gen->code, 0xDB);  /* rbx, rbx */
    buffer_write_byte(&gen->code, 0x08);  /* 8 */
}

/* imul rcx, rcx, 8 */
static void emit_imul_rcx_8(CodeGenerator *gen)
{
    emit_rex_w(gen);
    buffer_write_byte(&gen->code, 0x6B);  /* imul r64, r/m64, imm8 */
    buffer_write_byte(&gen->code, 0xC9);  /* rcx, rcx */
    buffer_write_byte(&gen->code, 0x08);  /* 8 */
}

/* add rax, rcx */
static void emit_add_rax_rcx(CodeGenerator *gen)
{
    emit_rex_w(gen);
    buffer_write_byte(&gen->code, 0x01);
    buffer_write_byte(&gen->code, 0xC8);
}

/* lea rax, [rbp + offset] */
static void emit_lea_rax_rbp_offset(CodeGenerator *gen, int32_t offset)
{
    emit_rex_w(gen);
    buffer_write_byte(&gen->code, 0x8D);  /* lea */
    buffer_write_byte(&gen->code, 0x85);  /* rax, [rbp + disp32] */
    buffer_write(&gen->code, &offset, 4);
}

/* mov rax, [rax] - load value from address in rax */
static void emit_mov_rax_ptr_rax(CodeGenerator *gen)
{
    emit_rex_w(gen);
    buffer_write_byte(&gen->code, 0x8B);  /* mov */
    buffer_write_byte(&gen->code, 0x00);  /* rax, [rax] */
}

/* mov [rax], rbx - store rbx at address in rax */
static void emit_mov_ptr_rax_rbx(CodeGenerator *gen)
{
    emit_rex_w(gen);
    buffer_write_byte(&gen->code, 0x89);  /* mov */
    buffer_write_byte(&gen->code, 0x18);  /* [rax], rbx */
}

/* mov [rbx], rax - store rax at address in rbx */
static void emit_mov_ptr_rbx_rax(CodeGenerator *gen)
{
    emit_rex_w(gen);
    buffer_write_byte(&gen->code, 0x89);  /* mov */
    buffer_write_byte(&gen->code, 0x03);  /* [rbx], rax */
}

/* idiv rbx */
static void emit_idiv_rbx(CodeGenerator *gen)
{
    emit_rex_w(gen);
    buffer_write_byte(&gen->code, 0xF7);
    buffer_write_byte(&gen->code, 0xFB);
}

/* cmp rax, rbx */
static void emit_cmp_rax_rbx(CodeGenerator *gen)
{
    emit_rex_w(gen);
    buffer_write_byte(&gen->code, 0x39);
    buffer_write_byte(&gen->code, 0xD8);
}

/* cmp rax, 0 */
static void emit_cmp_rax_0(CodeGenerator *gen)
{
    emit_rex_w(gen);
    buffer_write_byte(&gen->code, 0x83);
    buffer_write_byte(&gen->code, 0xF8);
    buffer_write_byte(&gen->code, 0x00);
}

/* sete al */
static void emit_sete_al(CodeGenerator *gen)
{
    buffer_write_byte(&gen->code, 0x0F);
    buffer_write_byte(&gen->code, 0x94);
    buffer_write_byte(&gen->code, 0xC0);
}

/* setne al */
static void emit_setne_al(CodeGenerator *gen)
{
    buffer_write_byte(&gen->code, 0x0F);
    buffer_write_byte(&gen->code, 0x95);
    buffer_write_byte(&gen->code, 0xC0);
}

/* setl al */
static void emit_setl_al(CodeGenerator *gen)
{
    buffer_write_byte(&gen->code, 0x0F);
    buffer_write_byte(&gen->code, 0x9C);
    buffer_write_byte(&gen->code, 0xC0);
}

/* setle al */
static void emit_setle_al(CodeGenerator *gen)
{
    buffer_write_byte(&gen->code, 0x0F);
    buffer_write_byte(&gen->code, 0x9E);
    buffer_write_byte(&gen->code, 0xC0);
}

/* setg al */
static void emit_setg_al(CodeGenerator *gen)
{
    buffer_write_byte(&gen->code, 0x0F);
    buffer_write_byte(&gen->code, 0x9F);
    buffer_write_byte(&gen->code, 0xC0);
}

/* setge al */
static void emit_setge_al(CodeGenerator *gen)
{
    buffer_write_byte(&gen->code, 0x0F);
    buffer_write_byte(&gen->code, 0x9D);
    buffer_write_byte(&gen->code, 0xC0);
}

/* movzx rax, al */
static void emit_movzx_rax_al(CodeGenerator *gen)
{
    emit_rex_w(gen);
    buffer_write_byte(&gen->code, 0x0F);
    buffer_write_byte(&gen->code, 0xB6);
    buffer_write_byte(&gen->code, 0xC0);
}

/* je rel32 */
static void emit_je_rel32(CodeGenerator *gen, int32_t rel)
{
    buffer_write_byte(&gen->code, 0x0F);
    buffer_write_byte(&gen->code, 0x84);
    buffer_write_u32(&gen->code, (uint32_t)rel);
}

/* jne rel32 */
__attribute__((unused))
static void emit_jne_rel32(CodeGenerator *gen, int32_t rel)
{
    buffer_write_byte(&gen->code, 0x0F);
    buffer_write_byte(&gen->code, 0x85);
    buffer_write_u32(&gen->code, (uint32_t)rel);
}

/* jl rel32 - jump if less (signed) */
__attribute__((unused))
static void emit_jl_rel32(CodeGenerator *gen, int32_t rel)
{
    buffer_write_byte(&gen->code, 0x0F);
    buffer_write_byte(&gen->code, 0x8C);
    buffer_write_u32(&gen->code, (uint32_t)rel);
}

/* jle rel32 - jump if less or equal (signed) */
__attribute__((unused))
static void emit_jle_rel32(CodeGenerator *gen, int32_t rel)
{
    buffer_write_byte(&gen->code, 0x0F);
    buffer_write_byte(&gen->code, 0x8E);
    buffer_write_u32(&gen->code, (uint32_t)rel);
}

/* jge rel32 - jump if greater or equal (signed) */
static void emit_jge_rel32(CodeGenerator *gen, int32_t rel)
{
    buffer_write_byte(&gen->code, 0x0F);
    buffer_write_byte(&gen->code, 0x8D);
    buffer_write_u32(&gen->code, (uint32_t)rel);
}

/* jmp rel32 */
static void emit_jmp_rel32(CodeGenerator *gen, int32_t rel)
{
    buffer_write_byte(&gen->code, 0xE9);
    buffer_write_u32(&gen->code, (uint32_t)rel);
}

/* call rel32 */
static void emit_call_rel32(CodeGenerator *gen, int32_t rel)
{
    buffer_write_byte(&gen->code, 0xE8);
    buffer_write_u32(&gen->code, (uint32_t)rel);
}

/* ========== emit_print_int: Print integer in rax to stdout ========== */
/*
 * This emits inline code to convert the integer in rax to decimal string
 * and print it. Uses stack for buffer.
 */
static void emit_print_int(CodeGenerator *gen)
{
    /* 
     * We need to print the integer in rax.
     * Algorithm:
     * 1. Save rax (the value to print)
     * 2. Handle negative: if negative, print '-' and negate
     * 3. Divide by 10, push digits onto stack
     * 4. Pop and print each digit
     */
    
    /* Save all registers we'll clobber */
    buffer_write_byte(&gen->code, 0x53);        /* push rbx */
    buffer_write_byte(&gen->code, 0x51);        /* push rcx */
    buffer_write_byte(&gen->code, 0x52);        /* push rdx */
    buffer_write_byte(&gen->code, 0x56);        /* push rsi */
    buffer_write_byte(&gen->code, 0x57);        /* push rdi */
    
    /* Push rax to save the value */
    buffer_write_byte(&gen->code, 0x50);        /* push rax */
    
    /* Allocate 32 bytes buffer on stack */
    emit_rex_w(gen);
    buffer_write_byte(&gen->code, 0x83);
    buffer_write_byte(&gen->code, 0xEC);
    buffer_write_byte(&gen->code, 0x20);        /* sub rsp, 32 */
    
    /* rcx = buffer end pointer (rsp + 31) */
    emit_rex_w(gen);
    buffer_write_byte(&gen->code, 0x8D);        /* lea rcx, [rsp+31] */
    buffer_write_byte(&gen->code, 0x4C);
    buffer_write_byte(&gen->code, 0x24);
    buffer_write_byte(&gen->code, 0x1F);
    
    /* rbx = digit count = 0 */
    emit_rex_w(gen);
    buffer_write_byte(&gen->code, 0x31);        /* xor rbx, rbx */
    buffer_write_byte(&gen->code, 0xDB);
    
    /* rsi = negative flag = 0 */
    emit_rex_w(gen);
    buffer_write_byte(&gen->code, 0x31);        /* xor rsi, rsi */
    buffer_write_byte(&gen->code, 0xF6);
    
    /* Restore rax from saved value */
    emit_rex_w(gen);
    buffer_write_byte(&gen->code, 0x8B);        /* mov rax, [rsp+32] */
    buffer_write_byte(&gen->code, 0x44);
    buffer_write_byte(&gen->code, 0x24);
    buffer_write_byte(&gen->code, 0x20);
    
    /* Test if negative */
    emit_rex_w(gen);
    buffer_write_byte(&gen->code, 0x85);        /* test rax, rax */
    buffer_write_byte(&gen->code, 0xC0);
    
    /* jns skip_neg (jump if not negative) - skip 6 bytes */
    buffer_write_byte(&gen->code, 0x79);        /* jns +6 */
    buffer_write_byte(&gen->code, 0x06);
    
    /* neg rax */
    emit_rex_w(gen);
    buffer_write_byte(&gen->code, 0xF7);        /* neg rax */
    buffer_write_byte(&gen->code, 0xD8);
    
    /* rsi = 1 (negative flag) */
    emit_rex_w(gen);
    buffer_write_byte(&gen->code, 0xFF);        /* inc rsi */
    buffer_write_byte(&gen->code, 0xC6);
    
    /* rdi = 10 (divisor) */
    emit_rex_w(gen);
    buffer_write_byte(&gen->code, 0xC7);        /* mov edi, 10 */
    buffer_write_byte(&gen->code, 0xC7);
    buffer_write_u32(&gen->code, 10);
    
    /* Loop: convert to digits */
    size_t loop_start = gen->code.size;
    
    /* xor rdx, rdx */
    emit_rex_w(gen);
    buffer_write_byte(&gen->code, 0x31);        /* xor rdx, rdx */
    buffer_write_byte(&gen->code, 0xD2);
    
    /* div rdi */
    emit_rex_w(gen);
    buffer_write_byte(&gen->code, 0xF7);        /* div rdi */
    buffer_write_byte(&gen->code, 0xF7);
    
    /* add dl, '0' */
    buffer_write_byte(&gen->code, 0x80);        /* add dl, 0x30 */
    buffer_write_byte(&gen->code, 0xC2);
    buffer_write_byte(&gen->code, 0x30);
    
    /* dec rcx */
    emit_rex_w(gen);
    buffer_write_byte(&gen->code, 0xFF);        /* dec rcx */
    buffer_write_byte(&gen->code, 0xC9);
    
    /* mov [rcx], dl */
    buffer_write_byte(&gen->code, 0x88);        /* mov [rcx], dl */
    buffer_write_byte(&gen->code, 0x11);
    
    /* inc rbx (digit count) */
    emit_rex_w(gen);
    buffer_write_byte(&gen->code, 0xFF);        /* inc rbx */
    buffer_write_byte(&gen->code, 0xC3);
    
    /* test rax, rax */
    emit_rex_w(gen);
    buffer_write_byte(&gen->code, 0x85);        /* test rax, rax */
    buffer_write_byte(&gen->code, 0xC0);
    
    /* jnz loop */
    int8_t loop_offset = (int8_t)((int64_t)loop_start - (int64_t)(gen->code.size + 2));
    buffer_write_byte(&gen->code, 0x75);        /* jnz loop */
    buffer_write_byte(&gen->code, (uint8_t)loop_offset);
    
    /* Check negative flag */
    emit_rex_w(gen);
    buffer_write_byte(&gen->code, 0x85);        /* test rsi, rsi */
    buffer_write_byte(&gen->code, 0xF6);
    
    /* jz skip_minus - skip 9 bytes */
    buffer_write_byte(&gen->code, 0x74);        /* jz +9 */
    buffer_write_byte(&gen->code, 0x09);
    
    /* Add minus sign */
    /* dec rcx */
    emit_rex_w(gen);
    buffer_write_byte(&gen->code, 0xFF);        /* dec rcx */
    buffer_write_byte(&gen->code, 0xC9);
    
    /* mov byte [rcx], '-' */
    buffer_write_byte(&gen->code, 0xC6);        /* mov byte [rcx], 0x2D */
    buffer_write_byte(&gen->code, 0x01);
    buffer_write_byte(&gen->code, 0x2D);
    
    /* inc rbx */
    emit_rex_w(gen);
    buffer_write_byte(&gen->code, 0xFF);        /* inc rbx */
    buffer_write_byte(&gen->code, 0xC3);
    
    /* Now print: syscall write(1, rcx, rbx) */
    /* mov rax, 1 */
    emit_rex_w(gen);
    buffer_write_byte(&gen->code, 0xC7);        /* mov eax, 1 */
    buffer_write_byte(&gen->code, 0xC0);
    buffer_write_u32(&gen->code, 1);
    
    /* mov rdi, 1 */
    emit_rex_w(gen);
    buffer_write_byte(&gen->code, 0xC7);        /* mov edi, 1 */
    buffer_write_byte(&gen->code, 0xC7);
    buffer_write_u32(&gen->code, 1);
    
    /* mov rsi, rcx */
    emit_rex_w(gen);
    buffer_write_byte(&gen->code, 0x89);        /* mov rsi, rcx */
    buffer_write_byte(&gen->code, 0xCE);
    
    /* mov rdx, rbx */
    emit_rex_w(gen);
    buffer_write_byte(&gen->code, 0x89);        /* mov rdx, rbx */
    buffer_write_byte(&gen->code, 0xDA);
    
    /* syscall */
    emit_syscall(gen);
    
    /* Clean up stack: add rsp, 32 */
    emit_rex_w(gen);
    buffer_write_byte(&gen->code, 0x83);
    buffer_write_byte(&gen->code, 0xC4);
    buffer_write_byte(&gen->code, 0x20);
    
    /* Pop saved rax (discard) */
    buffer_write_byte(&gen->code, 0x58);        /* pop rax */
    
    /* Restore registers */
    buffer_write_byte(&gen->code, 0x5F);        /* pop rdi */
    buffer_write_byte(&gen->code, 0x5E);        /* pop rsi */
    buffer_write_byte(&gen->code, 0x5A);        /* pop rdx */
    buffer_write_byte(&gen->code, 0x59);        /* pop rcx */
    buffer_write_byte(&gen->code, 0x5B);        /* pop rbx */
}

/* ========== emit_print_char: Print character in rax (low byte) to stdout ========== */
static void emit_print_char(CodeGenerator *gen)
{
    /* Save registers */
    buffer_write_byte(&gen->code, 0x52);        /* push rdx */
    buffer_write_byte(&gen->code, 0x56);        /* push rsi */
    buffer_write_byte(&gen->code, 0x57);        /* push rdi */
    
    /* Push the character onto stack (we'll use stack as buffer) */
    buffer_write_byte(&gen->code, 0x50);        /* push rax */
    
    /* rsi = rsp (buffer pointing to our char) */
    emit_rex_w(gen);
    buffer_write_byte(&gen->code, 0x89);        /* mov rsi, rsp */
    buffer_write_byte(&gen->code, 0xE6);
    
    /* mov rax, 1 (sys_write) */
    emit_rex_w(gen);
    buffer_write_byte(&gen->code, 0xC7);
    buffer_write_byte(&gen->code, 0xC0);
    buffer_write_u32(&gen->code, 1);
    
    /* mov rdi, 1 (stdout) */
    emit_rex_w(gen);
    buffer_write_byte(&gen->code, 0xC7);
    buffer_write_byte(&gen->code, 0xC7);
    buffer_write_u32(&gen->code, 1);
    
    /* mov rdx, 1 (length = 1 char) */
    emit_rex_w(gen);
    buffer_write_byte(&gen->code, 0xC7);
    buffer_write_byte(&gen->code, 0xC2);
    buffer_write_u32(&gen->code, 1);
    
    /* syscall */
    emit_syscall(gen);
    
    /* Pop the char we pushed */
    buffer_write_byte(&gen->code, 0x58);        /* pop rax */
    
    /* Restore registers */
    buffer_write_byte(&gen->code, 0x5F);        /* pop rdi */
    buffer_write_byte(&gen->code, 0x5E);        /* pop rsi */
    buffer_write_byte(&gen->code, 0x5A);        /* pop rdx */
}

/* ========== emit_print_string_ptr: Print string at address in rax ========== */
/* Note: This requires knowing the length, so we need strlen inline or pre-calculated */
/* For now, we'll use a simple approach: the string offset is in rax, length passed separately */
static void emit_print_string_offset(CodeGenerator *gen, size_t len)
{
    /* rax contains the string offset in data section (will be patched to real address) */
    /* Save registers */
    buffer_write_byte(&gen->code, 0x52);        /* push rdx */
    buffer_write_byte(&gen->code, 0x56);        /* push rsi */
    buffer_write_byte(&gen->code, 0x57);        /* push rdi */
    
    /* mov rsi, rax (string address) */
    emit_rex_w(gen);
    buffer_write_byte(&gen->code, 0x89);
    buffer_write_byte(&gen->code, 0xC6);
    
    /* mov rax, 1 (sys_write) */
    emit_rex_w(gen);
    buffer_write_byte(&gen->code, 0xC7);
    buffer_write_byte(&gen->code, 0xC0);
    buffer_write_u32(&gen->code, 1);
    
    /* mov rdi, 1 (stdout) */
    emit_rex_w(gen);
    buffer_write_byte(&gen->code, 0xC7);
    buffer_write_byte(&gen->code, 0xC7);
    buffer_write_u32(&gen->code, 1);
    
    /* mov rdx, len */
    emit_mov_rdx_imm64(gen, len);
    
    /* syscall */
    emit_syscall(gen);
    
    /* Restore registers */
    buffer_write_byte(&gen->code, 0x5F);        /* pop rdi */
    buffer_write_byte(&gen->code, 0x5E);        /* pop rsi */
    buffer_write_byte(&gen->code, 0x5A);        /* pop rdx */
}

/* ========== emit_print_string_with_rdx_len: Print string at address in rax, length in rdx ========== */
__attribute__((unused))
static void emit_print_string_with_rdx_len(CodeGenerator *gen)
{
    /* rax contains the string address, rdx contains the length */
    /* Save registers */
    buffer_write_byte(&gen->code, 0x52);        /* push rdx */
    buffer_write_byte(&gen->code, 0x56);        /* push rsi */
    buffer_write_byte(&gen->code, 0x57);        /* push rdi */
    
    /* Save rdx (length) temporarily */
    buffer_write_byte(&gen->code, 0x52);        /* push rdx */
    
    /* mov rsi, rax (string address) */
    emit_rex_w(gen);
    buffer_write_byte(&gen->code, 0x89);
    buffer_write_byte(&gen->code, 0xC6);
    
    /* Restore length to rdx */
    buffer_write_byte(&gen->code, 0x5A);        /* pop rdx */
    
    /* mov rax, 1 (sys_write) */
    emit_rex_w(gen);
    buffer_write_byte(&gen->code, 0xC7);
    buffer_write_byte(&gen->code, 0xC0);
    buffer_write_u32(&gen->code, 1);
    
    /* mov rdi, 1 (stdout) */
    emit_rex_w(gen);
    buffer_write_byte(&gen->code, 0xC7);
    buffer_write_byte(&gen->code, 0xC7);
    buffer_write_u32(&gen->code, 1);
    
    /* rdx already has the length */
    
    /* syscall */
    emit_syscall(gen);
    
    /* Restore registers */
    buffer_write_byte(&gen->code, 0x5F);        /* pop rdi */
    buffer_write_byte(&gen->code, 0x5E);        /* pop rsi */
    buffer_write_byte(&gen->code, 0x5A);        /* pop rdx */
}

/* ========== emit_print_string_compute_len: Calculate string length and print ========== */
/* String address is in rax, this computes strlen and calls write */
static void emit_print_string_compute_len(CodeGenerator *gen)
{
    /* Save rax (string address) for later */
    buffer_write_byte(&gen->code, 0x50);        /* push rax */
    
    /* Move string address to rdi for scanning */
    emit_rex_w(gen);
    buffer_write_byte(&gen->code, 0x89);        /* mov rdi, rax */
    buffer_write_byte(&gen->code, 0xC7);
    
    /* Set rcx to -1 (max count) */
    emit_rex_w(gen);
    buffer_write_byte(&gen->code, 0x48);        /* mov rcx, -1 */
    buffer_write_byte(&gen->code, 0xC7);
    buffer_write_byte(&gen->code, 0xC1);
    buffer_write_u32(&gen->code, 0xFFFFFFFF);
    
    /* xor eax, eax - we're looking for null byte */
    buffer_write_byte(&gen->code, 0x31);
    buffer_write_byte(&gen->code, 0xC0);
    
    /* repnz scasb - scan for null terminator */
    buffer_write_byte(&gen->code, 0xF2);        /* repnz prefix */
    buffer_write_byte(&gen->code, 0xAE);        /* scasb */
    
    /* rcx is now (-length - 2), so length = not(rcx) - 1 = -rcx - 2 */
    /* not rcx */
    emit_rex_w(gen);
    buffer_write_byte(&gen->code, 0xF7);
    buffer_write_byte(&gen->code, 0xD1);        /* not rcx */
    
    /* dec rcx (sub 1) */
    emit_rex_w(gen);
    buffer_write_byte(&gen->code, 0xFF);
    buffer_write_byte(&gen->code, 0xC9);        /* dec rcx */
    
    /* Move length to rdx */
    emit_rex_w(gen);
    buffer_write_byte(&gen->code, 0x89);        /* mov rdx, rcx */
    buffer_write_byte(&gen->code, 0xCA);
    
    /* Restore string address to rsi */
    buffer_write_byte(&gen->code, 0x5E);        /* pop rsi */
    
    /* sys_write(1, rsi, rdx) */
    emit_rex_w(gen);
    buffer_write_byte(&gen->code, 0xC7);        /* mov rax, 1 */
    buffer_write_byte(&gen->code, 0xC0);
    buffer_write_u32(&gen->code, 1);
    
    emit_rex_w(gen);
    buffer_write_byte(&gen->code, 0xC7);        /* mov rdi, 1 */
    buffer_write_byte(&gen->code, 0xC7);
    buffer_write_u32(&gen->code, 1);
    
    emit_syscall(gen);
}

/* ========== Emit sys_write (for print) ========== */

__attribute__((unused))
static void emit_sys_write(CodeGenerator *gen, uint64_t str_addr, size_t len)
{
    /* sys_write: rax=1, rdi=fd(1=stdout), rsi=buf, rdx=len */
    emit_mov_eax_imm32(gen, 1);       /* syscall number: write */
    emit_mov_edi_imm32(gen, 1);       /* fd: stdout */
    emit_mov_rsi_imm64(gen, str_addr);/* buffer address */
    emit_mov_rdx_imm64(gen, len);     /* length */
    emit_syscall(gen);
}

/* ========== Emit sys_exit ========== */

static void emit_sys_exit(CodeGenerator *gen)
{
    /* sys_exit: rax=60, rdi=exit_code (in rax before this) */
    /* First move the return value to rdi */
    emit_rex_w(gen);
    buffer_write_byte(&gen->code, 0x89);  /* mov rdi, rax */
    buffer_write_byte(&gen->code, 0xC7);
    emit_mov_rax_imm64(gen, 60);  /* syscall number: exit */
    emit_syscall(gen);
}

/* ========== Forward Declarations ========== */

static int codegen_expression(CodeGenerator *gen, ASTNode *node);
static int codegen_statement(CodeGenerator *gen, ASTNode *node);

/* ========== Expression Code Generation ========== */

static int codegen_expression(CodeGenerator *gen, ASTNode *node)
{
    if (!node) return -1;

    switch (node->type) {
        case AST_NUMBER: {
            int64_t val = (int64_t)node->data.number.value;
            emit_mov_rax_imm64(gen, (uint64_t)val);
            return 0;
        }

        case AST_STRING: {
            /* Add string to data section and load its address */
            size_t offset = string_table_add(&gen->strings, node->data.string.value);
            /* Use tracked relocation so patching works correctly */
            emit_mov_rax_string_offset(gen, offset);
            return 0;
        }

        case AST_IDENTIFIER: {
            const char *name = node->data.identifier.name;
            StackVar *var = stack_frame_find(&gen->stack, name);
            if (var) {
                if (var->is_array) {
                    /* For arrays, we want to pass the address/pointer */
                    if (var->is_pointer_array) {
                        /* Already a pointer, just load it */
                        emit_mov_rax_rbp_offset(gen, var->stack_offset);
                    } else {
                        /* Stack-allocated array, get its address */
                        emit_lea_rax_rbp_offset(gen, var->stack_offset);
                    }
                } else {
                    emit_mov_rax_rbp_offset(gen, var->stack_offset);
                }
                return 0;
            }
            
            /* Check if it's a constant */
            if (gen->constants) {
                for (size_t i = 0; i < gen->constants->count; ++i) {
                    ASTNode *const_node = gen->constants->items[i];
                    if (const_node->type == AST_CONST_DECL &&
                        strcmp(const_node->data.const_decl.name, name) == 0) {
                        /* Compile the constant value directly */
                        return codegen_expression(gen, const_node->data.const_decl.value);
                    }
                }
            }
            
            /* Check if it's an enum value (EnumName.Member or just Member) */
            if (gen->enums) {
                /* First check for dotted syntax: EnumName.Member */
                if (strchr(name, '.')) {
                    char *enum_name = strdup(name);
                    char *dot = strchr(enum_name, '.');
                    *dot = '\0';
                    char *member_name = dot + 1;
                    
                    for (size_t i = 0; i < gen->enums->count; ++i) {
                        ASTNode *enum_node = gen->enums->items[i];
                        if (enum_node->type == AST_ENUM_DEF &&
                            strcmp(enum_node->data.enum_def.name, enum_name) == 0) {
                            /* Find the member index */
                            for (size_t j = 0; j < enum_node->data.enum_def.member_count; ++j) {
                                if (strcmp(enum_node->data.enum_def.members[j], member_name) == 0) {
                                    free(enum_name);
                                    emit_mov_eax_imm32(gen, (int32_t)j);
                                    return 0;
                                }
                            }
                        }
                    }
                    free(enum_name);
                }
                
                /* Then check for direct member access (just Member) */
                for (size_t i = 0; i < gen->enums->count; ++i) {
                    ASTNode *enum_node = gen->enums->items[i];
                    if (enum_node->type == AST_ENUM_DEF) {
                        for (size_t j = 0; j < enum_node->data.enum_def.member_count; ++j) {
                            if (strcmp(enum_node->data.enum_def.members[j], name) == 0) {
                                int32_t value = (int32_t)j;
                                if (strcmp(enum_node->data.enum_def.name, "DataType") == 0) {
                                    for (size_t adj = 0; adj < j; ++adj) {
                                        if (strcmp(enum_node->data.enum_def.members[adj], "Array") == 0) {
                                            value -= 1;
                                            break;  /* Only skip the first placeholder */
                                        }
                                    }
                                }
                                emit_mov_eax_imm32(gen, value);
                                return 0;
                            }
                        }
                    }
                }
            }
            
            gen->error_msg = strdup("Undefined variable");
            gen->error_line = node->line;
            return -1;
        }

        case AST_STRUCT_ACCESS: {
            /* struct.field or struct.field.subfield or arr[i].field - read a field from struct */
            StackVar *struct_var = stack_frame_find(&gen->stack, node->data.struct_access.struct_name);
            
            if (!struct_var) {
                /* Not a struct variable - might be enum access (EnumName.Member) */
                /* Try to find as combined identifier */
                char combined[512];
                snprintf(combined, sizeof(combined), "%s.%s", 
                         node->data.struct_access.struct_name,
                         node->data.struct_access.field_name);
                StackVar *enum_var = stack_frame_find(&gen->stack, combined);
                if (enum_var) {
                    emit_mov_rax_rbp_offset(gen, enum_var->stack_offset);
                    return 0;
                }
                gen->error_msg = strdup("Undefined struct variable");
                gen->error_line = node->line;
                return -1;
            }
            
            /* Check if it's a struct array access (arr[i].field) */
            int is_struct_array = (struct_var->is_array && struct_var->struct_name);
            int is_struct_ptr = (struct_var->type == TYPE_STRUCT_PTR);
            
            /* Find struct definition using the struct variable's type name */
            StructDefInfo *current_struct = struct_def_table_find(&gen->struct_defs, struct_var->struct_name);
            if (!current_struct) {
                /* Not a struct type - might be enum access pattern */
                char combined[512];
                snprintf(combined, sizeof(combined), "%s.%s", 
                         node->data.struct_access.struct_name,
                         node->data.struct_access.field_name);
                StackVar *enum_var = stack_frame_find(&gen->stack, combined);
                if (enum_var) {
                    emit_mov_rax_rbp_offset(gen, enum_var->stack_offset);
                    return 0;
                }
                gen->error_msg = strdup("Struct definition not found");
                gen->error_line = node->line;
                return -1;
            }
            
            /* Calculate struct element size */
            size_t struct_size = calc_struct_size(&gen->struct_defs, current_struct);
            
            /* Handle nested field paths like "stats.vie" */
            char *field_path = strdup(node->data.struct_access.field_name);
            char *saveptr;
            char *field_token = strtok_r(field_path, ".", &saveptr);
            int field_offset = 0;
            
            while (field_token && current_struct) {
                /* Find this field in the current struct */
                int this_offset = 0;
                int found = 0;
                StructDefInfo *nested_struct = NULL;
                
                for (size_t i = 0; i < current_struct->fields.count; ++i) {
                    if (strcmp(current_struct->fields.items[i].name, field_token) == 0) {
                        found = 1;
                        /* Check if this field is itself a struct (for further nesting) */
                        /* Try to find a struct definition with a capitalized version of field name */
                        char nested_name[64];
                        strncpy(nested_name, field_token, sizeof(nested_name) - 1);
                        nested_name[0] = toupper(nested_name[0]);
                        nested_name[sizeof(nested_name) - 1] = '\0';
                        nested_struct = struct_def_table_find(&gen->struct_defs, nested_name);
                        if (!nested_struct) {
                            /* Try exact name */
                            nested_struct = struct_def_table_find(&gen->struct_defs, field_token);
                        }
                        break;
                    }
                    /* Calculate offset using proper field size (handles nested structs) */
                    this_offset += (int)calc_field_size(&gen->struct_defs, 
                                                         current_struct->fields.items[i].name,
                                                         current_struct->fields.items[i].type);
                }
                
                if (!found) {
                    free(field_path);
                    gen->error_msg = strdup("Field not found in struct");
                    gen->error_line = node->line;
                    return -1;
                }
                
                field_offset += this_offset;
                
                /* Move to the nested struct for the next field */
                current_struct = nested_struct;
                field_token = strtok_r(NULL, ".", &saveptr);
            }
            free(field_path);
            
            if (node->data.struct_access.indices.count > 0) {
                /* Struct array access: arr[i]...[j].field */
                
                /* Get base address */
                if (struct_var->is_pointer_array) {
                    emit_mov_rax_rbp_offset(gen, struct_var->stack_offset);
                } else {
                    emit_lea_rax_rbp_offset(gen, struct_var->stack_offset);
                }
                
                /* Handle all indices except the last one (pointer chasing) */
                for (size_t i = 0; i < node->data.struct_access.indices.count - 1; ++i) {
                    emit_push_rax(gen); /* Save base */
                    if (codegen_expression(gen, node->data.struct_access.indices.items[i]) != 0) return -1;
                    emit_mov_rbx_rax(gen); /* rbx = index */
                    emit_pop_rax(gen); /* Restore base */
                    
                    emit_imul_rbx_8(gen);
                    emit_add_rax_rbx(gen);
                    emit_mov_rax_ptr_rax(gen); /* Load pointer to next array */
                }
                
                /* Handle last index (struct access) */
                emit_push_rax(gen); /* Save base */
                if (codegen_expression(gen, node->data.struct_access.indices.items[node->data.struct_access.indices.count - 1]) != 0) return -1;
                emit_mov_rbx_rax(gen); /* rbx = index */
                emit_pop_rax(gen); /* Restore base */
                
                /* Calculate offset: index * struct_size */
                emit_push_rax(gen); /* Save base */
                emit_mov_rax_imm64(gen, struct_size);
                emit_imul_rax_rbx(gen); /* rax = index * struct_size */
                emit_mov_rbx_rax(gen); /* rbx = offset */
                emit_pop_rax(gen); /* Restore base */
                
                emit_add_rax_rbx(gen); /* rax = address of struct element */
                
                /* Now add field offset and load the value */
                emit_rex_w(gen);
                buffer_write_byte(&gen->code, 0x8B);  /* mov r64, [r64+disp32] */
                buffer_write_byte(&gen->code, 0x80);  /* ModRM: [rax + disp32] -> rax */
                buffer_write_u32(&gen->code, (uint32_t)field_offset);
            } else if (is_struct_ptr) {
                /* Load the pointer (address of struct) */
                emit_mov_rax_rbp_offset(gen, struct_var->stack_offset);
                /* Load field from [rax + field_offset] */
                emit_rex_w(gen);
                buffer_write_byte(&gen->code, 0x8B);  /* mov r64, [r64+disp32] */
                buffer_write_byte(&gen->code, 0x80);  /* ModRM: [rax + disp32] -> rax */
                buffer_write_u32(&gen->code, (uint32_t)field_offset);
            } else {
                /* Direct struct: Load field value from stack */
                emit_mov_rax_rbp_offset(gen, struct_var->stack_offset + field_offset);
            }
            return 0;
        }

        case AST_BINARY_OP: {
            /* Compile right operand first, push result */
            if (codegen_expression(gen, node->data.binary_op.right) != 0) return -1;
            emit_push_rax(gen);

            /* Compile left operand */
            if (codegen_expression(gen, node->data.binary_op.left) != 0) return -1;

            /* Pop right operand into rbx */
            emit_pop_rbx(gen);

            /* Now: rax = left, rbx = right */
            const char *op = node->data.binary_op.op;

            if (strcmp(op, "+") == 0) {
                emit_add_rax_rbx(gen);
            } else if (strcmp(op, "-") == 0) {
                emit_sub_rax_rbx(gen);
            } else if (strcmp(op, "*") == 0) {
                emit_imul_rax_rbx(gen);
            } else if (strcmp(op, "/") == 0) {
                /* For idiv: dividend in rdx:rax, divisor in rbx */
                /* rax = left (dividend), rbx = right (divisor) */
                emit_xor_rdx_rdx(gen);  /* Clear rdx for division (sign extend if needed) */
                emit_idiv_rbx(gen);     /* rax = rdx:rax / rbx, rdx = remainder */
            } else if (strcmp(op, "%") == 0) {
                emit_xor_rdx_rdx(gen);
                emit_idiv_rbx(gen);
                /* Result is in rdx for modulo */
                emit_rex_w(gen);
                buffer_write_byte(&gen->code, 0x89);  /* mov rax, rdx */
                buffer_write_byte(&gen->code, 0xD0);
            } else if (strcmp(op, "==") == 0) {
                emit_cmp_rax_rbx(gen);
                emit_sete_al(gen);
                emit_movzx_rax_al(gen);
            } else if (strcmp(op, "!=") == 0) {
                emit_cmp_rax_rbx(gen);
                emit_setne_al(gen);
                emit_movzx_rax_al(gen);
            } else if (strcmp(op, "<") == 0) {
                emit_cmp_rax_rbx(gen);
                emit_setl_al(gen);
                emit_movzx_rax_al(gen);
            } else if (strcmp(op, "<=") == 0) {
                emit_cmp_rax_rbx(gen);
                emit_setle_al(gen);
                emit_movzx_rax_al(gen);
            } else if (strcmp(op, ">") == 0) {
                emit_cmp_rax_rbx(gen);
                emit_setg_al(gen);
                emit_movzx_rax_al(gen);
            } else if (strcmp(op, ">=") == 0) {
                emit_cmp_rax_rbx(gen);
                emit_setge_al(gen);
                emit_movzx_rax_al(gen);
            }
            return 0;
        }

        case AST_FUNC_CALL: {
            /* Find function */
            FunctionInfo *func = func_table_find(&gen->functions, node->data.func_call.name);
            if (!func) {
                gen->error_msg = strdup("Undefined function");
                gen->error_line = node->line;
                return -1;
            }

            /* Push arguments in reverse order */
            for (int i = (int)node->data.func_call.args.count - 1; i >= 0; --i) {
                if (codegen_expression(gen, node->data.func_call.args.items[i]) != 0)
                    return -1;
                emit_push_rax(gen);
            }

            /* Call function */
            size_t call_site = gen->code.size + 1;  /* Offset of the rel32 in call instruction */
            emit_call_rel32(gen, 0);  /* Placeholder, will be patched */
            
            /* Calculate relative offset */
            int32_t rel = (int32_t)(func->code_offset - (call_site + 4));
            memcpy(gen->code.data + call_site, &rel, 4);

            /* Clean up arguments from stack */
            if (node->data.func_call.args.count > 0) {
                emit_add_rsp_imm32(gen, (int32_t)(node->data.func_call.args.count * 8));
            }
            return 0;
        }

        case AST_ARRAY_ACCESS: {
            /* Get array variable */
            StackVar *arr = stack_frame_find(&gen->stack, node->data.array_access.array_name);
            if (!arr || !arr->is_array) {
                gen->error_msg = strdup("Undefined array");
                gen->error_line = node->line;
                return -1;
            }
            
            /* Load base address into RAX */
            if (arr->is_pointer_array) {
                /* For pointer arrays (function parameters), load the pointer first */
                emit_mov_rax_rbp_offset(gen, arr->stack_offset);  /* rax = pointer to array */
            } else {
                /* For stack-allocated arrays, get address of array base */
                emit_lea_rax_rbp_offset(gen, arr->stack_offset);
            }
            
            /* Loop through indices */
            for (size_t i = 0; i < node->data.array_access.indices.count; ++i) {
                /* Save current base address (RAX) */
                emit_push_rax(gen);
                
                /* Evaluate index expression into rax */
                if (codegen_expression(gen, node->data.array_access.indices.items[i]) != 0) return -1;
                
                /* Move index to RBX */
                emit_mov_rbx_rax(gen);  /* rbx = index */
                
                /* Restore base address to RAX */
                emit_pop_rax(gen);
                
                /* Calculate offset: index * 8 */
                emit_imul_rbx_8(gen);   /* rbx = index * 8 */
                
                /* Add index offset to get actual element address */
                emit_add_rax_rbx(gen);
                
                /* Load value at that address */
                emit_mov_rax_ptr_rax(gen);
            }
            
            return 0;
        }

        case AST_ADDRESS_OF: {
            /* &var - get address of a variable */
            const char *var_name = node->data.address_of.var_name;
            StackVar *var = stack_frame_find(&gen->stack, var_name);
            if (!var) {
                gen->error_msg = strdup("Undefined variable in address-of");
                gen->error_line = node->line;
                return -1;
            }
            /* Load the address of the variable into rax */
            emit_lea_rax_rbp_offset(gen, var->stack_offset);
            return 0;
        }

        case AST_DEREF: {
            /* *ptr - dereference pointer, get value at address */
            if (codegen_expression(gen, node->data.deref.operand) != 0) return -1;
            /* rax now contains the pointer (address), load value at that address */
            emit_mov_rax_ptr_rax(gen);
            return 0;
        }

        default:
            gen->error_msg = strdup("Unsupported expression type");
            gen->error_line = node->line;
            return -1;
    }
}

/* ========== Statement Code Generation ========== */

static int codegen_statement(CodeGenerator *gen, ASTNode *node)
{
    if (!node) return 0;
    // fprintf(stderr, "Compiling statement type: %d\n", node->type);

    switch (node->type) {
        case AST_VAR_DECL: {
            /* Check if it's a struct type */
            if (node->data.var_decl.struct_type_name) {
                /* First check if it's an enum type (treat as int) */
                int is_enum = 0;
                if (gen->enums) {
                    for (size_t i = 0; i < gen->enums->count; ++i) {
                        ASTNode *enum_node = gen->enums->items[i];
                        if (enum_node->type == AST_ENUM_DEF &&
                            strcmp(enum_node->data.enum_def.name, node->data.var_decl.struct_type_name) == 0) {
                            is_enum = 1;
                            break;
                        }
                    }
                }
                
                if (is_enum) {
                    /* Treat enum as int */
                    stack_frame_push_var(&gen->stack, node->data.var_decl.name, TYPE_INT);
                    StackVar *var = stack_frame_find(&gen->stack, node->data.var_decl.name);
                    
                    /* Initialize if there's an initial value */
                    if (node->data.var_decl.init_value) {
                        if (codegen_expression(gen, node->data.var_decl.init_value) != 0)
                            return -1;
                    } else {
                        emit_mov_eax_imm32(gen, 0);  /* Default to 0 */
                    }
                    
                    emit_mov_rbp_offset_rax(gen, var->stack_offset);
                    return 0;
                }
                
                /* Check if it's a struct array type (e.g., "Node[]") */
                char *struct_type_name = strdup(node->data.var_decl.struct_type_name);
                size_t array_capacity = 0;
                int is_struct_array = 0;
                
                /* Check for [] suffix to determine if it's a struct array */
                size_t len = strlen(struct_type_name);
                if (len >= 2 && struct_type_name[len-2] == '[' && struct_type_name[len-1] == ']') {
                    is_struct_array = 1;
                    struct_type_name[len-2] = '\0';  /* Remove [] to get base struct name */
                    
                    /* Get array size from init_value (parser stores it there) */
                    if (node->data.var_decl.init_value && 
                        node->data.var_decl.init_value->type == AST_NUMBER) {
                        array_capacity = (size_t)node->data.var_decl.init_value->data.number.value;
                    } else {
                        array_capacity = 64;  /* Default capacity */
                    }
                }
                
                /* Find struct definition */
                StructDefInfo *struct_def = struct_def_table_find(&gen->struct_defs, struct_type_name);
                if (!struct_def) {
                    free(struct_type_name);
                    gen->error_msg = strdup("Undefined struct type");
                    gen->error_line = node->line;
                    return -1;
                }
                
                /* Calculate struct size including nested structs */
                size_t struct_size = calc_struct_size(&gen->struct_defs, struct_def);
                
                if (is_struct_array) {
                    /* Struct array: allocate space for multiple structs */
                    size_t total_size = struct_size * array_capacity;
                    
                    /* Check if variable already exists */
                    StackVar *existing_var = stack_frame_find(&gen->stack, node->data.var_decl.name);
                    if (!existing_var) {
                        StackVar var;
                        var.name = strdup(node->data.var_decl.name);
                        var.type = TYPE_UNKNOWN;
                        var.struct_name = strdup(struct_type_name);
                        var.string_data_offset = 0;
                        var.string_length = 0;
                        var.is_array = 1;
                        var.is_pointer_array = 0;
                        var.array_capacity = array_capacity;
                        var.stack_offset = gen->stack.current_offset - (int)total_size;
                        gen->stack.current_offset = var.stack_offset;
                        
                        /* Allocate space for size tracker */
                        gen->stack.current_offset -= 8;
                        var.array_size_offset = gen->stack.current_offset;
                        
                        /* Allocate space for last value tracker (not really used for structs) */
                        gen->stack.current_offset -= 8;
                        var.array_last_val_offset = gen->stack.current_offset;
                        
                        /* Add to stack frame */
                        if (gen->stack.count >= gen->stack.capacity) {
                            gen->stack.capacity = gen->stack.capacity == 0 ? 16 : gen->stack.capacity * 2;
                            StackVar *new_items = realloc(gen->stack.items, gen->stack.capacity * sizeof(StackVar));
                            if (!new_items) {
                                free(struct_type_name);
                                return -1;
                            }
                            gen->stack.items = new_items;
                        }
                        gen->stack.items[gen->stack.count++] = var;
                        existing_var = &gen->stack.items[gen->stack.count - 1];
                    }
                    
                    /* Store struct size per element for later use */
                    existing_var->string_data_offset = struct_size;  /* Reuse this field to store element size */
                    
                    /* Initialize all bytes to 0 */
                    for (size_t i = 0; i < array_capacity; i++) {
                        for (size_t f = 0; f < struct_size / 8; f++) {
                            emit_mov_eax_imm32(gen, 0);
                            emit_mov_rbp_offset_rax(gen, existing_var->stack_offset + (int)(i * struct_size) + (int)(f * 8));
                        }
                    }
                    
                    /* Initialize size to 0 */
                    emit_mov_eax_imm32(gen, 0);
                    emit_mov_rbp_offset_rax(gen, existing_var->array_size_offset);
                    
                    free(struct_type_name);
                    return 0;
                }
                
                /* Regular (non-array) struct */
                /* Check if variable already exists - reuse its slot */
                StackVar *existing_var = stack_frame_find(&gen->stack, node->data.var_decl.name);
                if (!existing_var) {
                    /* Variable doesn't exist, create new one */
                    StackVar var;
                    var.name = strdup(node->data.var_decl.name);
                    var.type = TYPE_UNKNOWN;
                    var.struct_name = strdup(struct_type_name);
                    var.string_data_offset = 0;
                    var.string_length = 0;
                    var.is_array = 0;
                    var.is_pointer_array = 0;
                    var.array_capacity = 0;
                    var.array_size_offset = 0;
                    var.array_last_val_offset = 0;
                    var.stack_offset = gen->stack.current_offset - (int)struct_size;
                    gen->stack.current_offset = var.stack_offset;
                    
                    /* Add to stack frame */
                    if (gen->stack.count >= gen->stack.capacity) {
                        gen->stack.capacity = gen->stack.capacity == 0 ? 16 : gen->stack.capacity * 2;
                        StackVar *new_items = realloc(gen->stack.items, gen->stack.capacity * sizeof(StackVar));
                        if (!new_items) {
                            free(struct_type_name);
                            return -1;
                        }
                        gen->stack.items = new_items;
                    }
                    gen->stack.items[gen->stack.count++] = var;
                    existing_var = &gen->stack.items[gen->stack.count - 1];
                }
                
                free(struct_type_name);
                
                /* Initialize all bytes of struct to 0 */
                /* Since we use negative offsets from rbp, we need to clear from base */
                size_t bytes_to_init = struct_size;
                int init_offset = 0;
                while (bytes_to_init >= 8) {
                    emit_mov_eax_imm32(gen, 0);
                    emit_mov_rbp_offset_rax(gen, existing_var->stack_offset + init_offset);
                    init_offset -= 8;
                    bytes_to_init -= 8;
                }
                
                return 0;
            }
            
            /* Check if it's an array type */
            DataType dtype = node->data.var_decl.var_type;
            if (dtype == TYPE_INT_ARRAY || dtype == TYPE_FLOAT_ARRAY || 
                dtype == TYPE_STRING_ARRAY) {
                /* Allocate array with default capacity of 64 elements */
                DataType elem_type = (dtype == TYPE_INT_ARRAY) ? TYPE_INT :
                                    (dtype == TYPE_FLOAT_ARRAY) ? TYPE_FLOAT : TYPE_STRING;
                stack_frame_push_array(&gen->stack, node->data.var_decl.name, 
                                      elem_type, 64);
                
                /* Initialize array to zeros */
                StackVar *arr = stack_frame_find(&gen->stack, node->data.var_decl.name);
                for (size_t i = 0; i < arr->array_capacity; i++) {
                    emit_mov_eax_imm32(gen, 0);
                    emit_mov_rbp_offset_rax(gen, arr->stack_offset + (int)(i * 8));
                }
                
                /* Initialize size to 0 */
                emit_mov_eax_imm32(gen, 0);
                emit_mov_rbp_offset_rax(gen, arr->array_size_offset);
                
                /* Initialize last_val to 0 */
                emit_mov_eax_imm32(gen, 0);
                emit_mov_rbp_offset_rax(gen, arr->array_last_val_offset);
                
                return 0;
            }
            
            /* Regular variable - allocate stack space */
            stack_frame_push_var(&gen->stack, node->data.var_decl.name, 
                                node->data.var_decl.var_type);
            
            StackVar *var = stack_frame_find(&gen->stack, node->data.var_decl.name);
            
            /* Initialize if there's an initial value */
            if (node->data.var_decl.init_value) {
                /* If it's a string type and init is a string literal, track the offset */
                if (node->data.var_decl.var_type == TYPE_STRING && 
                    node->data.var_decl.init_value->type == AST_STRING) {
                    const char *str = node->data.var_decl.init_value->data.string.value;
                    size_t offset = string_table_add(&gen->strings, str);
                    var->string_data_offset = offset;
                    var->string_length = strlen(str);
                }
                if (codegen_expression(gen, node->data.var_decl.init_value) != 0)
                    return -1;
            } else {
                emit_mov_eax_imm32(gen, 0);  /* Default to 0 */
            }
            
            emit_mov_rbp_offset_rax(gen, var->stack_offset);
            return 0;
        }

        case AST_ASSIGNMENT: {
            StackVar *var = stack_frame_find(&gen->stack, node->data.assignment.var_name);
            if (!var) {
                gen->error_msg = strdup("Undefined variable");
                gen->error_line = node->line;
                return -1;
            }
            
            if (codegen_expression(gen, node->data.assignment.value) != 0)
                return -1;
            emit_mov_rbp_offset_rax(gen, var->stack_offset);
            return 0;
        }

        case AST_DEREF_ASSIGN: {
            /* *ptr = value - store value at the address in ptr */
            
            /* Evaluate the pointer expression first to get the address */
            if (codegen_expression(gen, node->data.deref_assign.ptr) != 0)
                return -1;
            emit_push_rax(gen);  /* Save address on stack */
            
            /* Now evaluate the value */
            if (codegen_expression(gen, node->data.deref_assign.value) != 0)
                return -1;
            /* rax now holds the value to store */
            
            emit_pop_rbx(gen);  /* rbx = address */
            
            /* Store value at address: mov [rbx], rax */
            emit_mov_ptr_rbx_rax(gen);
            return 0;
        }

        case AST_ARRAY_ASSIGN: {
            /* arr[index] = value */
            StackVar *arr = stack_frame_find(&gen->stack, node->data.array_assign.array_name);
            if (!arr || !arr->is_array) {
                gen->error_msg = strdup("Undefined array in assignment");
                gen->error_line = node->line;
                return -1;
            }
            
            /* Check for type initialization: nu[0] -> int[] */
            if (node->data.array_assign.value->type == AST_STRING && 
                strncmp(node->data.array_assign.value->data.string.value, "TYPE:", 5) == 0) {
                
                /* For single-dimension case (nu[i] -> int[]), we need to:
                 * 1. Allocate from old_size to target_index (inclusive)
                 * 2. Each slot gets its own sub-array
                 */
                
                if (node->data.array_assign.indices.count == 1 && !arr->is_pointer_array) {
                    /* Single dimension - need to handle auto-fill for outer array */
                    int metadata_size = 16;
                    int data_size = 2048;
                    
                    /* Evaluate target index and save to r12 (callee-saved) */
                    if (codegen_expression(gen, node->data.array_assign.indices.items[0]) != 0) return -1;
                    emit_push_r12(gen);  /* Save old r12 */
                    emit_push_r13(gen);  /* Save old r13 */
                    emit_mov_r12_rax(gen);  /* r12 = target_index */
                    
                    /* Load current size into r13 = loop counter */
                    emit_mov_rax_rbp_offset(gen, arr->array_size_offset);
                    emit_mov_r13_rax(gen);  /* r13 = i = old_size */
                    
                    /* Loop: while (r13 <= r12) allocate sub-array for r13, r13++ */
                    int loop_label = codegen_create_label(gen);
                    int end_label = codegen_create_label(gen);
                    
                    codegen_set_label(gen, loop_label);
                    
                    /* Check r13 <= r12 */
                    emit_cmp_r13_r12(gen);
                    size_t jg_pos = gen->code.size + 2;
                    buffer_write_byte(&gen->code, 0x0F);  /* jg end */
                    buffer_write_byte(&gen->code, 0x8F);
                    buffer_write_u32(&gen->code, 0);
                    codegen_patch_label(gen, end_label, jg_pos);
                    
                    /* Allocate sub-array */
                    emit_sub_rsp_imm32(gen, metadata_size + data_size);
                    
                    /* Initialize metadata to 0 */
                    emit_mov_rax_imm64(gen, 0);
                    emit_rex_w(gen);
                    buffer_write_byte(&gen->code, 0x89);  /* mov [rsp], rax */
                    buffer_write_byte(&gen->code, 0x04);
                    buffer_write_byte(&gen->code, 0x24);
                    emit_rex_w(gen);
                    buffer_write_byte(&gen->code, 0x89);  /* mov [rsp+8], rax */
                    buffer_write_byte(&gen->code, 0x44);
                    buffer_write_byte(&gen->code, 0x24);
                    buffer_write_byte(&gen->code, 0x08);
                    
                    /* Get data address (rsp + 16) into rbx */
                    emit_rex_w(gen);
                    buffer_write_byte(&gen->code, 0x8D);  /* lea rbx, [rsp+16] */
                    buffer_write_byte(&gen->code, 0x5C);
                    buffer_write_byte(&gen->code, 0x24);
                    buffer_write_byte(&gen->code, 0x10);
                    
                    /* Calculate &arr[r13] */
                    emit_lea_rax_rbp_offset(gen, arr->stack_offset);
                    emit_mov_rcx_r13(gen);  /* rcx = i */
                    emit_imul_rcx_8(gen);
                    emit_add_rax_rcx(gen);  /* rax = &arr[i] */
                    
                    /* Store sub-array address */
                    emit_mov_ptr_rax_rbx(gen);
                    
                    /* i++ */
                    emit_inc_r13(gen);
                    
                    /* Jump back to loop */
                    size_t jmp_pos = gen->code.size + 1;
                    emit_jmp_rel32(gen, 0);
                    int32_t rel = (int32_t)(gen->labels[loop_label].offset - (jmp_pos + 4));
                    memcpy(gen->code.data + jmp_pos, &rel, 4);
                    
                    codegen_set_label(gen, end_label);
                    
                    /* Update outer array size = target_index + 1 */
                    emit_mov_rax_r12(gen);
                    emit_rex_w(gen);
                    buffer_write_byte(&gen->code, 0xFF);  /* inc rax */
                    buffer_write_byte(&gen->code, 0xC0);
                    emit_mov_rbp_offset_rax(gen, arr->array_size_offset);
                    
                    /* Update last_val to the target sub-array address */
                    emit_lea_rax_rbp_offset(gen, arr->stack_offset);
                    emit_mov_rcx_r12(gen);
                    emit_imul_rcx_8(gen);
                    emit_add_rax_rcx(gen);
                    emit_mov_rax_ptr_rax(gen);  /* rax = arr[target_index] */
                    emit_mov_rbp_offset_rax(gen, arr->array_last_val_offset);
                    
                    /* Restore r12, r13 */
                    emit_pop_r13(gen);
                    emit_pop_r12(gen);
                    
                    /* The pops above moved RSP up by 16 bytes, but that space is now
                     * part of the first sub-array's metadata. Move RSP back down. */
                    emit_sub_rsp_imm32(gen, 16);
                    
                    return 0;
                }
                
                /* Multi-dimensional type init - just allocate one sub-array */
                int metadata_size = 16;
                int data_size = 2048;
                emit_sub_rsp_imm32(gen, metadata_size + data_size);
                
                /* Initialize size to 0: [rsp] = 0 */
                emit_mov_rax_imm64(gen, 0);
                emit_rex_w(gen);
                buffer_write_byte(&gen->code, 0x89);  /* mov [rsp], rax */
                buffer_write_byte(&gen->code, 0x04);
                buffer_write_byte(&gen->code, 0x24);
                
                /* Initialize last_val to 0: [rsp+8] = 0 */
                emit_rex_w(gen);
                buffer_write_byte(&gen->code, 0x89);  /* mov [rsp+8], rax */
                buffer_write_byte(&gen->code, 0x44);
                buffer_write_byte(&gen->code, 0x24);
                buffer_write_byte(&gen->code, 0x08);
                
                /* Get address of array data (rsp + 16) */
                emit_rex_w(gen);
                buffer_write_byte(&gen->code, 0x8D);  /* lea rax, [rsp+16] */
                buffer_write_byte(&gen->code, 0x44);
                buffer_write_byte(&gen->code, 0x24);
                buffer_write_byte(&gen->code, 0x10);
                
                /* Store this address into target element */
                emit_push_rax(gen); /* Save new array address */
                
                /* Calculate address of target element */
                if (arr->is_pointer_array) {
                    emit_mov_rax_rbp_offset(gen, arr->stack_offset);
                } else {
                    emit_lea_rax_rbp_offset(gen, arr->stack_offset);
                }
                
                /* Traverse indices except last one */
                for (size_t i = 0; i < node->data.array_assign.indices.count - 1; ++i) {
                    emit_push_rax(gen);
                    if (codegen_expression(gen, node->data.array_assign.indices.items[i]) != 0) return -1;
                    emit_mov_rbx_rax(gen);
                    emit_pop_rax(gen);
                    emit_imul_rbx_8(gen);
                    emit_add_rax_rbx(gen);
                    emit_mov_rax_ptr_rax(gen);
                }
                
                /* Last index */
                emit_push_rax(gen);
                if (codegen_expression(gen, node->data.array_assign.indices.items[node->data.array_assign.indices.count - 1]) != 0) return -1;
                emit_mov_rbx_rax(gen);
                emit_pop_rax(gen);
                emit_imul_rbx_8(gen);
                emit_add_rax_rbx(gen); /* rax = address of element */
                
                /* Pop new array address and store */
                emit_pop_rbx(gen); /* rbx = new array address */
                emit_mov_ptr_rax_rbx(gen);
                
                return 0;
            }
            
            /* Evaluate value first, push to stack */
            if (codegen_expression(gen, node->data.array_assign.value) != 0) return -1;
            emit_push_rax(gen);  /* Stack: [value] */
            
            /* For single-dimension arrays, implement auto-fill logic */
            if (node->data.array_assign.indices.count == 1 && !arr->is_pointer_array) {
                /* Evaluate the index */
                if (codegen_expression(gen, node->data.array_assign.indices.items[0]) != 0) return -1;
                /* rax = target index */
                
                /* Save target index */
                emit_push_rax(gen);  /* Stack: [value, target_index] */
                
                /* Load current size */
                emit_mov_rbx_rax(gen);  /* rbx = target index */
                emit_mov_rax_rbp_offset(gen, arr->array_size_offset);  /* rax = size */
                
                /* Check if size > 0 AND target_index > size */
                emit_cmp_rax_0(gen);
                int skip_fill_label = codegen_create_label(gen);
                size_t jz_pos = gen->code.size + 2;
                emit_je_rel32(gen, 0);  /* If size == 0, skip fill */
                codegen_patch_label(gen, skip_fill_label, jz_pos);
                
                /* rax = size, rbx = target_index */
                /* Check if target_index > size (i.e., rbx > rax) */
                emit_cmp_rax_rbx(gen);
                int skip_fill2_label = codegen_create_label(gen);
                size_t jge2_pos = gen->code.size + 2;
                emit_jge_rel32(gen, 0);  /* If size >= target, skip fill */
                codegen_patch_label(gen, skip_fill2_label, jge2_pos);
                
                /* Need to fill from size to target_index-1 with last_val */
                /* Use rcx as loop counter, start at size (rax), end at target (rbx) */
                emit_mov_rcx_rax(gen);  /* rcx = i = size */
                emit_push_rbx(gen);     /* Save target_index */
                
                /* Fill loop */
                int fill_loop_label = codegen_create_label(gen);
                int fill_end_label = codegen_create_label(gen);
                codegen_set_label(gen, fill_loop_label);
                
                /* Check: i < target_index */
                /* target is at [rsp], rcx = i */
                emit_rex_w(gen);
                buffer_write_byte(&gen->code, 0x8B);  /* mov rax, [rsp] */
                buffer_write_byte(&gen->code, 0x04);
                buffer_write_byte(&gen->code, 0x24);
                /* rax = target_index */
                emit_cmp_rcx_rbx(gen);  /* Wrong - rbx was clobbered */
                
                /* Fix: compare rcx with rax (target from stack) */
                emit_cmp_rax_rcx(gen);  /* cmp target, i */
                size_t jle_pos = gen->code.size + 2;
                buffer_write_byte(&gen->code, 0x0F);  /* jle rel32 - if target <= i, done */
                buffer_write_byte(&gen->code, 0x8E);
                buffer_write_u32(&gen->code, 0);
                codegen_patch_label(gen, fill_end_label, jle_pos);
                
                /* Store last_val at arr[i] */
                emit_push_rcx(gen);  /* Save i */
                
                /* Calculate address: base + i * 8 */
                emit_lea_rax_rbp_offset(gen, arr->stack_offset);  /* rax = base */
                emit_pop_rcx(gen);   /* rcx = i */
                emit_push_rcx(gen);  /* Keep i */
                
                /* rcx * 8 -> rbx */
                emit_mov_rbx_rax(gen);  /* rbx = base */
                emit_mov_rax_rcx(gen);  /* rax = i */
                emit_push_rbx(gen);     /* Save base */
                emit_rex_w(gen);
                buffer_write_byte(&gen->code, 0x6B);  /* imul rax, rax, 8 */
                buffer_write_byte(&gen->code, 0xC0);
                buffer_write_byte(&gen->code, 0x08);
                emit_pop_rbx(gen);      /* rbx = base */
                emit_add_rax_rbx(gen);  /* rax = base + i*8 = &arr[i] */
                
                /* Load last_val */
                emit_mov_rbx_rax(gen);  /* rbx = &arr[i] */
                emit_mov_rax_rbp_offset(gen, arr->array_last_val_offset);
                
                /* Store: mov [rbx], rax */
                emit_mov_ptr_rbx_rax(gen);
                
                /* i++ */
                emit_pop_rcx(gen);
                emit_inc_rcx(gen);
                
                /* Jump back to loop start */
                size_t jmp_pos = gen->code.size + 1;
                emit_jmp_rel32(gen, 0);
                int32_t rel = (int32_t)(gen->labels[fill_loop_label].offset - (jmp_pos + 4));
                memcpy(gen->code.data + jmp_pos, &rel, 4);
                
                codegen_set_label(gen, fill_end_label);
                emit_pop_rax(gen);  /* Pop saved target */
                
                codegen_set_label(gen, skip_fill2_label);
                codegen_set_label(gen, skip_fill_label);
                
                /* Now do the actual assignment */
                /* Stack: [value, target_index] */
                emit_pop_rax(gen);  /* rax = target_index */
                emit_mov_rbx_rax(gen);  /* rbx = index */
                
                /* Calculate element address */
                emit_lea_rax_rbp_offset(gen, arr->stack_offset);  /* rax = base */
                emit_imul_rbx_8(gen);   /* rbx = index * 8 */
                emit_add_rax_rbx(gen);  /* rax = element address */
                
                /* Get value from stack */
                emit_pop_rbx(gen);      /* rbx = value */
                
                /* Store value */
                emit_mov_ptr_rax_rbx(gen);
                
                /* Update last_val */
                emit_mov_rax_rbx(gen);  /* rax = value */
                emit_mov_rbp_offset_rax(gen, arr->array_last_val_offset);
                
                /* Need to get index again to update size */
                /* Re-evaluate index (simpler than saving it) */
                if (codegen_expression(gen, node->data.array_assign.indices.items[0]) != 0) return -1;
                /* rax = index */
                emit_rex_w(gen);
                buffer_write_byte(&gen->code, 0xFF);  /* inc rax */
                buffer_write_byte(&gen->code, 0xC0);
                /* rax = index + 1 */
                
                emit_mov_rbx_rax(gen);  /* rbx = index + 1 */
                emit_mov_rax_rbp_offset(gen, arr->array_size_offset);  /* rax = old size */
                emit_cmp_rax_rbx(gen);
                
                /* if old_size >= new_size, skip update */
                int skip_size_update = codegen_create_label(gen);
                size_t jge_pos = gen->code.size + 2;
                emit_jge_rel32(gen, 0);
                codegen_patch_label(gen, skip_size_update, jge_pos);
                
                /* Update size */
                emit_mov_rax_rbx(gen);
                emit_mov_rbp_offset_rax(gen, arr->array_size_offset);
                
                codegen_set_label(gen, skip_size_update);
                
                return 0;
            }
            
            /* Multi-dimensional array - simple assignment (no auto-fill for now) */
            /* Load base address */
            if (arr->is_pointer_array) {
                emit_mov_rax_rbp_offset(gen, arr->stack_offset);
            } else {
                emit_lea_rax_rbp_offset(gen, arr->stack_offset);
            }
            
            /* Traverse indices except last one - get pointer to innermost array */
            for (size_t i = 0; i < node->data.array_assign.indices.count - 1; ++i) {
                emit_push_rax(gen); /* Save base */
                
                if (codegen_expression(gen, node->data.array_assign.indices.items[i]) != 0) return -1;
                emit_mov_rbx_rax(gen); /* rbx = index */
                
                emit_pop_rax(gen); /* Restore base */
                
                emit_imul_rbx_8(gen);
                emit_add_rax_rbx(gen);
                emit_mov_rax_ptr_rax(gen); /* Load pointer to next array */
            }
            
            /* rax = innermost array base pointer */
            emit_push_rax(gen);  /* Save array_base - Stack: [value, array_base] */
            
            /* Evaluate last index */
            if (codegen_expression(gen, node->data.array_assign.indices.items[node->data.array_assign.indices.count - 1]) != 0) return -1;
            emit_mov_rbx_rax(gen);  /* rbx = target_index */
            
            emit_pop_rax(gen);  /* rax = array_base */
            
            /* Save array_base and target_index for auto-fill */
            emit_push_rax(gen);  /* Stack: [value, array_base] */
            emit_push_rbx(gen);  /* Stack: [value, array_base, target_index] */
            
            /* === Auto-fill: check if size > 0 and target > size === */
            /* size is at [array_base - 16], last_val at [array_base - 8] */
            
            /* Load size */
            emit_rex_w(gen);
            buffer_write_byte(&gen->code, 0x8B);  /* mov rcx, [rax-16] */
            buffer_write_byte(&gen->code, 0x48);
            buffer_write_byte(&gen->code, 0xF0);  /* -16 */
            /* rcx = size */
            
            /* if size == 0, skip fill */
            emit_rex_w(gen);
            buffer_write_byte(&gen->code, 0x83);  /* cmp rcx, 0 */
            buffer_write_byte(&gen->code, 0xF9);
            buffer_write_byte(&gen->code, 0x00);
            
            int skip_fill_label = codegen_create_label(gen);
            size_t jz_pos = gen->code.size + 2;
            emit_je_rel32(gen, 0);
            codegen_patch_label(gen, skip_fill_label, jz_pos);
            
            /* if target_index <= size, skip fill */
            /* rbx = target_index, rcx = size */
            emit_cmp_rcx_rbx(gen);  /* cmp size, target */
            int skip_fill2_label = codegen_create_label(gen);
            size_t jge_pos = gen->code.size + 2;
            emit_jge_rel32(gen, 0);  /* if size >= target, skip */
            codegen_patch_label(gen, skip_fill2_label, jge_pos);
            
            /* Fill loop: i = size (rcx) to target-1 (rbx-1) */
            /* Load last_val from [array_base - 8] */
            emit_rex_w(gen);
            buffer_write_byte(&gen->code, 0x8B);  /* mov rax, [rsp+8] - array_base */
            buffer_write_byte(&gen->code, 0x44);
            buffer_write_byte(&gen->code, 0x24);
            buffer_write_byte(&gen->code, 0x08);
            emit_rex_w(gen);
            buffer_write_byte(&gen->code, 0x8B);  /* mov rdi, [rax-8] - last_val */
            buffer_write_byte(&gen->code, 0x78);
            buffer_write_byte(&gen->code, 0xF8);
            /* rdi = last_val, rcx = i, rbx = target */
            
            int fill_loop = codegen_create_label(gen);
            int fill_done = codegen_create_label(gen);
            codegen_set_label(gen, fill_loop);
            
            /* if i >= target, done */
            emit_cmp_rcx_rbx(gen);
            size_t jge2_pos = gen->code.size + 2;
            emit_jge_rel32(gen, 0);
            codegen_patch_label(gen, fill_done, jge2_pos);
            
            /* arr[i] = last_val */
            /* address = array_base + i * 8 */
            emit_push_rcx(gen);
            emit_push_rbx(gen);
            emit_push_rax(gen);  /* Save rax (will be clobbered) */
            
            emit_rex_w(gen);
            buffer_write_byte(&gen->code, 0x8B);  /* mov rax, [rsp+32] - array_base */
            buffer_write_byte(&gen->code, 0x44);
            buffer_write_byte(&gen->code, 0x24);
            buffer_write_byte(&gen->code, 0x20);
            emit_mov_rbx_rax(gen);  /* rbx = array_base */
            
            emit_rex_w(gen);
            buffer_write_byte(&gen->code, 0x8B);  /* mov rax, [rsp+16] - i (saved rcx) */
            buffer_write_byte(&gen->code, 0x44);
            buffer_write_byte(&gen->code, 0x24);
            buffer_write_byte(&gen->code, 0x10);
            /* rax = i */
            emit_rex_w(gen);
            buffer_write_byte(&gen->code, 0x6B);  /* imul rax, rax, 8 */
            buffer_write_byte(&gen->code, 0xC0);
            buffer_write_byte(&gen->code, 0x08);
            emit_add_rax_rbx(gen);  /* rax = &arr[i] */
            
            /* Store last_val (rdi) at [rax] */
            emit_rex_w(gen);
            buffer_write_byte(&gen->code, 0x89);  /* mov [rax], rdi */
            buffer_write_byte(&gen->code, 0x38);
            
            emit_pop_rax(gen);
            emit_pop_rbx(gen);
            emit_pop_rcx(gen);
            
            /* i++ */
            emit_inc_rcx(gen);
            
            /* Jump back */
            size_t jmp_pos = gen->code.size + 1;
            emit_jmp_rel32(gen, 0);
            int32_t rel = (int32_t)(gen->labels[fill_loop].offset - (jmp_pos + 4));
            memcpy(gen->code.data + jmp_pos, &rel, 4);
            
            codegen_set_label(gen, fill_done);
            codegen_set_label(gen, skip_fill2_label);
            codegen_set_label(gen, skip_fill_label);
            
            /* === Now do actual assignment === */
            /* Stack: [value, array_base, target_index] */
            emit_pop_rbx(gen);  /* rbx = target_index */
            emit_pop_rax(gen);  /* rax = array_base */
            emit_push_rax(gen);  /* Keep array_base */
            emit_push_rbx(gen);  /* Keep target_index */
            
            /* Calculate address */
            emit_imul_rbx_8(gen);
            emit_add_rax_rbx(gen);  /* rax = &arr[target] */
            
            /* Get value from stack */
            emit_rex_w(gen);
            buffer_write_byte(&gen->code, 0x8B);  /* mov rbx, [rsp+16] - value */
            buffer_write_byte(&gen->code, 0x5C);
            buffer_write_byte(&gen->code, 0x24);
            buffer_write_byte(&gen->code, 0x10);
            
            emit_mov_ptr_rax_rbx(gen);  /* Store value */
            
            /* Update last_val */
            emit_pop_rcx(gen);  /* rcx = target_index */
            emit_pop_rax(gen);  /* rax = array_base */
            emit_push_rax(gen);
            emit_push_rcx(gen);
            emit_rex_w(gen);
            buffer_write_byte(&gen->code, 0x89);  /* mov [rax-8], rbx */
            buffer_write_byte(&gen->code, 0x58);
            buffer_write_byte(&gen->code, 0xF8);
            
            /* Update size = max(size, target+1) */
            emit_pop_rcx(gen);  /* rcx = target */
            emit_inc_rcx(gen);  /* rcx = target + 1 */
            emit_pop_rax(gen);  /* rax = array_base */
            
            /* Load old size */
            emit_rex_w(gen);
            buffer_write_byte(&gen->code, 0x8B);  /* mov rbx, [rax-16] */
            buffer_write_byte(&gen->code, 0x58);
            buffer_write_byte(&gen->code, 0xF0);
            /* rbx = old_size, rcx = new_size */
            
            emit_cmp_rcx_rbx(gen);  /* cmp new, old */
            int skip_size = codegen_create_label(gen);
            size_t jle_pos2 = gen->code.size + 2;
            buffer_write_byte(&gen->code, 0x0F);  /* jle */
            buffer_write_byte(&gen->code, 0x8E);
            buffer_write_u32(&gen->code, 0);
            codegen_patch_label(gen, skip_size, jle_pos2);
            
            /* Update: [array_base - 16] = new_size */
            emit_rex_w(gen);
            buffer_write_byte(&gen->code, 0x89);  /* mov [rax-16], rcx */
            buffer_write_byte(&gen->code, 0x48);
            buffer_write_byte(&gen->code, 0xF0);
            
            codegen_set_label(gen, skip_size);
            
            /* Pop value */
            emit_pop_rax(gen);
            
            return 0;
        }

        case AST_STRUCT_ASSIGN: {
            /* struct.field = value or arr[i].field = value (or via struct pointer) */
            StackVar *struct_var = stack_frame_find(&gen->stack, node->data.struct_assign.struct_name);
            if (!struct_var) {
                gen->error_msg = strdup("Undefined struct variable");
                gen->error_line = node->line;
                return -1;
            }
            
            /* Check if it's a struct array access (arr[i].field = value) */
            int is_struct_array = (struct_var->is_array && struct_var->struct_name);
            int is_struct_ptr = (struct_var->type == TYPE_STRUCT_PTR);
            
            /* Find struct definition using the struct variable's type name */
            StructDefInfo *current_struct = struct_def_table_find(&gen->struct_defs, struct_var->struct_name);
            if (!current_struct) {
                gen->error_msg = strdup("Struct definition not found");
                gen->error_line = node->line;
                return -1;
            }
            
            /* Calculate struct element size */
            size_t struct_size = calc_struct_size(&gen->struct_defs, current_struct);
            
            /* Handle nested field paths like "stats.vie" */
            char *field_path = strdup(node->data.struct_assign.field_name);
            char *saveptr;
            char *field_token = strtok_r(field_path, ".", &saveptr);
            int field_offset = 0;
            DataType field_type = TYPE_UNKNOWN;
            StructDefInfo *field_struct = current_struct;
            
            while (field_token && field_struct) {
                /* Find this field in the current struct */
                int this_offset = 0;
                int found = 0;
                StructDefInfo *nested_struct = NULL;
                
                for (size_t i = 0; i < field_struct->fields.count; ++i) {
                    if (strcmp(field_struct->fields.items[i].name, field_token) == 0) {
                        found = 1;
                        field_type = field_struct->fields.items[i].type;
                        /* Check if this field is itself a struct (for further nesting) */
                        char nested_name[64];
                        strncpy(nested_name, field_token, sizeof(nested_name) - 1);
                        nested_name[0] = toupper(nested_name[0]);
                        nested_name[sizeof(nested_name) - 1] = '\0';
                        nested_struct = struct_def_table_find(&gen->struct_defs, nested_name);
                        if (!nested_struct) {
                            nested_struct = struct_def_table_find(&gen->struct_defs, field_token);
                        }
                        break;
                    }
                    /* Calculate offset using proper field size (handles nested structs) */
                    this_offset += (int)calc_field_size(&gen->struct_defs,
                                                         field_struct->fields.items[i].name,
                                                         field_struct->fields.items[i].type);
                }
                
                if (!found) {
                    free(field_path);
                    gen->error_msg = strdup("Field not found in struct");
                    gen->error_line = node->line;
                    return -1;
                }
                
                field_offset += this_offset;
                
                /* Move to the nested struct for the next field */
                field_struct = nested_struct;
                field_token = strtok_r(NULL, ".", &saveptr);
            }
            free(field_path);
            
            /* Evaluate the value */
            if (codegen_expression(gen, node->data.struct_assign.value) != 0)
                return -1;
            
            if (node->data.struct_assign.indices.count > 0) {
                /* Struct array assignment: arr[i]...[j].field = value */
                /* rax has the value to store, save it */
                emit_push_rax(gen);
                
                /* Get base address */
                if (struct_var->is_pointer_array) {
                    emit_mov_rax_rbp_offset(gen, struct_var->stack_offset);
                } else {
                    emit_lea_rax_rbp_offset(gen, struct_var->stack_offset);
                }
                
                /* Handle all indices except the last one (pointer chasing) */
                for (size_t i = 0; i < node->data.struct_assign.indices.count - 1; ++i) {
                    emit_push_rax(gen); /* Save base */
                    if (codegen_expression(gen, node->data.struct_assign.indices.items[i]) != 0) return -1;
                    emit_mov_rbx_rax(gen); /* rbx = index */
                    emit_pop_rax(gen); /* Restore base */
                    
                    emit_imul_rbx_8(gen);
                    emit_add_rax_rbx(gen);
                    emit_mov_rax_ptr_rax(gen); /* Load pointer to next array */
                }
                
                /* Handle last index (struct access) */
                emit_push_rax(gen); /* Save base */
                if (codegen_expression(gen, node->data.struct_assign.indices.items[node->data.struct_assign.indices.count - 1]) != 0) return -1;
                emit_mov_rbx_rax(gen); /* rbx = index */
                emit_pop_rax(gen); /* Restore base */
                
                /* Calculate offset: index * struct_size */
                emit_push_rax(gen); /* Save base */
                emit_mov_rax_imm64(gen, struct_size);
                emit_imul_rax_rbx(gen); /* rax = index * struct_size */
                emit_mov_rbx_rax(gen); /* rbx = offset */
                emit_pop_rax(gen); /* Restore base */
                
                emit_add_rax_rbx(gen); /* rax = address of struct element */
                emit_mov_rbx_rax(gen); /* rbx = struct element address */
                
                /* Restore value to rax */
                emit_pop_rax(gen);
                
                /* Store value at [rbx + field_offset] */
                emit_rex_w(gen);
                buffer_write_byte(&gen->code, 0x89);  /* mov [r64+disp32], r64 */
                buffer_write_byte(&gen->code, 0x83);  /* ModRM: rax -> [rbx + disp32] */
                buffer_write_u32(&gen->code, (uint32_t)field_offset);
            } else if (is_struct_ptr) {
                /* For struct pointer: store value at [pointer + field_offset] */
                /* rax has the value to store, save it */
                emit_push_rax(gen);
                /* Load struct pointer */
                emit_mov_rax_rbp_offset(gen, struct_var->stack_offset);
                /* Move pointer to rbx */
                emit_mov_rbx_rax(gen);
                /* Restore value to rax */
                emit_pop_rax(gen);
                /* Store: mov [rbx + field_offset], rax */
                emit_rex_w(gen);
                buffer_write_byte(&gen->code, 0x89);  /* mov [r64+disp32], r64 */
                buffer_write_byte(&gen->code, 0x83);  /* ModRM: rax -> [rbx + disp32] */
                buffer_write_u32(&gen->code, (uint32_t)field_offset);
                
                /* For strings, also store the length */
                if (field_type == TYPE_STRING) {
                    ASTNode *value_node = node->data.struct_assign.value;
                    size_t str_len = 0;
                    if (value_node->type == AST_STRING) {
                        str_len = strlen(value_node->data.string.value);
                    }
                    emit_mov_rax_imm64(gen, str_len);
                    /* Store length at [rbx + field_offset - 8] */
                    emit_rex_w(gen);
                    buffer_write_byte(&gen->code, 0x89);
                    buffer_write_byte(&gen->code, 0x83);
                    buffer_write_u32(&gen->code, (uint32_t)(field_offset - 8));
                }
            } else {
                /* Direct struct: Store at struct_offset + field_offset */
                if (field_type == TYPE_STRING) {
                    /* For strings, need to store address and length */
                    /* rax contains the address of the string data */
                    emit_mov_rbp_offset_rax(gen, struct_var->stack_offset + field_offset);
                    /* Now we need to store the length */
                    /* If the value is a string literal, get its length directly */
                    ASTNode *value_node = node->data.struct_assign.value;
                    size_t str_len = 0;
                    if (value_node->type == AST_STRING) {
                        str_len = strlen(value_node->data.string.value);
                    } else if (value_node->type == AST_IDENTIFIER) {
                        /* Look up the variable's string length */
                        StackVar *src_var = stack_frame_find(&gen->stack, value_node->data.identifier.name);
                        if (src_var && src_var->type == TYPE_STRING) {
                            str_len = src_var->string_length;
                        }
                    }
                    emit_mov_rax_imm64(gen, str_len);
                    emit_mov_rbp_offset_rax(gen, struct_var->stack_offset + field_offset - 8);
                } else {
                    emit_mov_rbp_offset_rax(gen, struct_var->stack_offset + field_offset);
                }
            }
            return 0;
        }

        case AST_RETURN: {
            if (node->data.return_stmt.value) {
                if (codegen_expression(gen, node->data.return_stmt.value) != 0)
                    return -1;
            } else {
                emit_mov_eax_imm32(gen, 0);
            }
            
            /* If this is main (Eric), emit exit syscall */
            if (gen->current_function && 
                (strcmp(gen->current_function, "Eric") == 0 ||
                 strcmp(gen->current_function, "eric") == 0)) {
                emit_sys_exit(gen);
            } else {
                /* Function epilogue and return */
                emit_mov_rsp_rbp(gen);
                emit_pop_rbp(gen);
                emit_ret(gen);
            }
            return 0;
        }

        case AST_BREAK: {
            if (gen->loop_end_label == -1) {
                fprintf(stderr, "Error: 'deschreak' (break) used outside of loop\n");
                return -1;
            }
            /* Jump to end of loop */
            size_t jmp_pos = gen->code.size + 1;
            emit_jmp_rel32(gen, 0);
            codegen_patch_label(gen, gen->loop_end_label, jmp_pos);
            return 0;
        }

        case AST_CONTINUE: {
            if (gen->loop_start_label == -1) {
                fprintf(stderr, "Error: 'deschontinue' (continue) used outside of loop\n");
                return -1;
            }
            /* Jump to start/continue point of loop */
            size_t jmp_pos = gen->code.size + 1;
            emit_jmp_rel32(gen, 0);
            codegen_patch_label(gen, gen->loop_start_label, jmp_pos);
            return 0;
        }

        case AST_PRINT: {
            /* For print, we need to handle format strings with {var} interpolation */
            ASTNode *val = node->data.print_stmt.value;
            
            if (val && val->type == AST_STRING) {
                const char *fmt = val->data.string.value;
                
                if (!fmt) {
                    /* NULL string, just print newline */
                    size_t nl_offset = string_table_add(&gen->strings, "\n");
                    emit_mov_eax_imm32(gen, 1);
                    emit_mov_edi_imm32(gen, 1);
                    emit_mov_rsi_string_offset(gen, nl_offset);
                    emit_mov_rdx_imm64(gen, 1);
                    emit_syscall(gen);
                    return 0;
                }
                
                size_t fmt_len = strlen(fmt);
                
                /* If empty string, just print a newline */
                if (fmt_len == 0) {
                    size_t nl_offset = string_table_add(&gen->strings, "\n");
                    emit_mov_eax_imm32(gen, 1);
                    emit_mov_edi_imm32(gen, 1);
                    emit_mov_rsi_string_offset(gen, nl_offset);
                    emit_mov_rdx_imm64(gen, 1);
                    emit_syscall(gen);
                    return 0;
                }
                
                size_t i = 0;
                
                while (i < fmt_len) {
                    /* Look for '{' */
                    size_t start = i;
                    while (i < fmt_len && fmt[i] != '{') i++;
                    
                    /* Print static part before '{' */
                    if (i > start) {
                        char *static_part = malloc(i - start + 1);
                        memcpy(static_part, fmt + start, i - start);
                        static_part[i - start] = '\0';
                        
                        size_t str_offset = string_table_add(&gen->strings, static_part);
                        size_t len = strlen(static_part);
                        free(static_part);
                        
                        emit_mov_eax_imm32(gen, 1);       /* syscall: write */
                        emit_mov_edi_imm32(gen, 1);       /* fd: stdout */
                        emit_mov_rsi_string_offset(gen, str_offset);
                        emit_mov_rdx_imm64(gen, len);
                        emit_syscall(gen);
                    }
                    
                    if (i >= fmt_len) break;
                    
                    /* Found '{', look for '}' handling nested parens */
                    if (fmt[i] == '{') {
                        i++;  /* Skip '{' */
                        size_t var_start = i;
                        int paren_depth = 0;
                        while (i < fmt_len && (fmt[i] != '}' || paren_depth > 0)) {
                            if (fmt[i] == '(') paren_depth++;
                            else if (fmt[i] == ')') paren_depth--;
                            i++;
                        }
                        
                        if (i < fmt_len && fmt[i] == '}') {
                            /* Extract expression */
                            size_t expr_len = i - var_start;
                            char *expr = malloc(expr_len + 1);
                            memcpy(expr, fmt + var_start, expr_len);
                            expr[expr_len] = '\0';
                            
                            /* Check if it's a function call: name(...) */
                            char *paren = strchr(expr, '(');
                            if (paren && !strchr(expr, '[')) {
                                /* Parse function call */
                                size_t name_len = paren - expr;
                                char *func_name = malloc(name_len + 1);
                                memcpy(func_name, expr, name_len);
                                func_name[name_len] = '\0';
                                
                                /* Parse arguments */
                                char *args_start = paren + 1;
                                char *args_end = strrchr(args_start, ')');
                                
                                if (args_end) {
                                    /* Create a mini AST for the function call */
                                    ASTNode *call_node = ast_create(AST_FUNC_CALL, 0, 0);
                                    call_node->data.func_call.name = func_name;
                                    ast_list_init(&call_node->data.func_call.args);
                                    
                                    /* Parse multiple comma-separated arguments */
                                    size_t args_len = args_end - args_start;
                                    if (args_len > 0) {
                                        char *args_copy = malloc(args_len + 1);
                                        memcpy(args_copy, args_start, args_len);
                                        args_copy[args_len] = '\0';
                                        
                                        /* Split by comma */
                                        char *saveptr;
                                        char *arg_token = strtok_r(args_copy, ",", &saveptr);
                                        while (arg_token) {
                                            /* Trim whitespace */
                                            while (*arg_token == ' ') arg_token++;
                                            char *end = arg_token + strlen(arg_token) - 1;
                                            while (end > arg_token && *end == ' ') { *end = '\0'; end--; }
                                            
                                            /* Check if arg is a variable or number */
                                            StackVar *arg_var = stack_frame_find(&gen->stack, arg_token);
                                            ASTNode *arg_node;
                                            if (arg_var) {
                                                arg_node = ast_create(AST_IDENTIFIER, 0, 0);
                                                arg_node->data.identifier.name = strdup(arg_token);
                                            } else {
                                                /* Try as number */
                                                arg_node = ast_create(AST_NUMBER, 0, 0);
                                                arg_node->data.number.value = atof(arg_token);
                                                arg_node->data.number.is_float = (strchr(arg_token, '.') != NULL);
                                            }
                                            ast_list_push(&call_node->data.func_call.args, arg_node);
                                            
                                            arg_token = strtok_r(NULL, ",", &saveptr);
                                        }
                                        free(args_copy);
                                    }
                                    
                                    /* Compile and execute the function call */
                                    codegen_expression(gen, call_node);
                                    emit_print_int(gen);
                                    ast_free(call_node);
                                } else {
                                    free(func_name);
                                    size_t err_offset = string_table_add(&gen->strings, "<error>");
                                    emit_mov_eax_imm32(gen, 1);
                                    emit_mov_edi_imm32(gen, 1);
                                    emit_mov_rsi_string_offset(gen, err_offset);
                                    emit_mov_rdx_imm64(gen, 7);
                                    emit_syscall(gen);
                                }
                            }
                            /* Check if it's an array access: name[index] or name[index].field */
                            else if (strchr(expr, '[')) {
                                char *bracket = strchr(expr, '[');
                                size_t name_len = bracket - expr;
                                char *arr_name = malloc(name_len + 1);
                                memcpy(arr_name, expr, name_len);
                                arr_name[name_len] = '\0';
                                trim_whitespace(arr_name);
                                
                                /* Parse indices */
                                char *current_pos = bracket;
                                ASTNodeList indices;
                                ast_list_init(&indices);
                                
                                while (*current_pos == '[') {
                                    char *idx_start = current_pos + 1;
                                    char *idx_end = strchr(idx_start, ']');
                                    if (!idx_end) break;
                                    
                                    size_t idx_len = idx_end - idx_start;
                                    char *idx_expr = malloc(idx_len + 1);
                                    memcpy(idx_expr, idx_start, idx_len);
                                    idx_expr[idx_len] = '\0';
                                    trim_whitespace(idx_expr);
                                    
                                    /* Create index node */
                                    StackVar *idx_var = stack_frame_find(&gen->stack, idx_expr);
                                    ASTNode *idx_node;
                                    if (idx_var) {
                                        idx_node = ast_create(AST_IDENTIFIER, 0, 0);
                                        idx_node->data.identifier.name = strdup(idx_expr);
                                    } else {
                                        idx_node = ast_create(AST_NUMBER, 0, 0);
                                        idx_node->data.number.value = atof(idx_expr);
                                        idx_node->data.number.is_float = 0;
                                    }
                                    ast_list_push(&indices, idx_node);
                                    
                                    free(idx_expr);
                                    current_pos = idx_end + 1;
                                    while (*current_pos && isspace((unsigned char)*current_pos)) current_pos++;
                                }
                                
                                /* Optional field path after last ] */
                                char *field_path = NULL;
                                if (*current_pos == '.') {
                                    current_pos++;
                                    while (*current_pos && isspace((unsigned char)*current_pos)) current_pos++;
                                    if (*current_pos) {
                                        field_path = strdup(current_pos);
                                        trim_whitespace(field_path);
                                    }
                                }
                                
                                StackVar *arr = stack_frame_find(&gen->stack, arr_name);
                                int handled = 0;
                                
                                if (arr && arr->is_array) {
                                    int is_struct_array = (arr->struct_name != NULL && field_path && *field_path);
                                    if (is_struct_array) {
                                        /* Struct array access logic */
                                        StructDefInfo *struct_def = struct_def_table_find(&gen->struct_defs, arr->struct_name);
                                        if (struct_def) {
                                            size_t struct_size = calc_struct_size(&gen->struct_defs, struct_def);
                                            DataType field_type = TYPE_UNKNOWN;
                                            int field_offset = calc_field_offset(&gen->struct_defs, struct_def, field_path, &field_type);
                                            if (field_offset >= 0) {
                                                /* Load base address */
                                                if (arr->is_pointer_array) {
                                                    emit_mov_rax_rbp_offset(gen, arr->stack_offset);
                                                } else {
                                                    emit_lea_rax_rbp_offset(gen, arr->stack_offset);
                                                }
                                                
                                                /* Handle indices except last one */
                                                for (size_t i = 0; i < indices.count - 1; ++i) {
                                                    emit_push_rax(gen);
                                                    if (codegen_expression(gen, indices.items[i]) != 0) break;
                                                    emit_mov_rbx_rax(gen);
                                                    emit_pop_rax(gen);
                                                    emit_imul_rbx_8(gen);
                                                    emit_add_rax_rbx(gen);
                                                    emit_mov_rax_ptr_rax(gen);
                                                }
                                                
                                                /* Handle last index */
                                                emit_push_rax(gen);
                                                if (codegen_expression(gen, indices.items[indices.count - 1]) != 0) {
                                                    /* Error handling */
                                                }
                                                emit_mov_rbx_rax(gen);
                                                emit_pop_rax(gen);
                                                
                                                /* Calculate offset: index * struct_size */
                                                emit_push_rax(gen);
                                                emit_mov_rax_imm64(gen, struct_size);
                                                emit_imul_rax_rbx(gen);
                                                emit_mov_rbx_rax(gen);
                                                emit_pop_rax(gen);
                                                
                                                emit_add_rax_rbx(gen);
                                                
                                                emit_rex_w(gen);
                                                buffer_write_byte(&gen->code, 0x8B);
                                                buffer_write_byte(&gen->code, 0x80);
                                                buffer_write_u32(&gen->code, (uint32_t)field_offset);
                                                
                                                if (field_type == TYPE_STRING) {
                                                    emit_print_string_compute_len(gen);
                                                } else {
                                                    emit_print_int(gen);
                                                }
                                                handled = 1;
                                            }
                                        }
                                    }
                                    
                                    if (!handled) {
                                        /* Primitive array access */
                                        /* Load base address */
                                        if (arr->is_pointer_array) {
                                            emit_mov_rax_rbp_offset(gen, arr->stack_offset);
                                        } else {
                                            emit_lea_rax_rbp_offset(gen, arr->stack_offset);
                                        }
                                        
                                        /* Handle all indices */
                                        for (size_t i = 0; i < indices.count; ++i) {
                                            emit_push_rax(gen);
                                            if (codegen_expression(gen, indices.items[i]) != 0) break;
                                            emit_mov_rbx_rax(gen);
                                            emit_pop_rax(gen);
                                            emit_imul_rbx_8(gen);
                                            emit_add_rax_rbx(gen);
                                            emit_mov_rax_ptr_rax(gen);
                                        }
                                        
                                        emit_print_int(gen);
                                    }
                                } else {
                                    size_t err_offset = string_table_add(&gen->strings, "<undefined>");
                                    emit_mov_eax_imm32(gen, 1);
                                    emit_mov_edi_imm32(gen, 1);
                                    emit_mov_rsi_string_offset(gen, err_offset);
                                    emit_mov_rdx_imm64(gen, 11);
                                    emit_syscall(gen);
                                }
                                
                                free(arr_name);
                                if (field_path) free(field_path);
                                ast_list_free(&indices);
                            } else if (expr[0] == '*') {
                                /* Pointer dereference: *ptr */
                                char *ptr_name = expr + 1;
                                StackVar *ptr_var = stack_frame_find(&gen->stack, ptr_name);
                                if (ptr_var) {
                                    /* Load pointer value from stack */
                                    emit_mov_rax_rbp_offset(gen, ptr_var->stack_offset);
                                    /* Dereference: load value at pointer address */
                                    emit_mov_rax_ptr_rax(gen);
                                    /* Print the dereferenced value */
                                    emit_print_int(gen);
                                } else {
                                    /* Pointer variable not found */
                                    size_t err_offset = string_table_add(&gen->strings, "<undefined>");
                                    emit_mov_eax_imm32(gen, 1);
                                    emit_mov_edi_imm32(gen, 1);
                                    emit_mov_rsi_string_offset(gen, err_offset);
                                    emit_mov_rdx_imm64(gen, 11);
                                    emit_syscall(gen);
                                }
                            } else if (strchr(expr, '.')) {
                                /* Struct field access: struct.field or struct.field.subfield */
                                /* Split on first dot to get struct name */
                                char *expr_copy = strdup(expr);
                                char *dot = strchr(expr_copy, '.');
                                *dot = '\0';
                                char *struct_name = expr_copy;
                                char *field_path = dot + 1;  /* Could be "field" or "field.subfield" */
                                
                                StackVar *struct_var = stack_frame_find(&gen->stack, struct_name);
                                if (struct_var) {
                                    /* Check if it's a struct pointer */
                                    int is_struct_ptr = (struct_var->type == TYPE_STRUCT_PTR);
                                    
                                    /* Navigate through the field path */
                                    StructDefInfo *current_struct = struct_def_table_find(&gen->struct_defs, struct_var->struct_name);
                                    int total_offset = 0;
                                    DataType final_field_type = TYPE_UNKNOWN;
                                    
                                    /* Parse the field path (e.g., "stats.vie") */
                                    char *field_copy = strdup(field_path);
                                    char *saveptr;
                                    char *field_token = strtok_r(field_copy, ".", &saveptr);
                                    
                                    while (field_token && current_struct) {
                                        /* Find this field in current struct */
                                        int field_offset = 0;
                                        DataType field_type = TYPE_UNKNOWN;
                                        
                                        for (size_t fi = 0; fi < current_struct->fields.count; ++fi) {
                                            if (strcmp(current_struct->fields.items[fi].name, field_token) == 0) {
                                                field_type = current_struct->fields.items[fi].type;
                                                /* Check if this field is a nested struct */
                                                if (field_type == TYPE_UNKNOWN) {
                                                    /* It's a struct type - find which one */
                                                    /* For now, assume field name matches struct name if not a basic type */
                                                }
                                                break;
                                            }
                                            /* Use calc_field_size for proper nested struct handling */
                                            field_offset += (int)calc_field_size(&gen->struct_defs,
                                                                                 current_struct->fields.items[fi].name,
                                                                                 current_struct->fields.items[fi].type);
                                        }
                                        
                                        total_offset += field_offset;
                                        final_field_type = field_type;
                                        
                                        /* Check if there's another level */
                                        char *next_field = strtok_r(NULL, ".", &saveptr);
                                        if (next_field) {
                                            /* Find the nested struct definition */
                                            /* Look for a struct with the field name as type */
                                            for (size_t si = 0; si < current_struct->fields.count; ++si) {
                                                if (strcmp(current_struct->fields.items[si].name, field_token) == 0) {
                                                    /* This field might be a struct - try to find its definition */
                                                    /* We need to figure out the struct type name */
                                                    /* For now, use a heuristic: capitalize first letter */
                                                    char struct_type_name[64];
                                                    strncpy(struct_type_name, field_token, sizeof(struct_type_name) - 1);
                                                    struct_type_name[0] = toupper(struct_type_name[0]);
                                                    struct_type_name[sizeof(struct_type_name) - 1] = '\0';
                                                    
                                                    StructDefInfo *nested = struct_def_table_find(&gen->struct_defs, struct_type_name);
                                                    if (nested) {
                                                        current_struct = nested;
                                                    } else {
                                                        /* Try exact field name */
                                                        nested = struct_def_table_find(&gen->struct_defs, field_token);
                                                        if (nested) {
                                                            current_struct = nested;
                                                        }
                                                    }
                                                    break;
                                                }
                                            }
                                        }
                                        field_token = next_field;
                                    }
                                    free(field_copy);
                                    
                                    /* Now generate code to load the value */
                                    if (is_struct_ptr) {
                                        /* Load the pointer (address of struct) */
                                        emit_mov_rax_rbp_offset(gen, struct_var->stack_offset);
                                        /* Load field from [rax + total_offset] */
                                        emit_rex_w(gen);
                                        buffer_write_byte(&gen->code, 0x8B);
                                        buffer_write_byte(&gen->code, 0x80);
                                        buffer_write_u32(&gen->code, (uint32_t)total_offset);
                                    } else {
                                        /* Direct struct: Load field value from stack */
                                        emit_mov_rax_rbp_offset(gen, struct_var->stack_offset + total_offset);
                                    }
                                    
                                    /* Print based on field type */
                                    if (final_field_type == TYPE_STRING) {
                                        /* For struct strings, compute length at runtime */
                                        /* rax already has the string address */
                                        emit_print_string_compute_len(gen);
                                    } else {
                                        emit_print_int(gen);
                                    }
                                } else {
                                    /* Struct variable not found */
                                    size_t err_offset = string_table_add(&gen->strings, "<undefined>");
                                    emit_mov_eax_imm32(gen, 1);
                                    emit_mov_edi_imm32(gen, 1);
                                    emit_mov_rsi_string_offset(gen, err_offset);
                                    emit_mov_rdx_imm64(gen, 11);
                                    emit_syscall(gen);
                                }
                                free(expr_copy);
                            } else {
                                /* Simple variable or constant */
                                StackVar *var = stack_frame_find(&gen->stack, expr);
                                if (var) {
                                    /* Load variable value into rax */
                                    emit_mov_rax_rbp_offset(gen, var->stack_offset);
                                    
                                    /* Print based on variable type */
                                    switch (var->type) {
                                        case TYPE_INT:
                                            emit_print_int(gen);
                                            break;
                                        case TYPE_CHAR:
                                            /* Print char as actual character */
                                            emit_print_char(gen);
                                            break;
                                        case TYPE_STRING:
                                            /* For string, rax contains string address (after patching) */
                                            /* Use var->string_length for the length */
                                            emit_print_string_offset(gen, var->string_length);
                                            break;
                                        default:
                                            emit_print_int(gen);  /* Default to int */
                                            break;
                                    }
                                } else {
                                    /* Check if it's a constant */
                                    int found = 0;
                                    if (gen->constants) {
                                        for (size_t ci = 0; ci < gen->constants->count; ++ci) {
                                            ASTNode *const_node = gen->constants->items[ci];
                                            if (const_node->type == AST_CONST_DECL &&
                                                strcmp(const_node->data.const_decl.name, expr) == 0) {
                                                /* Handle based on constant type */
                                                if (const_node->data.const_decl.const_type == TYPE_STRING) {
                                                    /* For string constants, print the string directly */
                                                    if (const_node->data.const_decl.value->type == AST_STRING) {
                                                        const char *str_val = const_node->data.const_decl.value->data.string.value;
                                                        size_t str_offset = string_table_add(&gen->strings, str_val);
                                                        size_t len = strlen(str_val);
                                                        emit_mov_eax_imm32(gen, 1);
                                                        emit_mov_edi_imm32(gen, 1);
                                                        emit_mov_rsi_string_offset(gen, str_offset);
                                                        emit_mov_rdx_imm64(gen, len);
                                                        emit_syscall(gen);
                                                    }
                                                } else if (const_node->data.const_decl.const_type == TYPE_FLOAT) {
                                                    /* For float, print as fixed decimal */
                                                    /* Since we don't have float printing, convert to string at compile time */
                                                    if (const_node->data.const_decl.value->type == AST_NUMBER) {
                                                        char buf[64];
                                                        snprintf(buf, sizeof(buf), "%g", const_node->data.const_decl.value->data.number.value);
                                                        size_t str_offset = string_table_add(&gen->strings, buf);
                                                        size_t len = strlen(buf);
                                                        emit_mov_eax_imm32(gen, 1);
                                                        emit_mov_edi_imm32(gen, 1);
                                                        emit_mov_rsi_string_offset(gen, str_offset);
                                                        emit_mov_rdx_imm64(gen, len);
                                                        emit_syscall(gen);
                                                    } else {
                                                        codegen_expression(gen, const_node->data.const_decl.value);
                                                        emit_print_int(gen);
                                                    }
                                                } else {
                                                    /* For int and other types */
                                                    codegen_expression(gen, const_node->data.const_decl.value);
                                                    emit_print_int(gen);
                                                }
                                                found = 1;
                                                break;
                                            }
                                        }
                                    }
                                    
                                    /* Check if it's an enum value */
                                    if (!found && gen->enums) {
                                        for (size_t ei = 0; ei < gen->enums->count; ++ei) {
                                            ASTNode *enum_node = gen->enums->items[ei];
                                            if (enum_node->type == AST_ENUM_DEF) {
                                                for (size_t ej = 0; ej < enum_node->data.enum_def.member_count; ++ej) {
                                                    if (strcmp(enum_node->data.enum_def.members[ej], expr) == 0) {
                                                        emit_mov_eax_imm32(gen, (int32_t)ej);
                                                        emit_print_int(gen);
                                                        found = 1;
                                                        break;
                                                    }
                                                }
                                            }
                                            if (found) break;
                                        }
                                    }
                                    
                                    if (!found) {
                                        /* Variable not found, print error marker */
                                        size_t err_offset = string_table_add(&gen->strings, "<undefined>");
                                        emit_mov_eax_imm32(gen, 1);
                                        emit_mov_edi_imm32(gen, 1);
                                        emit_mov_rsi_string_offset(gen, err_offset);
                                        emit_mov_rdx_imm64(gen, 11);
                                        emit_syscall(gen);
                                    }
                                }
                            }
                            free(expr);
                            i++;  /* Skip '}' */
                        }
                    }
                }
                
                /* Print newline at the end */
                size_t nl_offset = string_table_add(&gen->strings, "\n");
                emit_mov_eax_imm32(gen, 1);
                emit_mov_edi_imm32(gen, 1);
                emit_mov_rsi_string_offset(gen, nl_offset);
                emit_mov_rdx_imm64(gen, 1);
                emit_syscall(gen);
                
            } else {
                /* For non-string values, evaluate and print as number */
                if (codegen_expression(gen, val) != 0) return -1;
                emit_print_int(gen);
                
                /* Print newline */
                size_t nl_offset = string_table_add(&gen->strings, "\n");
                emit_mov_eax_imm32(gen, 1);
                emit_mov_edi_imm32(gen, 1);
                emit_mov_rsi_string_offset(gen, nl_offset);
                emit_mov_rdx_imm64(gen, 1);
                emit_syscall(gen);
            }
            return 0;
        }

        case AST_IF: {
            /* Evaluate condition */
            if (codegen_expression(gen, node->data.conditional.condition) != 0)
                return -1;
            
            emit_cmp_rax_0(gen);
            
            int else_label = codegen_create_label(gen);
            int end_label = codegen_create_label(gen);
            
            /* Jump to else if condition is false (rax == 0) */
            size_t je_pos = gen->code.size + 2;  /* Position of the rel32 */
            emit_je_rel32(gen, 0);  /* Placeholder */
            codegen_patch_label(gen, else_label, je_pos);
            
            /* Compile if body */
            for (size_t i = 0; i < node->data.conditional.body.count; ++i) {
                if (codegen_statement(gen, node->data.conditional.body.items[i]) != 0)
                    return -1;
            }
            
            /* Jump to end */
            size_t jmp_pos = gen->code.size + 1;
            emit_jmp_rel32(gen, 0);  /* Placeholder */
            codegen_patch_label(gen, end_label, jmp_pos);
            
            /* Else label */
            codegen_set_label(gen, else_label);
            
            /* Compile else body if present */
            for (size_t i = 0; i < node->data.conditional.else_body.count; ++i) {
                if (codegen_statement(gen, node->data.conditional.else_body.items[i]) != 0)
                    return -1;
            }
            
            /* End label */
            codegen_set_label(gen, end_label);
            return 0;
        }

        case AST_WHILE: {
            int start_label = codegen_create_label(gen);
            int end_label = codegen_create_label(gen);
            
            /* Save outer loop context */
            int saved_start = gen->loop_start_label;
            int saved_end = gen->loop_end_label;
            
            /* Set up loop context for break/continue */
            gen->loop_start_label = start_label;  /* continue jumps back to condition */
            gen->loop_end_label = end_label;
            
            /* Start of loop */
            codegen_set_label(gen, start_label);
            
            /* Evaluate condition */
            if (codegen_expression(gen, node->data.conditional.condition) != 0)
                return -1;
            
            emit_cmp_rax_0(gen);
            
            /* Jump to end if condition is false */
            size_t je_pos = gen->code.size + 2;
            emit_je_rel32(gen, 0);
            codegen_patch_label(gen, end_label, je_pos);
            
            /* Compile loop body */
            for (size_t i = 0; i < node->data.conditional.body.count; ++i) {
                if (codegen_statement(gen, node->data.conditional.body.items[i]) != 0)
                    return -1;
            }
            
            /* Jump back to start */
            size_t jmp_pos = gen->code.size + 1;
            emit_jmp_rel32(gen, 0);
            /* Calculate relative offset to start */
            int32_t rel = (int32_t)(gen->labels[start_label].offset - (jmp_pos + 4));
            memcpy(gen->code.data + jmp_pos, &rel, 4);
            
            /* End of loop */
            codegen_set_label(gen, end_label);
            
            /* Restore outer loop context */
            gen->loop_start_label = saved_start;
            gen->loop_end_label = saved_end;
            
            return 0;
        }

        case AST_FOR: {
            /* Initialize loop variable */
            stack_frame_push_var(&gen->stack, node->data.for_loop.var_name, TYPE_INT);
            
            if (codegen_expression(gen, node->data.for_loop.start) != 0)
                return -1;
            
            StackVar *var = stack_frame_find(&gen->stack, node->data.for_loop.var_name);
            emit_mov_rbp_offset_rax(gen, var->stack_offset);
            
            int start_label = codegen_create_label(gen);
            int end_label = codegen_create_label(gen);
            int continue_label = codegen_create_label(gen);  /* Label for continue (before increment) */
            
            /* Save outer loop context */
            int saved_start = gen->loop_start_label;
            int saved_end = gen->loop_end_label;
            int saved_in_loop = gen->in_loop;
            
            /* Set up loop context for break/continue */
            gen->loop_start_label = continue_label;  /* continue jumps to increment section */
            gen->loop_end_label = end_label;
            gen->in_loop = 1;
            
            codegen_set_label(gen, start_label);
            
            /* Check condition: var < end */
            emit_mov_rax_rbp_offset(gen, var->stack_offset);
            emit_push_rax(gen);
            if (codegen_expression(gen, node->data.for_loop.end) != 0)
                return -1;
            emit_mov_rbx_rax(gen);
            emit_pop_rax(gen);
            emit_cmp_rax_rbx(gen);
            
            size_t jge_pos = gen->code.size + 2;
            buffer_write_byte(&gen->code, 0x0F);  /* jge rel32 */
            buffer_write_byte(&gen->code, 0x8D);
            buffer_write_u32(&gen->code, 0);
            codegen_patch_label(gen, end_label, jge_pos);
            
            /* Loop body */
            for (size_t i = 0; i < node->data.for_loop.body.count; ++i) {
                if (codegen_statement(gen, node->data.for_loop.body.items[i]) != 0)
                    return -1;
            }
            
            /* Continue label - continue jumps here to do the increment */
            codegen_set_label(gen, continue_label);
            
            /* Increment */
            emit_mov_rax_rbp_offset(gen, var->stack_offset);
            emit_rex_w(gen);
            buffer_write_byte(&gen->code, 0xFF);  /* inc rax */
            buffer_write_byte(&gen->code, 0xC0);
            emit_mov_rbp_offset_rax(gen, var->stack_offset);
            
            /* Jump to start */
            size_t jmp_pos = gen->code.size + 1;
            emit_jmp_rel32(gen, 0);
            int32_t rel = (int32_t)(gen->labels[start_label].offset - (jmp_pos + 4));
            memcpy(gen->code.data + jmp_pos, &rel, 4);
            
            codegen_set_label(gen, end_label);
            
            /* Restore outer loop context */
            gen->loop_start_label = saved_start;
            gen->loop_end_label = saved_end;
            gen->in_loop = saved_in_loop;
            
            return 0;
        }

        case AST_BLOCK: {
            for (size_t i = 0; i < node->data.block.statements.count; ++i) {
                if (codegen_statement(gen, node->data.block.statements.items[i]) != 0)
                    return -1;
            }
            return 0;
        }

        case AST_FUNC_CALL: {
            /* Expression statement - evaluate the function call for its side effects */
            if (codegen_expression(gen, node) != 0)
                return -1;
            return 0;
        }

        case AST_BINARY_OP:
        case AST_UNARY_OP:
        case AST_IDENTIFIER:
        case AST_NUMBER:
        case AST_STRING:
        case AST_ARRAY_ACCESS:
        case AST_DEREF: {
            /* Other expression statements - evaluate for side effects if any */
            if (codegen_expression(gen, node) != 0)
                return -1;
            return 0;
        }

        default:
            return 0;
    }
}

/* ========== Function Code Generation ========== */

static int codegen_function(CodeGenerator *gen, ASTNode *node)
{
    if (node->type != AST_FUNCTION_DEF) return -1;

    /* Record function position */
    size_t func_offset = gen->code.size;
    
    /* Check if this is the entry point (Eric = main) */
    if (strcasecmp(node->data.func_def.name, "Eric") == 0) {
        gen->entry_point = func_offset;
    }
    
    /* Add to function table */
    func_table_add(&gen->functions, node->data.func_def.name, func_offset,
                   &node->data.func_def.params, node->data.func_def.return_type);
    
    /* Set current function */
    free(gen->current_function);
    gen->current_function = strdup(node->data.func_def.name);
    
    /* Clear stack frame for new function */
    stack_frame_clear(&gen->stack);
    
    /* Function prologue */
    emit_push_rbp(gen);
    emit_mov_rbp_rsp(gen);
    
    /* Allocate stack space (will be patched later) */
    size_t stack_alloc_pos = gen->code.size;
    emit_sub_rsp_imm32(gen, 65536);  /* Reserve 64KB stack space initially */
    
    /* Load parameters from stack into local variables */
    for (size_t i = 0; i < node->data.func_def.params.count; ++i) {
        DataType param_type = node->data.func_def.params.items[i].type;
        const char *param_name = node->data.func_def.params.items[i].name;
        const char *struct_type_name = node->data.func_def.params.items[i].struct_type_name;
        
        /* Check if parameter is an array type - passed as pointer */
        int is_array_param = (param_type == TYPE_INT_ARRAY || param_type == TYPE_FLOAT_ARRAY ||
                              param_type == TYPE_STRING_ARRAY || param_type == TYPE_CHAR_ARRAY);
        
        /* Check if parameter is a struct pointer */
        int is_struct_ptr_param = (param_type == TYPE_STRUCT_PTR);
        
        stack_frame_push_var(&gen->stack, param_name, param_type);
        StackVar *var = stack_frame_find(&gen->stack, param_name);
        
        if (is_array_param) {
            /* For array parameters, mark as pointer array (passed by reference) */
            var->is_array = 1;
            var->is_pointer_array = 1;  /* This is a pointer to array data, not stack-allocated */
        }
        
        if (is_struct_ptr_param && struct_type_name) {
            /* For struct pointer parameters, store the struct type name */
            var->struct_name = strdup(struct_type_name);
        }
        
        /* Parameters are pushed in reverse order, so first param is at [rbp+16] */
        int param_offset = 16 + (int)(i * 8);
        emit_rex_w(gen);
        buffer_write_byte(&gen->code, 0x8B);  /* mov rax, [rbp+offset] */
        buffer_write_byte(&gen->code, 0x45);
        buffer_write_byte(&gen->code, (uint8_t)param_offset);
        
        emit_mov_rbp_offset_rax(gen, var->stack_offset);
    }
    
    /* Compile function body */
    for (size_t i = 0; i < node->data.func_def.body.count; ++i) {
        if (codegen_statement(gen, node->data.func_def.body.items[i]) != 0)
            return -1;
    }
    
    /* If no explicit return, add default */
    emit_mov_eax_imm32(gen, 0);
    
    if (strcasecmp(node->data.func_def.name, "Eric") == 0) {
        emit_sys_exit(gen);
    } else {
        emit_mov_rsp_rbp(gen);
        emit_pop_rbp(gen);
        emit_ret(gen);
    }
    
    /* Patch stack allocation size */
    int32_t actual_stack = (-gen->stack.current_offset + 15) & ~15;  /* Align to 16 */
    if (actual_stack < 64) actual_stack = 64;
    memcpy(gen->code.data + stack_alloc_pos + 3, &actual_stack, 4);
    
    return 0;
}

/* ========== Main Compilation ========== */

int codegen_compile(CodeGenerator *gen, ASTNode *program)
{
    if (!program || program->type != AST_PROGRAM) {
        gen->error_msg = strdup("Invalid program AST");
        return -1;
    }

    /* Store constants, enums, and structs in the generator for later lookup */
    gen->constants = &program->data.program.constants;
    gen->enums = &program->data.program.enums;
    gen->structs = &program->data.program.structs;
    
    /* Load struct definitions */
    for (size_t i = 0; i < program->data.program.structs.count; ++i) {
        ASTNode *struct_node = program->data.program.structs.items[i];
        if (struct_node->type == AST_STRUCT_DEF) {
            struct_def_table_add(&gen->struct_defs, 
                               struct_node->data.struct_def.name,
                               &struct_node->data.struct_def.fields);
        }
    }

    /* First pass: register all functions */
    for (size_t i = 0; i < program->data.program.functions.count; ++i) {
        ASTNode *func = program->data.program.functions.items[i];
        if (func->type == AST_FUNCTION_DEF) {
            /* Just add placeholder, will be updated during compilation */
        }
    }

    /* Second pass: compile all functions */
    for (size_t i = 0; i < program->data.program.functions.count; ++i) {
        ASTNode *func = program->data.program.functions.items[i];
        if (func->type == AST_FUNCTION_DEF) {
            if (codegen_function(gen, func) != 0) {
                return -1;
            }
        }
    }

    /* Resolve all label patches */
    codegen_resolve_patches(gen);

    return 0;
}

/* ========== ELF File Writing ========== */

int codegen_write_elf(CodeGenerator *gen, const char *filename)
{
    FILE *f = fopen(filename, "wb");
    if (!f) {
        gen->error_msg = strdup("Failed to open output file");
        return -1;
    }

    /* 
     * Simple ELF layout:
     * - Everything in one PT_LOAD segment starting at offset 0
     * - ELF header + program headers + code + data all together
     */
    
    size_t ehdr_size = sizeof(Elf64_Ehdr);
    size_t phdr_size = sizeof(Elf64_Phdr);
    size_t num_phdrs = 1;  /* Single segment for simplicity */
    
    size_t headers_size = ehdr_size + (phdr_size * num_phdrs);
    
    /* Code starts right after headers */
    size_t code_offset = headers_size;
    size_t code_size = gen->code.size;
    
    /* Data starts right after code, aligned to 8 bytes */
    size_t data_offset = code_offset + code_size;
    data_offset = (data_offset + 7) & ~7;
    
    /* Build data section from string table */
    buffer_init(&gen->data);
    for (size_t i = 0; i < gen->strings.count; ++i) {
        buffer_write(&gen->data, gen->strings.items[i].str, 
                    strlen(gen->strings.items[i].str) + 1);
    }
    size_t data_size = gen->data.size;
    if (data_size == 0) data_size = 1;  /* At least 1 byte */
    
    size_t total_size = data_offset + data_size;

    /* Virtual address - load everything at BASE_ADDR */
    uint64_t load_vaddr = BASE_ADDR;
    uint64_t code_vaddr = load_vaddr + code_offset;
    uint64_t data_vaddr = load_vaddr + data_offset;
    uint64_t entry_vaddr = code_vaddr + gen->entry_point;

    /* Patch string references using the relocation table */
    for (size_t i = 0; i < gen->string_relocs.count; ++i) {
        size_t code_off = gen->string_relocs.items[i].code_offset;
        size_t str_off = gen->string_relocs.items[i].string_offset;
        uint64_t new_addr = data_vaddr + str_off;
        memcpy(&gen->code.data[code_off], &new_addr, 8);
    }
    
    /* ELF Header */
    Elf64_Ehdr ehdr;
    memset(&ehdr, 0, sizeof(ehdr));
    ehdr.e_ident[EI_MAG0] = ELFMAG0;
    ehdr.e_ident[EI_MAG1] = ELFMAG1;
    ehdr.e_ident[EI_MAG2] = ELFMAG2;
    ehdr.e_ident[EI_MAG3] = ELFMAG3;
    ehdr.e_ident[EI_CLASS] = ELFCLASS64;
    ehdr.e_ident[EI_DATA] = ELFDATA2LSB;
    ehdr.e_ident[EI_VERSION] = EV_CURRENT;
    ehdr.e_ident[EI_OSABI] = ELFOSABI_NONE;
    ehdr.e_type = ET_EXEC;
    ehdr.e_machine = EM_X86_64;
    ehdr.e_version = EV_CURRENT;
    ehdr.e_entry = entry_vaddr;
    ehdr.e_phoff = sizeof(Elf64_Ehdr);
    ehdr.e_shoff = 0;
    ehdr.e_flags = 0;
    ehdr.e_ehsize = sizeof(Elf64_Ehdr);
    ehdr.e_phentsize = sizeof(Elf64_Phdr);
    ehdr.e_phnum = num_phdrs;
    ehdr.e_shentsize = 0;
    ehdr.e_shnum = 0;
    ehdr.e_shstrndx = 0;

    /* Single program header - load everything RWX */
    Elf64_Phdr phdr;
    memset(&phdr, 0, sizeof(phdr));
    phdr.p_type = PT_LOAD;
    phdr.p_flags = PF_R | PF_W | PF_X;
    phdr.p_offset = 0;
    phdr.p_vaddr = load_vaddr;
    phdr.p_paddr = load_vaddr;
    phdr.p_filesz = total_size;
    phdr.p_memsz = total_size;
    phdr.p_align = 0x1000;

    /* Write ELF header */
    fwrite(&ehdr, 1, sizeof(ehdr), f);
    
    /* Write program header */
    fwrite(&phdr, 1, sizeof(phdr), f);

    /* Write code */
    fwrite(gen->code.data, 1, gen->code.size, f);

    /* Pad to data offset */
    size_t current_pos = code_offset + gen->code.size;
    while (current_pos < data_offset) {
        fputc(0, f);
        current_pos++;
    }

    /* Write data */
    fwrite(gen->data.data, 1, gen->data.size, f);

    fclose(f);

    /* Make executable */
    chmod(filename, 0755);

    return 0;
}
