/**==============================================
 *                 code_generator.c
 *  x86-64 code generator implementation
 *  Author: shirosaaki
 *  Date: 2025-11-27
 *=============================================**/

#include "../includes/code_generator.h"
#include <elf.h>
#include <sys/stat.h>

/* Base address for the executable */
#define BASE_ADDR 0x400000
#define PAGE_SIZE 0x1000

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
    }
    free(sf->items);
    sf->items = NULL;
    sf->count = 0;
    sf->capacity = 0;
    sf->current_offset = 0;
}

int stack_frame_push_var(StackFrame *sf, const char *name, DataType type)
{
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
    sf->items[sf->count].string_data_offset = 0;
    sf->items[sf->count].string_length = 0;
    sf->items[sf->count].is_array = 0;
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
    sf->items[sf->count].string_data_offset = 0;
    sf->items[sf->count].string_length = 0;
    sf->items[sf->count].is_array = 1;
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
            FuncParam p = {strdup(params->items[i].name), params->items[i].type};
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
    
    gen->labels = NULL;
    gen->label_count = 0;
    gen->label_capacity = 0;
    
    gen->patches.items = NULL;
    gen->patches.count = 0;
    gen->patches.capacity = 0;
    
    gen->current_function = NULL;
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
static void emit_jne_rel32(CodeGenerator *gen, int32_t rel)
{
    buffer_write_byte(&gen->code, 0x0F);
    buffer_write_byte(&gen->code, 0x85);
    buffer_write_u32(&gen->code, (uint32_t)rel);
}

/* jl rel32 - jump if less (signed) */
static void emit_jl_rel32(CodeGenerator *gen, int32_t rel)
{
    buffer_write_byte(&gen->code, 0x0F);
    buffer_write_byte(&gen->code, 0x8C);
    buffer_write_u32(&gen->code, (uint32_t)rel);
}

/* jle rel32 - jump if less or equal (signed) */
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

/* ========== Emit sys_write (for print) ========== */

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
            StackVar *var = stack_frame_find(&gen->stack, node->data.identifier.name);
            if (!var) {
                gen->error_msg = strdup("Undefined variable");
                gen->error_line = node->line;
                return -1;
            }
            emit_mov_rax_rbp_offset(gen, var->stack_offset);
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
                /* Save rbx (divisor), move to correct position */
                emit_mov_rbx_rax(gen);  /* rbx = left */
                emit_pop_rax(gen);      /* We need to re-push... */
                emit_push_rax(gen);
                emit_mov_rax_rbp_offset(gen, -8);  /* Load left again */
                /* Actually, let's redo this properly */
                /* rax = left, rbx = right (from stack) */
                emit_xor_rdx_rdx(gen);  /* Clear rdx for division */
                emit_idiv_rbx(gen);     /* rax = rax / rbx */
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
            
            /* Evaluate index expression into rax */
            if (codegen_expression(gen, node->data.array_access.index) != 0) return -1;
            
            /* Calculate offset: index * 8 */
            emit_mov_rbx_rax(gen);  /* rbx = index */
            emit_imul_rbx_8(gen);   /* rbx = index * 8 */
            
            /* Load address of array base: rbp + stack_offset */
            emit_lea_rax_rbp_offset(gen, arr->stack_offset);
            
            /* Add index offset to get actual element address */
            emit_add_rax_rbx(gen);
            
            /* Load value at that address */
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

    switch (node->type) {
        case AST_VAR_DECL: {
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

        case AST_ARRAY_ASSIGN: {
            /* 
             * Auto-fill array assignment:
             * If index > current_size and current_size > 0:
             *   Fill arr[current_size..index-1] with last_value
             * Then set arr[index] = value
             * Update current_size = index + 1, last_value = value
             *
             * We use callee-saved registers to simplify:
             * - Store value, index, last_value on stack
             * - Use rcx as loop counter
             */
            StackVar *arr = stack_frame_find(&gen->stack, node->data.array_assign.array_name);
            if (!arr || !arr->is_array) {
                gen->error_msg = strdup("Undefined array");
                gen->error_line = node->line;
                return -1;
            }
            
            /* Evaluate value expression */
            if (codegen_expression(gen, node->data.array_assign.value) != 0) return -1;
            /* Store value temporarily at a known stack location */
            emit_push_rax(gen);  /* Stack: [value] */
            
            /* Evaluate index expression */
            if (codegen_expression(gen, node->data.array_assign.index) != 0) return -1;
            emit_push_rax(gen);  /* Stack: [value, index] */
            
            /* === Auto-fill check === */
            /* Load current_size */
            emit_mov_rax_rbp_offset(gen, arr->array_size_offset);
            emit_push_rax(gen);  /* Stack: [value, index, current_size] */
            
            /* Load index for comparison */
            emit_mov_rax_rbp_offset(gen, gen->stack.current_offset + 8);  /* Get index from stack */
            /* Actually, let's use cleaner approach - reload from stack positions */
            
            /* Stack layout: RSP -> [current_size, index, value] */
            /* Pop all and redo with known positions */
            emit_pop_rcx(gen);  /* rcx = current_size */
            emit_pop_rbx(gen);  /* rbx = index */
            emit_pop_rax(gen);  /* rax = value */
            
            /* Save them to known stack positions */
            emit_push_rax(gen);  /* value at [rsp] */
            emit_push_rbx(gen);  /* index at [rsp+8] - wait, push decrements */
            emit_push_rcx(gen);  /* current_size at [rsp+16] */
            /* Stack: RSP -> [current_size, index, value] */
            
            /* Check: if current_size >= index OR current_size == 0, skip fill */
            emit_cmp_rcx_rbx(gen);  /* current_size vs index */
            int skip_fill = codegen_create_label(gen);
            size_t jge_pos = gen->code.size + 2;
            emit_jge_rel32(gen, 0);
            codegen_patch_label(gen, skip_fill, jge_pos);
            
            /* Check current_size == 0 */
            emit_mov_rax_rcx(gen);
            emit_cmp_rax_0(gen);
            size_t je_pos = gen->code.size + 2;
            emit_je_rel32(gen, 0);
            codegen_patch_label(gen, skip_fill, je_pos);
            
            /* === Auto-fill loop === */
            /* rcx = current_size (loop counter, already set) */
            /* rbx = index (target, already set) */
            /* Load last_value and store on stack */
            emit_mov_rax_rbp_offset(gen, arr->array_last_val_offset);
            emit_push_rax(gen);  /* Stack: [last_val, current_size, index, value] */
            
            /* Also save target index (rbx) on stack since we'll clobber it */
            emit_push_rbx(gen);  /* Stack: [target_idx, last_val, current_size, index, value] */
            
            int loop_start = codegen_create_label(gen);
            codegen_set_label(gen, loop_start);
            
            /* Restore target index for comparison */
            emit_pop_rbx(gen);  /* rbx = target index */
            emit_push_rbx(gen);  /* Put it back */
            
            /* Check rcx < rbx (loop_counter < target_index) */
            emit_cmp_rcx_rbx(gen);
            int loop_end = codegen_create_label(gen);
            size_t jge_loop = gen->code.size + 2;
            emit_jge_rel32(gen, 0);
            codegen_patch_label(gen, loop_end, jge_loop);
            
            /* Store last_value at arr[rcx] */
            /* Calculate address: base + rcx * 8 */
            emit_push_rcx(gen);  /* Save loop counter */
            
            emit_mov_rax_rcx(gen);  /* rax = loop counter */
            emit_mov_rbx_rax(gen);  /* rbx = loop counter */
            emit_imul_rbx_8(gen);   /* rbx = loop counter * 8 */
            emit_lea_rax_rbp_offset(gen, arr->stack_offset);
            emit_add_rax_rbx(gen);  /* rax = &arr[loop_counter] */
            
            /* Get last_value from stack: Stack is [rcx, target_idx, last_val, ...] */
            /* last_val is at [rsp + 16] */
            emit_push_rax(gen);  /* Save address, Stack: [addr, rcx, target_idx, last_val, ...] */
            emit_mov_rax_rbp_offset(gen, arr->array_last_val_offset);  /* Re-load last_val from memory */
            emit_mov_rbx_rax(gen);  /* rbx = last_val */
            emit_pop_rax(gen);  /* rax = address */
            
            /* Store last_val at address */
            emit_mov_ptr_rax_rbx(gen);
            
            /* Restore and increment loop counter */
            emit_pop_rcx(gen);  /* rcx = loop counter */
            emit_inc_rcx(gen);
            
            /* Jump back */
            size_t jmp_pos = gen->code.size + 1;
            emit_jmp_rel32(gen, 0);
            int32_t rel = (int32_t)(gen->labels[loop_start].offset - (jmp_pos + 4));
            memcpy(gen->code.data + jmp_pos, &rel, 4);
            
            codegen_set_label(gen, loop_end);
            
            /* Clean up: pop target_idx and last_val from stack */
            emit_pop_rax(gen);  /* Discard target_idx */
            emit_pop_rax(gen);  /* Discard last_val, Stack: [current_size, index, value] */
            
            codegen_set_label(gen, skip_fill);
            
            /* === Actual assignment === */
            /* Stack: [current_size, index, value] */
            emit_pop_rcx(gen);  /* rcx = current_size (discard) */
            emit_pop_rbx(gen);  /* rbx = index */
            emit_pop_rax(gen);  /* rax = value */
            
            /* Save value for later */
            emit_push_rax(gen);
            emit_push_rbx(gen);  /* Stack: [index, value] */
            
            /* Calculate address: base + index * 8 */
            emit_imul_rbx_8(gen);
            emit_push_rax(gen);  /* Save value */
            emit_lea_rax_rbp_offset(gen, arr->stack_offset);
            emit_add_rax_rbx(gen);  /* rax = &arr[index] */
            emit_pop_rbx(gen);  /* rbx = value */
            
            /* Store value */
            emit_mov_ptr_rax_rbx(gen);
            
            /* Update size if needed: size = max(size, index + 1) */
            emit_pop_rbx(gen);  /* rbx = index */
            emit_pop_rax(gen);  /* rax = value */
            emit_push_rax(gen);  /* Keep value for last_val update */
            
            /* rbx = index, calculate index + 1 */
            emit_mov_rax_rbx(gen);
            emit_push_rax(gen);  /* Save index */
            emit_mov_rcx_rax(gen);
            emit_inc_rcx(gen);  /* rcx = index + 1 */
            
            /* Load current size */
            emit_mov_rax_rbp_offset(gen, arr->array_size_offset);
            
            /* If current_size >= index + 1, skip update */
            emit_cmp_rax_rcx(gen);
            int skip_size = codegen_create_label(gen);
            size_t jge_size = gen->code.size + 2;
            emit_jge_rel32(gen, 0);
            codegen_patch_label(gen, skip_size, jge_size);
            
            /* Update size */
            emit_mov_rax_rcx(gen);
            emit_mov_rbp_offset_rax(gen, arr->array_size_offset);
            
            codegen_set_label(gen, skip_size);
            
            /* Update last_val */
            emit_pop_rax(gen);  /* Discard saved index */
            emit_pop_rax(gen);  /* rax = value */
            emit_mov_rbp_offset_rax(gen, arr->array_last_val_offset);
            
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

        case AST_PRINT: {
            /* For print, we need to handle format strings with {var} interpolation */
            ASTNode *val = node->data.print_stmt.value;
            
            if (val && val->type == AST_STRING) {
                const char *fmt = val->data.string.value;
                size_t fmt_len = strlen(fmt);
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
                    
                    /* Found '{', look for '}' */
                    if (fmt[i] == '{') {
                        i++;  /* Skip '{' */
                        size_t var_start = i;
                        while (i < fmt_len && fmt[i] != '}') i++;
                        
                        if (i < fmt_len && fmt[i] == '}') {
                            /* Extract expression */
                            size_t expr_len = i - var_start;
                            char *expr = malloc(expr_len + 1);
                            memcpy(expr, fmt + var_start, expr_len);
                            expr[expr_len] = '\0';
                            
                            /* Check if it's an array access: name[index] */
                            char *bracket = strchr(expr, '[');
                            if (bracket) {
                                /* Parse array access */
                                size_t name_len = bracket - expr;
                                char *arr_name = malloc(name_len + 1);
                                memcpy(arr_name, expr, name_len);
                                arr_name[name_len] = '\0';
                                
                                char *idx_start = bracket + 1;
                                char *idx_end = strchr(idx_start, ']');
                                if (idx_end) {
                                    size_t idx_len = idx_end - idx_start;
                                    char *idx_expr = malloc(idx_len + 1);
                                    memcpy(idx_expr, idx_start, idx_len);
                                    idx_expr[idx_len] = '\0';
                                    
                                    StackVar *arr = stack_frame_find(&gen->stack, arr_name);
                                    StackVar *idx_var = stack_frame_find(&gen->stack, idx_expr);
                                    
                                    if (arr && arr->is_array) {
                                        /* Load index value */
                                        if (idx_var) {
                                            emit_mov_rax_rbp_offset(gen, idx_var->stack_offset);
                                        } else {
                                            /* Try parsing as number */
                                            long idx_val = atol(idx_expr);
                                            emit_mov_rax_imm64(gen, (uint64_t)idx_val);
                                        }
                                        emit_mov_rbx_rax(gen);  /* rbx = index */
                                        emit_imul_rbx_8(gen);   /* rbx = index * 8 */
                                        
                                        /* Load array element */
                                        emit_lea_rax_rbp_offset(gen, arr->stack_offset);
                                        emit_add_rax_rbx(gen);
                                        emit_mov_rax_ptr_rax(gen);
                                        
                                        /* Print as int */
                                        emit_print_int(gen);
                                    } else {
                                        /* Array not found */
                                        size_t err_offset = string_table_add(&gen->strings, "<undefined>");
                                        emit_mov_eax_imm32(gen, 1);
                                        emit_mov_edi_imm32(gen, 1);
                                        emit_mov_rsi_string_offset(gen, err_offset);
                                        emit_mov_rdx_imm64(gen, 11);
                                        emit_syscall(gen);
                                    }
                                    free(idx_expr);
                                }
                                free(arr_name);
                            } else {
                                /* Simple variable */
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
                                    /* Variable not found, print error marker */
                                    size_t err_offset = string_table_add(&gen->strings, "<undefined>");
                                    emit_mov_eax_imm32(gen, 1);
                                    emit_mov_edi_imm32(gen, 1);
                                    emit_mov_rsi_string_offset(gen, err_offset);
                                    emit_mov_rdx_imm64(gen, 11);
                                    emit_syscall(gen);
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
            size_t je_pos = gen->code.size + 2;  /* Position of rel32 */
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
            return 0;
        }

        case AST_BLOCK: {
            for (size_t i = 0; i < node->data.block.statements.count; ++i) {
                if (codegen_statement(gen, node->data.block.statements.items[i]) != 0)
                    return -1;
            }
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
    emit_sub_rsp_imm32(gen, 64);  /* Reserve some space initially */
    
    /* Load parameters from stack into local variables */
    for (size_t i = 0; i < node->data.func_def.params.count; ++i) {
        stack_frame_push_var(&gen->stack, node->data.func_def.params.items[i].name,
                            node->data.func_def.params.items[i].type);
        /* Parameters are pushed in reverse order, so first param is at [rbp+16] */
        int param_offset = 16 + (int)(i * 8);
        emit_rex_w(gen);
        buffer_write_byte(&gen->code, 0x8B);  /* mov rax, [rbp+offset] */
        buffer_write_byte(&gen->code, 0x45);
        buffer_write_byte(&gen->code, (uint8_t)param_offset);
        
        StackVar *var = stack_frame_find(&gen->stack, node->data.func_def.params.items[i].name);
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
