/**==============================================
 *                 lexer.c
 *  lexer
 *  Author: shirosaaki
 *  Date: 2025-11-21
 *=============================================**/
#include "../includes/lexer.h"

static const char *keywords[] = {
    "deschodt","desnote","destruct","cz","desnum",
    "erif","deschelse","aer","darius","deschontinue","deschreak",
    "peric","eric","Deschodt","Desnote","Destruct","Cz","Desnum",
    NULL
};

static int is_keyword(const char *s)
{
    for (const char **k = keywords; *k; ++k) {
        if (strcmp(*k, s) == 0) return 1;
    }
    return 0;
}

int lexer_tokenize_file(const char *filename, TokenList *out_tokens, LexError *out_err)
{
    token_list_init(out_tokens);
    FILE *f = fopen(filename, "rb");
    if (!f) {
        if (out_err) *out_err = lex_error_create("Failed to open file", 0, 0);
        return -1;
    }

    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *src = malloc(fsize + 1);
    if (!src) {
        fclose(f);
        if (out_err) *out_err = lex_error_create("Out of memory", 0, 0);
        return -1;
    }
    fread(src, 1, fsize, f);
    src[fsize] = '\0';
    fclose(f);

    size_t i = 0;
    size_t line = 1, col = 1;
    int at_line_start = 1;

    size_t indent_stack[256];
    int indent_top = 0;
    indent_stack[0] = 0;

    char delim_stack[256];
    int delim_top = 0;
    char block_stack[256];
    int block_top = 0;
    int pending_if = 0;
    int pending_else = 0;
    int last_closed_if = 0;

    while (i <= (size_t)fsize) {
        char c = src[i];
        if (c == '\0') {
            break;
        }
        if (at_line_start) {
            size_t start_i = i;
            size_t spaces = 0;
            while (src[i] == ' ' || src[i] == '\t') {
                if (src[i] == '\t') spaces += 4; else spaces += 1;
                ++i; ++col;
            }
            at_line_start = 0;
            if (src[i] == '\n' || src[i] == '#') {
                i = start_i; col = 1;
            } else {
                if (spaces > indent_stack[indent_top]) {
                    indent_stack[++indent_top] = spaces;
                    Token t = token_create(TOK_INDENT, strdup(""), line, col);
                    token_list_push(out_tokens, t);
                    if (pending_if) {
                        if (block_top < (int)sizeof(block_stack)) block_stack[block_top++] = 'I';
                        pending_if = 0;
                        last_closed_if = 0;
                    } else if (pending_else) {
                        if (block_top < (int)sizeof(block_stack)) block_stack[block_top++] = 'E';
                        pending_else = 0;
                        last_closed_if = 0;
                    }
                } else {
                    while (spaces < indent_stack[indent_top]) {
                        Token t = token_create(TOK_DEDENT, strdup(""), line, col);
                        token_list_push(out_tokens, t);
                        if (block_top > 0) {
                            char popped = block_stack[--block_top];
                            if (popped == 'I') last_closed_if = 1; else last_closed_if = 0;
                        } else last_closed_if = 0;
                        if (indent_top > 0) --indent_top; else break;
                    }
                    if (spaces != indent_stack[indent_top]) {
                        free(src);
                        if (out_err) *out_err = lex_error_create("Indentation error", line, col);
                        return -1;
                    }
                }
            }
        }

        c = src[i];
        if (c == '\n') {
                Token t = token_create(TOK_NEWLINE, strdup("\n"), line, col);
            token_list_push(out_tokens, t);
            ++i; ++line; col = 1; at_line_start = 1;
            continue;
        }

        if (isspace((unsigned char)c)) {
            ++i; ++col; continue;
        }

        if (isalpha((unsigned char)c) || c == '_') {
            size_t start = i; size_t startcol = col;
            while (isalnum((unsigned char)src[i]) || src[i] == '_' ) { ++i; ++col; }
            size_t len = i - start;
            char *lex = malloc(len + 1);
            memcpy(lex, src + start, len); lex[len] = '\0';
            if (is_keyword(lex)) {
                    size_t look = i; while (src[look] == ' ' || src[look] == '\t') { ++look; }
                    char nextc = src[look];

                    if (strcasecmp(lex, "peric") == 0) {
                        if (nextc != '(') {
                            free(lex); free(src);
                            if (out_err) *out_err = lex_error_create("Keyword 'peric' must be followed by '(' and a string literal", line, startcol);
                            return -1;
                        }
                    } else if (strcasecmp(lex, "deschelse") == 0) {
                        if (nextc != ':') {
                            free(lex); free(src);
                            if (out_err) *out_err = lex_error_create("Keyword 'deschelse' must be followed by ':'", line, startcol);
                            return -1;
                        }
                        if (!last_closed_if) {
                            free(lex); free(src);
                            if (out_err) *out_err = lex_error_create("'deschelse' without matching 'erif'/'darius'", line, startcol);
                            return -1;
                        }
                        pending_else = 1;
                        last_closed_if = 0;
                    } else if (strcasecmp(lex, "eric") == 0) {
                        size_t scan = i;
                        while (src[scan] == ' ' || src[scan] == '\t') ++scan;
                        if (!isalpha((unsigned char)src[scan]) && src[scan] != '_') {
                            free(lex); free(src);
                            if (out_err) *out_err = lex_error_create("Keyword 'eric' must be followed by a variable name", line, startcol);
                            return -1;
                        }
                        while (isalnum((unsigned char)src[scan]) || src[scan] == '_') ++scan;
                        while (src[scan] == ' ' || src[scan] == '\t') ++scan;
                        if (src[scan] == '=') {
                            ++scan; while (src[scan] == ' ' || src[scan] == '\t') ++scan;
                            if (src[scan] == '\n' || src[scan] == '\0') {
                                free(lex); free(src);
                                if (out_err) *out_err = lex_error_create("'eric' assignment requires a value before '-> <type>'", line, startcol);
                                return -1;
                            }
                            while (src[scan] && src[scan] != '\n' && !(src[scan] == '-' && src[scan+1] == '>')) ++scan;
                        }
                        size_t arrow = scan;
                        int found_arrow = 0;
                        while (src[arrow] && src[arrow] != '\n') {
                            if (src[arrow] == '-' && src[arrow+1] == '>') { found_arrow = 1; break; }
                            ++arrow;
                        }
                        if (!found_arrow) {
                            free(lex); free(src);
                            if (out_err) *out_err = lex_error_create("Variable declaration must specify type with '-> <type>'", line, startcol);
                            return -1;
                        }
                        arrow += 2; while (src[arrow] == ' ' || src[arrow] == '\t') ++arrow;
                        if (!isalpha((unsigned char)src[arrow]) && src[arrow] != '_') {
                            free(lex); free(src);
                            if (out_err) *out_err = lex_error_create("Missing variable type after '->'", line, startcol);
                            return -1;
                        }
                    } else if (strcmp(lex, "Deschodt") == 0) {
                        size_t scan = i;
                        while (src[scan] == ' ' || src[scan] == '\t') ++scan;
                        if (!isalpha((unsigned char)src[scan]) && src[scan] != '_') {
                            free(lex); free(src);
                            if (out_err) *out_err = lex_error_create("Keyword 'Deschodt' must be followed by a function name", line, startcol);
                            return -1;
                        }
                        while (isalnum((unsigned char)src[scan]) || src[scan] == '_') ++scan;
                        while (src[scan] == ' ' || src[scan] == '\t') ++scan;
                        if (src[scan] != '(') {
                            free(lex); free(src);
                            if (out_err) *out_err = lex_error_create("Function declaration must contain parameter list '()'", line, startcol);
                            return -1;
                        }
                        size_t par = scan + 1; int found_close = 0;
                        while (src[par] && src[par] != '\n') {
                            if (src[par] == ')') { found_close = 1; break; }
                            ++par;
                        }
                        if (!found_close) {
                            free(lex); free(src);
                            if (out_err) *out_err = lex_error_create("Unclosed parameter list in function declaration", line, startcol);
                            return -1;
                        }
                        par++; while (src[par] == ' ' || src[par] == '\t') ++par;
                        if (!(src[par] == '-' && src[par+1] == '>')) {
                            free(lex); free(src);
                            if (out_err) *out_err = lex_error_create("Function declaration must specify return type with '-> <type>'", line, startcol);
                            return -1;
                        }
                        par += 2; while (src[par] == ' ' || src[par] == '\t') ++par;
                        if (!isalpha((unsigned char)src[par]) && src[par] != '_') {
                            free(lex); free(src);
                            if (out_err) *out_err = lex_error_create("Missing return type after '->'", line, startcol);
                            return -1;
                        }
                    } else if (strcasecmp(lex, "aer") == 0) {
                        size_t scan = i;
                        while (src[scan] == ' ' || src[scan] == '\t') ++scan;
                        if (!isalpha((unsigned char)src[scan]) && src[scan] != '_') {
                            free(lex); free(src);
                            if (out_err) *out_err = lex_error_create("Keyword 'aer' must be followed by a loop variable name", line, startcol);
                            return -1;
                        }
                        while (isalnum((unsigned char)src[scan]) || src[scan] == '_') ++scan;
                        while (src[scan] == ' ' || src[scan] == '\t') ++scan;
                        if (!(src[scan] == 'i' && src[scan+1] == 'n')) {
                            free(lex); free(src);
                            if (out_err) *out_err = lex_error_create("Keyword 'aer' must use 'in' (e.g. 'aer i in range(...)')", line, startcol);
                            return -1;
                        }
                        scan += 2; while (src[scan] == ' ' || src[scan] == '\t') ++scan;
                        if (strncmp(src + scan, "range", 5) != 0) {
                            free(lex); free(src);
                            if (out_err) *out_err = lex_error_create("Expected 'range(...)' after 'in' in 'aer' loop", line, startcol);
                            return -1;
                        }
                        scan += 5; while (src[scan] == ' ' || src[scan] == '\t') ++scan;
                        if (src[scan] != '(') {
                            free(lex); free(src);
                            if (out_err) *out_err = lex_error_create("'range' must be followed by parameters in parentheses", line, startcol);
                            return -1;
                        }
                        size_t p = scan + 1; int found_close = 0; int commas = 0; int nonspace = 0;
                        while (src[p] && src[p] != '\n') {
                            if (src[p] == ',') ++commas;
                            if (!isspace((unsigned char)src[p])) nonspace = 1;
                            if (src[p] == ')') { found_close = 1; break; }
                            ++p;
                        }
                        if (!found_close) {
                            free(lex); free(src);
                            if (out_err) *out_err = lex_error_create("Unclosed 'range(...)' in 'aer' loop", line, startcol);
                            return -1;
                        }
                        if (!nonspace || commas < 1) {
                            free(lex); free(src);
                            if (out_err) *out_err = lex_error_create("'range' must contain at least start and end arguments", line, startcol);
                            return -1;
                        }
                        p++; while (src[p] == ' ' || src[p] == '\t') ++p;
                        if (src[p] != ':') {
                            free(lex); free(src);
                            if (out_err) *out_err = lex_error_create("'aer' loop must end with ':' after range(...)", line, startcol);
                            return -1;
                        }
                    } else if (strcasecmp(lex, "darius") == 0 || strcasecmp(lex, "erif") == 0) {
                        if (nextc != '(') {
                            free(lex); free(src);
                            if (out_err) *out_err = lex_error_create("Keyword 'darius'/'erif' must be followed by '(' and a condition", line, startcol);
                            return -1;
                        }
                        size_t s = look + 1;
                        int has_content = 0;
                        while (src[s] && src[s] != '\n') {
                            if (!isspace((unsigned char)src[s])) {
                                if (src[s] == ')') break;
                                has_content = 1;
                            }
                            if (src[s] == ')') break;
                            ++s;
                        }
                        if (!has_content) {
                            free(lex); free(src);
                            if (out_err) *out_err = lex_error_create("Empty condition in parentheses for 'darius'/'erif'", line, startcol);
                            return -1;
                        }
                        size_t close = look + 1; int have_close = 0;
                        while (src[close] && src[close] != '\n') { if (src[close] == ')') { have_close = 1; break; } ++close; }
                        if (!have_close) {
                            free(lex); free(src);
                            if (out_err) *out_err = lex_error_create("Unclosed condition parentheses for 'darius'/'erif'", line, startcol);
                            return -1;
                        }
                        close++; while (src[close] == ' ' || src[close] == '\t') ++close;
                        if (src[close] != ':') {
                            free(lex); free(src);
                            if (out_err) *out_err = lex_error_create("'darius'/'erif' condition must be followed by ':'", line, startcol);
                            return -1;
                        }
                    }
                    if (strcasecmp(lex, "darius") == 0 || strcasecmp(lex, "erif") == 0) {
                        pending_if = 1;
                    }

                    else if (strcmp(lex, "deschodt") == 0) {
                        size_t look2 = i;
                        while (src[look2] == ' ' || src[look2] == '\t') ++look2;
                        if (src[look2] == '\n' || src[look2] == '\0') {
                            free(lex); free(src);
                            if (out_err) *out_err = lex_error_create("'deschodt' must be followed by an expression", line, startcol);
                            return -1;
                        }
                    }

                    Token t = token_create(TOK_KEYWORD, lex, line, startcol);
                    token_list_push(out_tokens, t);
                    if (strcmp(lex, "desnote") == 0 || strcmp(lex, "Desnote") == 0) {
                        size_t j = i;
                        while (src[j] && src[j] != '\n') ++j;
                        col += (j - i);
                        i = j;
                        continue;
                    }
            } else {
                if (len >= 3 && (strncmp(lex, "des", 3) == 0 || strncmp(lex, "Des", 3) == 0)) {
                    char msgbuf[128];
                    snprintf(msgbuf, sizeof(msgbuf), "Unknown keyword-like identifier '%s'", lex);
                    free(lex); free(src);
                    if (out_err) *out_err = lex_error_create(msgbuf, line, startcol);
                    return -1;
                }
                Token t = token_create(TOK_IDENTIFIER, lex, line, startcol);
                token_list_push(out_tokens, t);
            }
            continue;
        }

        if (isdigit((unsigned char)c)) {
            size_t start = i; size_t startcol = col;
            while (isdigit((unsigned char)src[i])) { ++i; ++col; }
            if (src[i] == '.') {
                ++i; ++col;
                while (isdigit((unsigned char)src[i])) { ++i; ++col; }
            }
            size_t len = i - start;
            char *lex = malloc(len + 1);
            memcpy(lex, src + start, len); lex[len] = '\0';
            Token t = token_create(TOK_NUMBER, lex, line, startcol);
            token_list_push(out_tokens, t);
            continue;
        }

        /* Character literal: 'x' */
        if (c == '\'') {
            size_t startcol = col;
            ++i; ++col;
            char char_val = src[i];
            if (src[i] == '\\' && src[i+1]) {
                ++i; ++col;
                char esc = src[i];
                if (esc == 'n') char_val = '\n';
                else if (esc == 't') char_val = '\t';
                else if (esc == '\\') char_val = '\\';
                else if (esc == '\'') char_val = '\'';
                else char_val = esc;
            }
            ++i; ++col;
            if (src[i] != '\'') {
                free(src);
                if (out_err) *out_err = lex_error_create("Unterminated character literal", line, col);
                return -1;
            }
            ++i; ++col;
            /* Store as a number (ASCII value) */
            char lex[16];
            snprintf(lex, sizeof(lex), "%d", (unsigned char)char_val);
            Token t = token_create(TOK_NUMBER, strdup(lex), line, startcol);
            token_list_push(out_tokens, t);
            continue;
        }

        if (c == '"') {
            size_t startcol = col;
            ++i; ++col; size_t start = i;
            char *buf = malloc(1);
            size_t blen = 0;
            while (src[i] && src[i] != '"') {
                if (src[i] == '\\' && src[i+1]) {
                    ++i; ++col;
                    char esc = src[i];
                    char outc = esc;
                    if (esc == 'n') outc = '\n';
                    else if (esc == 't') outc = '\t';
                    buf = realloc(buf, blen + 2);
                    buf[blen++] = outc; buf[blen] = '\0';
                    ++i; ++col;
                    continue;
                }
                buf = realloc(buf, blen + 2);
                buf[blen++] = src[i]; buf[blen] = '\0';
                ++i; ++col;
            }
            if (src[i] != '"') {
                free(buf); free(src);
                if (out_err) *out_err = lex_error_create("Unterminated string", line, col);
                return -1;
            }
            ++i; ++col;
            Token t = token_create(TOK_STRING, buf, line, startcol);
            token_list_push(out_tokens, t);
            continue;
        }

        if ((src[i] == '-' && src[i+1] == '>') ||
            (src[i] == '=' && src[i+1] == '=') ||
            (src[i] == '!' && src[i+1] == '=') ||
            (src[i] == '<' && src[i+1] == '=') ||
            (src[i] == '>' && src[i+1] == '=')) {
            char two[3] = { src[i], src[i+1], '\0' };
            char *lex = strdup(two);
            Token t = token_create(TOK_OPERATOR, lex, line, col);
            token_list_push(out_tokens, t);
            i += 2; col += 2; continue;
        }

        if (src[i] == '(' || src[i] == '[' || src[i] == '{') {
            if (delim_top < (int)sizeof(delim_stack)) delim_stack[delim_top++] = src[i];
            char s[2] = { src[i], '\0' };
            char *lex = strdup(s);
            Token t = token_create(TOK_OPERATOR, lex, line, col);
            token_list_push(out_tokens, t);
            ++i; ++col; continue;
        }
        if (src[i] == ')' || src[i] == ']' || src[i] == '}') {
            if (delim_top == 0) {
                free(src);
                if (out_err) *out_err = lex_error_create("Unmatched closing delimiter", line, col);
                return -1;
            }
            char open = delim_stack[delim_top-1];
            int match = 0;
            if (open == '(' && src[i] == ')') match = 1;
            if (open == '[' && src[i] == ']') match = 1;
            if (open == '{' && src[i] == '}') match = 1;
            if (!match) {
                free(src);
                if (out_err) *out_err = lex_error_create("Mismatched closing delimiter", line, col);
                return -1;
            }
            --delim_top;
            char s[2] = { src[i], '\0' };
            char *lex = strdup(s);
            Token t = token_create(TOK_OPERATOR, lex, line, col);
            token_list_push(out_tokens, t);
            ++i; ++col; continue;
        }
        const char *ops = "+-*/%=<>:,.";
        if (strchr(ops, src[i])) {
            char s[2] = { src[i], '\0' };
            char *lex = strdup(s);
            Token t = token_create(TOK_OPERATOR, lex, line, col);
            token_list_push(out_tokens, t);
            ++i; ++col; continue;
        }
        char unknown[2] = { src[i], '\0' };
        Token t = token_create(TOK_UNKNOWN, strdup(unknown), line, col);
        token_list_push(out_tokens, t);
        ++i; ++col;
    }
    if (out_tokens->count == 0 || out_tokens->items[out_tokens->count - 1].type != TOK_NEWLINE) {
        Token t = token_create(TOK_NEWLINE, strdup("\n"), line, col);
        token_list_push(out_tokens, t);
    }
    while (indent_top > 0) {
        Token t = token_create(TOK_DEDENT, strdup(""), line, col);
        token_list_push(out_tokens, t);
        --indent_top;
    }
    if (delim_top > 0) {
        char msgbuf[128];
        char open = delim_stack[delim_top-1];
        snprintf(msgbuf, sizeof(msgbuf), "Unclosed delimiter '%c' at EOF", open);
        free(src);
        if (out_err) *out_err = lex_error_create(msgbuf, line, col);
        return -1;
    }

    Token t_eof = token_create(TOK_EOF, strdup(""), line, col);
    token_list_push(out_tokens, t_eof);
    {
        auto_prev_next: ;
    }
    {
        size_t n = out_tokens->count;
        for (size_t idx = 0; idx < n; ++idx) {
            Token *tk = &out_tokens->items[idx];
            if (tk->type != TOK_OPERATOR) continue;
            const char *op = tk->lexeme ? tk->lexeme : "";
            int is_binary = 0;
            if (strcmp(op, "+") == 0 || strcmp(op, "-") == 0 || strcmp(op, "*") == 0 || strcmp(op, "/") == 0 || strcmp(op, "%") == 0 || strcmp(op, "<") == 0 || strcmp(op, ">") == 0 || strcmp(op, "<=") == 0 || strcmp(op, ">=") == 0 || strcmp(op, "==") == 0 || strcmp(op, "!=") == 0) is_binary = 1;
            int is_assign = (strcmp(op, "=") == 0);
            if (!is_binary && !is_assign) continue;
            long pj = (long)idx - 1;
            while (pj >= 0 && (out_tokens->items[pj].type == TOK_NEWLINE || out_tokens->items[pj].type == TOK_INDENT || out_tokens->items[pj].type == TOK_DEDENT)) --pj;
            size_t nj = idx + 1;
            while (nj < n && (out_tokens->items[nj].type == TOK_NEWLINE || out_tokens->items[nj].type == TOK_INDENT || out_tokens->items[nj].type == TOK_DEDENT)) ++nj;

            Token *prev = (pj >= 0) ? &out_tokens->items[pj] : NULL;
            Token *next = (nj < n) ? &out_tokens->items[nj] : NULL;
            int prev_is_value = 0;
            if (prev) {
                if (prev->type == TOK_IDENTIFIER || prev->type == TOK_NUMBER || prev->type == TOK_STRING) prev_is_value = 1;
                else if (prev->type == TOK_OPERATOR && prev->lexeme) {
                    if (strcmp(prev->lexeme, ")") == 0 || strcmp(prev->lexeme, "]") == 0 || strcmp(prev->lexeme, "}") == 0) prev_is_value = 1;
                }
            }
            int next_is_start = 0;
            if (next) {
                if (next->type == TOK_IDENTIFIER || next->type == TOK_NUMBER || next->type == TOK_STRING) next_is_start = 1;
                else if (next->type == TOK_OPERATOR && next->lexeme) {
                    if (strcmp(next->lexeme, "(") == 0 || strcmp(next->lexeme, "[") == 0 || strcmp(next->lexeme, "{") == 0) next_is_start = 1;
                    else if (strcmp(next->lexeme, "+") == 0 || strcmp(next->lexeme, "-") == 0) {
                        /* allow unary +/- if followed by a number or identifier */
                        size_t k = nj + 1;
                        while (k < n && (out_tokens->items[k].type == TOK_NEWLINE || out_tokens->items[k].type == TOK_INDENT || out_tokens->items[k].type == TOK_DEDENT)) ++k;
                        if (k < n) {
                            Token *kth = &out_tokens->items[k];
                            if (kth->type == TOK_NUMBER || kth->type == TOK_IDENTIFIER) next_is_start = 1;
                        }
                    }
                }
            }
            if (is_binary) {
                if (!prev_is_value) {
                    char msg[128];
                    snprintf(msg, sizeof(msg), "Operator '%s' missing left operand", op);
                    free(src);
                    if (out_err) *out_err = lex_error_create(msg, tk->line, tk->column);
                    return -1;
                }
                if (!next_is_start) {
                    char msg[128];
                    snprintf(msg, sizeof(msg), "Operator '%s' missing right operand", op);
                    free(src);
                    if (out_err) *out_err = lex_error_create(msg, tk->line, tk->column);
                    return -1;
                }
            }
            if (is_assign) {
                /* Allow assignment after identifier OR after ']' (for array access) */
                int valid_lhs = 0;
                if (prev && prev->type == TOK_IDENTIFIER) {
                    valid_lhs = 1;
                } else if (prev && prev->type == TOK_OPERATOR && strcmp(prev->lexeme, "]") == 0) {
                    valid_lhs = 1;  /* Array element assignment: arr[i] = value */
                }
                if (!valid_lhs) {
                    char msg[128];
                    snprintf(msg, sizeof(msg), "Assignment '=' must follow a variable name on the left-hand side");
                    free(src);
                    if (out_err) *out_err = lex_error_create(msg, tk->line, tk->column);
                    return -1;
                }
                if (!next_is_start) {
                    char msg[128];
                    snprintf(msg, sizeof(msg), "Assignment '=' missing right-hand expression");
                    free(src);
                    if (out_err) *out_err = lex_error_create(msg, tk->line, tk->column);
                    return -1;
                }
            }
        }
    }

    free(src);
    return 0;
}

void lexer_free_tokens(TokenList *list)
{
    token_list_free(list);
}
