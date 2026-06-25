/* protocol/json_helpers.c — parse JSON an toàn bằng cJSON.
 *
 * Bản cũ dùng strstr() để tìm key theo tên — không an toàn: một value chứa chuỗi
 * "type":"admin" có thể đánh lừa jget() trả "admin" cho key "type".
 *
 * cJSON dựng cây parse đúng nên tra key luôn theo vị trí cấu trúc, không theo tìm
 * chuỗi con. Một key nằm BÊN TRONG giá trị string bị bỏ qua.
 *
 * API (khai báo trong json_helpers.h) giữ nguyên — không cần sửa nơi gọi.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include "cJSON.h"
#include "json_helpers.h"

/* ── helpers ─────────────────────────────────────────────────────────── */

typedef int (*extract_fn)(cJSON *item, void *ud);

static int with_item(const char *json, const char *key,
                     extract_fn cb, void *ud)
{
    if (!json || !key) return 0;
    cJSON *root = cJSON_Parse(json);
    if (!root) return 0;
    cJSON *item = cJSON_GetObjectItemCaseSensitive(root, key);
    int   rc   = cb(item, ud);
    cJSON_Delete(root);
    return rc;
}

/* ── jget ────────────────────────────────────────────────────────────── */

typedef struct { char *val; int vmax; } JgetCtx;

static int _jget_cb(cJSON *item, void *ud)
{
    JgetCtx *ctx = (JgetCtx *)ud;
    if (!cJSON_IsString(item) || !item->valuestring) return 0;
    strncpy(ctx->val, item->valuestring, (size_t)(ctx->vmax - 1));
    ctx->val[ctx->vmax - 1] = '\0';
    return 1;
}

int jget(const char *json, const char *key, char *val, int vmax)
{
    if (!val || vmax < 1) return 0;
    val[0] = '\0';
    JgetCtx ctx = { val, vmax };
    return with_item(json, key, _jget_cb, &ctx);
}

/* ── jget_int ────────────────────────────────────────────────────────── */

static int _jget_int_cb(cJSON *item, void *ud)
{
    int *out = (int *)ud;
    if (cJSON_IsNumber(item)) {
        *out = item->valueint;
        return 1;
    }
    if (cJSON_IsString(item) && item->valuestring && item->valuestring[0]) {
        char *end = NULL;
        errno = 0;
        long v = strtol(item->valuestring, &end, 10);
        while (end && (*end == ' ' || *end == '\t' ||
                       *end == '\r' || *end == '\n')) {
            end++;
        }
        if (end && end != item->valuestring && *end == '\0' &&
                errno != ERANGE && v >= INT_MIN && v <= INT_MAX) {
            *out = (int)v;
            return 1;
        }
    }
    return 0;
}

int jget_int(const char *json, const char *key, int *out_val)
{
    if (!out_val) return 0;
    return with_item(json, key, _jget_int_cb, out_val);
}

/* ── jget_array ──────────────────────────────────────────────────────── */

typedef struct { int *arr; int maxlen; int count; } JarrCtx;

static int _jget_array_cb(cJSON *item, void *ud)
{
    JarrCtx *ctx = (JarrCtx *)ud;
    if (!cJSON_IsArray(item)) return 0;
    cJSON *elem;
    cJSON_ArrayForEach(elem, item) {
        if (ctx->count >= ctx->maxlen) break;
        if (cJSON_IsNumber(elem))
            ctx->arr[ctx->count++] = elem->valueint;
    }
    return ctx->count;
}

int jget_array(const char *json, const char *key, int *arr, int maxlen)
{
    if (!arr || maxlen < 1) return 0;
    JarrCtx ctx = { arr, maxlen, 0 };
    with_item(json, key, _jget_array_cb, &ctx);
    return ctx.count;
}

/* ── json_esc ────────────────────────────────────────────────────────── */

void json_esc(const char *in, char *out, int maxout)
{
    if (!out || maxout <= 0) return;
    if (!in) {
        out[0] = '\0';
        return;
    }
    int j = 0;
    for (int i = 0; in[i] && j < maxout - 7; i++) {
        unsigned char c = (unsigned char)in[i];
        if      (c == '"')  { out[j++] = '\\'; out[j++] = '"';  }
        else if (c == '\\') { out[j++] = '\\'; out[j++] = '\\'; }
        else if (c == '\n') { out[j++] = '\\'; out[j++] = 'n';  }
        else if (c == '\r') { out[j++] = '\\'; out[j++] = 'r';  }
        else if (c == '\t') { out[j++] = '\\'; out[j++] = 't';  }
        else if (c < 0x20)  { j += snprintf(out + j, (size_t)(maxout - j), "\\u%04x", c); }
        else                { out[j++] = (char)c; }
    }
    out[j] = '\0';
}
