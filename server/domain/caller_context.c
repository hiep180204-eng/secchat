/*
 * domain/caller_context.c — tạo CallerContext từ một slot client đang sống.
 *
 * Đây là file DUY NHẤT trong domain/ phụ thuộc tầng transport (clients.h). Các
 * header domain thuần (validation.h, entities.h, định nghĩa struct
 * caller_context.h) vẫn không phụ thuộc gì.
 */

#include "caller_context.h"
#include "clients.h"

#include <string.h>
