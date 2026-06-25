/*
 * services/chat.c — bộ điều phối (dispatcher) của nhóm nghiệp vụ nhắn tin.
 *
 * Lớp mỏng điều phối: định tuyến lệnh tới các sub-service nhắn tin tương ứng.
 * Toàn bộ logic handler nằm trong từng file service riêng.
 */

#include "chat.h"
#include "messaging_service.h"
#include "reaction_service.h"
#include "pin_service.h"
#include "disappearing_service.h"
#include "conv_pref_service.h"

int chat_dispatch(int idx, const char *type, const char *buf)
{
    if (messaging_dispatch(idx, type, buf))    return 1;
    if (reaction_dispatch(idx, type, buf))     return 1;
    if (pin_dispatch(idx, type, buf))          return 1;
    if (disappearing_dispatch(idx, type, buf)) return 1;
    if (conv_pref_dispatch(idx, type, buf))    return 1;
    return 0;
}
