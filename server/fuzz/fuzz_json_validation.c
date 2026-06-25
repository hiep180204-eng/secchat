#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../domain/validation.h"
#include "../protocol/json_helpers.h"
#include "../transport/ws.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size > 65536) return 0;

    char *s = (char *)malloc(size + 1);
    if (!s) return 0;
    memcpy(s, data, size);
    s[size] = '\0';

    char text[512];
    char tiny[1];
    char accept[29];
    int value = 0;
    int values[16];

    jget(s, "type", text, sizeof(text));
    jget(s, "body", text, sizeof(text));
    jget(s, "email", text, sizeof(text));
    jget_int(s, "user_id", &value);
    jget_int(s, "conversation_id", &value);
    jget_array(s, "members", values, 16);

    json_esc(s, text, sizeof(text));
    json_esc(s, tiny, sizeof(tiny));
    json_esc(NULL, tiny, sizeof(tiny));
    json_esc(s, NULL, 0);

    domain_validate_username(s);
    domain_validate_email(s);
    domain_validate_group_name(s);
    domain_validate_message_body(s, 4096);
    domain_validate_role(s);
    domain_validate_pwhash(s);
    domain_validate_display_name(s);
    domain_validate_bio(s);
    domain_validate_emoji(s);
    domain_validate_e2e_prefix(s);

    ws_build_accept(s, accept, sizeof(accept));

    free(s);
    return 0;
}

#ifndef SECCHAT_LIBFUZZER
int main(void)
{
    const char *samples[] = {
        "",
        "{}",
        "{\"type\":\"auth\",\"user_id\":\"2147483648\"}",
        "GET / HTTP/1.1\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
    };
    size_t count = sizeof(samples) / sizeof(samples[0]);
    for (size_t i = 0; i < count; i++) {
        LLVMFuzzerTestOneInput((const uint8_t *)samples[i], strlen(samples[i]));
    }
    return 0;
}
#endif
