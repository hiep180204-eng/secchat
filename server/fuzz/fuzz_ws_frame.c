#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../transport/ws.h"

static void try_decode(const uint8_t *data, size_t size)
{
    char tiny[1];
    char small[8];
    char out[4096];
    int opcode = 0;

    ws_decode_client_frame(data, size, tiny, sizeof(tiny), &opcode);
    ws_decode_client_frame(data, size, small, sizeof(small), &opcode);
    ws_decode_client_frame(data, size, out, sizeof(out), &opcode);
    ws_decode_client_frame(data, size, NULL, 0, &opcode);
}

static void synthesize_masked_text(const uint8_t *data, size_t size)
{
    size_t payload_len = size > 2048 ? 2048 : size;
    size_t header_len = payload_len <= 125 ? 6 : 8;
    uint8_t *frame = (uint8_t *)malloc(header_len + payload_len);
    if (!frame) return;

    frame[0] = 0x81;
    if (payload_len <= 125) {
        frame[1] = (uint8_t)(0x80 | payload_len);
        frame[2] = 0x11;
        frame[3] = 0x22;
        frame[4] = 0x33;
        frame[5] = 0x44;
    } else {
        frame[1] = 0x80 | 126;
        frame[2] = (uint8_t)((payload_len >> 8) & 0xff);
        frame[3] = (uint8_t)(payload_len & 0xff);
        frame[4] = 0x11;
        frame[5] = 0x22;
        frame[6] = 0x33;
        frame[7] = 0x44;
    }

    const uint8_t *mask = frame + header_len - 4;
    for (size_t i = 0; i < payload_len; i++)
        frame[header_len + i] = data[i] ^ mask[i & 3];

    try_decode(frame, header_len + payload_len);
    free(frame);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size > 65536) return 0;
    try_decode(data, size);
    synthesize_masked_text(data, size);
    return 0;
}

#ifndef SECCHAT_LIBFUZZER
int main(void)
{
    const uint8_t sample[] = {
        0x81, 0x85, 't', 'e', 's', 't',
        (uint8_t)('h' ^ 't'),
        (uint8_t)('e' ^ 'e'),
        (uint8_t)('l' ^ 's'),
        (uint8_t)('l' ^ 't'),
        (uint8_t)('o' ^ 't'),
    };
    LLVMFuzzerTestOneInput(sample, sizeof(sample));
    LLVMFuzzerTestOneInput((const uint8_t *)"", 0);
    return 0;
}
#endif
