#pragma once
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint64_t handle;
} rcx_core_t;

/* Return codes match BridgeError */
int rcx_core_init(rcx_core_t* out);

int rcx_core_unlock_with_phrase(
    uint64_t handle,
    const uint8_t* phrase,
    size_t len
);

int rcx_core_encrypt_chunk(
    uint64_t handle,
    uint64_t file_id,
    uint16_t cloud_id,
    uint32_t chunk,
    const uint8_t* in,
    size_t in_len,
    uint8_t* out,
    size_t out_len
);

int rcx_core_decrypt_chunk(
    uint64_t handle,
    uint64_t file_id,
    uint16_t cloud_id,
    uint32_t chunk,
    const uint8_t* in,
    size_t in_len,
    uint8_t* out,
    size_t out_len
);

int rcx_core_is_killed(void);

#ifdef __cplusplus
}
#endif

