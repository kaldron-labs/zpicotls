/* TLS 1.3 output fits the original ciphertext body without allocating. */
#include <stdlib.h>
#include <string.h>
#include "zpicotls.h"
#include "zpicotls/openssl.h"
#include "../deps/picotest/picotest.h"

static size_t alloc_calls;
static void *reject_alloc(ptls_buffer_t *buf, size_t capacity, uint8_t align_bits, int tx)
{
    ++alloc_calls;
    return NULL;
}

static void test_exact_rx(size_t length)
{
    ptls_cipher_suite_t *suites[] = {&ptls_openssl_aes128gcmsha256, NULL};
    ptls_context_t ctx = {.random_bytes = ptls_openssl_random_bytes,
                          .get_time = &ptls_get_time,
                          .key_exchanges = ptls_openssl_key_exchanges,
                          .cipher_suites = suites};
    ctx.pre_shared_key.identity = ptls_iovec_init("inplace", 7);
    ctx.pre_shared_key.secret = ptls_iovec_init("exact receive capacity", 22);
    ctx.pre_shared_key.hash = suites[0]->hash;
    ptls_t *client = ptls_new(&ctx, 0), *server = ptls_new(&ctx, 1);
    ptls_buffer_t cbuf, sbuf;
    ptls_buffer_init_tx(&cbuf, "", 0);
    ptls_buffer_init_tx(&sbuf, "", 0);
    int ret = ptls_handshake(client, &cbuf, NULL, NULL, NULL);
    ok(ret == PTLS_ERROR_IN_PROGRESS);
    size_t consumed = cbuf.off;
    ret = ptls_handshake(server, &sbuf, cbuf.base, &consumed, NULL);
    ok(ret == 0 || ret == PTLS_ERROR_IN_PROGRESS);
    ok(consumed == cbuf.off);
    cbuf.off = 0;
    consumed = sbuf.off;
    ret = ptls_handshake(client, &cbuf, sbuf.base, &consumed, NULL);
    ok(ret == 0);
    ok(consumed == sbuf.off);
    sbuf.off = 0;
    consumed = cbuf.off;
    ret = ptls_handshake(server, &sbuf, cbuf.base, &consumed, NULL);
    ok(ret == 0);
    ok(consumed == cbuf.off);
    ok(ptls_handshake_is_complete(client) && ptls_handshake_is_complete(server));
    cbuf.off = 0;
    uint8_t *payload = malloc(length);
    memset(payload, 0x37, length);
    ret = ptls_send(client, &cbuf, payload, length);
    ok(ret == 0);
    /* One checked sentinel follows the exact record boundary. */
    uint8_t *wire = malloc(cbuf.off + 1);
    memcpy(wire, cbuf.base, cbuf.off);
    wire[cbuf.off] = 0xa5;
    ptls_buffer_t output;
    ptls_buffer_init_rx(&output, wire + 5, cbuf.off - 5);
    output.origin = wire;
    void *(*saved_alloc)(ptls_buffer_t *, size_t, uint8_t, int) = ptls_buffer_alloc;
    alloc_calls = 0;
    ptls_buffer_alloc = reject_alloc;
    consumed = cbuf.off;
    ret = ptls_receive(server, &output, wire, &consumed);
    ptls_buffer_alloc = saved_alloc;
    ok(ret == 0);
    ok(consumed == cbuf.off);
    ok(alloc_calls == 0);
    ok(output.base == wire + 5 && output.origin == wire && !output.is_allocated);
    ok(output.off == length);
    ok(memcmp(wire + 5, payload, length) == 0);
    ok(wire[cbuf.off] == 0xa5);
    free(wire);
    free(payload);
    ptls_buffer_dispose(&cbuf);
    ptls_buffer_dispose(&sbuf);
    ptls_free(client);
    ptls_free(server);
}

int main(void)
{
    subtest("exact-rx-small", test_exact_rx, 1);
    subtest("exact-rx-full", test_exact_rx, 16384 /* TLS plaintext record limit */);
    return done_testing();
}
