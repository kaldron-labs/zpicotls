/* Immutable fragmented plaintext must produce the same records as contiguous input. */
#include <stdlib.h>
#include <string.h>
#include "zpicotls.h"
#include "zpicotls/openssl.h"
#include "zpicotls/fusion.h"
#include "../deps/picotest/picotest.h"

static size_t alloc_calls;
static void *reject_alloc(ptls_buffer_t *buf, size_t capacity, uint8_t align_bits, int tx)
{
    ++alloc_calls;
    return NULL;
}

static void records(ptls_t *client, ptls_t *baseline, ptls_t *server, int tls13)
{
    ptls_tx_t *vector_tx = NULL, *scalar_tx = NULL;
    ok(ptls_detach_tx(client, &vector_tx) == 0);
    ok(ptls_detach_tx(baseline, &scalar_tx) == 0);
    if (vector_tx == NULL || scalar_tx == NULL)
        goto Exit;

    const size_t maximum = 16384; /* TLS plaintext record limit. */
    size_t capacity = 2 * (maximum + ptls_tx_get_record_overhead(vector_tx));
    uint8_t *source = malloc(maximum + 1), *wire = NULL, *reference = NULL, *clear = malloc(capacity);
    ok(posix_memalign((void **)&wire, 64, capacity + 1) == 0);
    ok(posix_memalign((void **)&reference, 64, capacity + 1) == 0);
    for (size_t i = 0; i <= maximum; ++i)
        source[i] = (uint8_t)(0x37 + i);

    ptls_buffer_t output;
    ptls_buffer_init_tx(&output, wire, capacity);
    output.origin = wire;
    output.align_bits = ptls_tx_get_cipher(vector_tx)->aead->align_bits;
    ptls_iovec_t oversized[] = {ptls_iovec_init(source, maximum), ptls_iovec_init(source + maximum, 1), {NULL, 0}};
    ok(ptls_tx_sendv(vector_tx, &output, oversized, 2) == PTLS_ERROR_LIBRARY);
    ok(output.off == 0 && output.base == wire);
    ok(ptls_tx_sendv(NULL, &output, NULL, 0) == PTLS_ERROR_NOT_AVAILABLE);

    /* Odd seven-byte fragments cross AEAD block boundaries, including the full record. */
    size_t lengths[] = {0, 1, 17, maximum, 17};
    for (size_t trial = 0; trial != sizeof(lengths) / sizeof(lengths[0]); ++trial) {
        size_t length = lengths[trial], count = (length + 6) / 7;
        ptls_iovec_t *spans = calloc(count + 1, sizeof(*spans));
        for (size_t i = 0, offset = 0; i != count; ++i) {
            size_t n = length - offset;
            if (n > 7)
                n = 7;
            spans[i] = ptls_iovec_init(source + offset, n);
            offset += n;
        }
        ptls_buffer_t scalar;
        ptls_buffer_init_tx(&output, wire, capacity);
        ptls_buffer_init_tx(&scalar, reference, capacity);
        output.origin = wire;
        scalar.origin = reference;
        output.align_bits = scalar.align_bits = ptls_tx_get_cipher(vector_tx)->aead->align_bits;
        /* Fuzz builds leave dummy authentication tags unwritten. */
        memset(wire, 0, capacity);
        memset(reference, 0, capacity);
        wire[capacity] = reference[capacity] = 0xa5;
        int update = tls13 && trial == sizeof(lengths) / sizeof(lengths[0]) - 1;
        if (update) {
            ok(ptls_tx_update_key(vector_tx, &output, 0) == 0);
            ok(ptls_tx_update_key(scalar_tx, &scalar, 0) == 0);
        }
        void *(*saved_alloc)(ptls_buffer_t *, size_t, uint8_t, int) = ptls_buffer_alloc;
        alloc_calls = 0;
        ptls_buffer_alloc = reject_alloc;
        int ret = ptls_tx_sendv(vector_tx, &output, spans, count);
        ptls_buffer_alloc = saved_alloc;
        ok(ret == 0);
        ok(alloc_calls == 0);
        ok(output.base == wire && output.origin == wire && !output.is_allocated);
        ok(ptls_tx_send(scalar_tx, &scalar, source, length) == 0);
        ok(output.off == scalar.off && memcmp(output.base, scalar.base, output.off) == 0);
        ok(wire[capacity] == 0xa5 && reference[capacity] == 0xa5);
        size_t record_count = 0;
        for (size_t offset = 0; offset < output.off; ++record_count) {
            size_t n = 5 + ((size_t)wire[offset + 3] << 8) + wire[offset + 4];
            ok(n <= output.off - offset);
            offset += n;
        }
        ok(record_count == (length != 0) + update);
        int unchanged = 1;
        for (size_t i = 0; i <= maximum; ++i)
            unchanged &= source[i] == (uint8_t)(0x37 + i);
        ok(unchanged);
        ptls_buffer_t plain;
        ptls_buffer_init_rx(&plain, clear, capacity);
        for (size_t consumed = 0; consumed < output.off;) {
            size_t n = output.off - consumed;
            ret = ptls_receive(server, &plain, output.base + consumed, &n);
            ok(ret == 0 && n != 0);
            if (ret != 0 || n == 0)
                break;
            consumed += n;
        }
        ok(plain.off == length && memcmp(plain.base, source, length) == 0);
        ptls_buffer_dispose(&plain);
        ptls_buffer_dispose(&scalar);
        ptls_buffer_dispose(&output);
        free(spans);
    }
    free(clear);
    free(reference);
    free(wire);
    free(source);
Exit:
    ptls_tx_free(vector_tx);
    ptls_tx_free(scalar_tx);
}

static void tls13(int fusion)
{
    struct st_ptls_cipher_suite_t suite = ptls_openssl_aes128gcmsha256;
    if (fusion)
        suite.aead = &ptls_fusion_aes128gcm;
    ptls_cipher_suite_t *suites[] = {&suite, NULL};
    ptls_context_t ctx = {.random_bytes = ptls_openssl_random_bytes,
                          .get_time = &ptls_get_time,
                          .key_exchanges = ptls_openssl_key_exchanges,
                          .cipher_suites = suites};
    ctx.pre_shared_key.identity = ptls_iovec_init("vector", 6);
    ctx.pre_shared_key.secret = ptls_iovec_init("immutable fragments", 19);
    ctx.pre_shared_key.hash = suite.hash;
    ptls_t *client = ptls_new(&ctx, 0), *server = ptls_new(&ctx, 1), *baseline = NULL;
    ptls_buffer_t cbuf, sbuf, exported;
    ptls_buffer_init_tx(&cbuf, "", 0);
    ptls_buffer_init_tx(&sbuf, "", 0);
    ptls_buffer_init_tx(&exported, "", 0);
    ok(ptls_handshake(client, &cbuf, NULL, NULL, NULL) == PTLS_ERROR_IN_PROGRESS);
    size_t consumed = cbuf.off;
    int ret = ptls_handshake(server, &sbuf, cbuf.base, &consumed, NULL);
    ok(ret == 0 || ret == PTLS_ERROR_IN_PROGRESS);
    ok(consumed == cbuf.off);
    cbuf.off = 0;
    consumed = sbuf.off;
    ok(ptls_handshake(client, &cbuf, sbuf.base, &consumed, NULL) == 0);
    ok(consumed == sbuf.off);
    consumed = cbuf.off;
    ok(ptls_handshake(server, &sbuf, cbuf.base, &consumed, NULL) == 0);
    ok(consumed == cbuf.off);
    ok(ptls_export(server, &exported) == 0);
    ok(ptls_import(&ctx, &baseline, ptls_iovec_init(exported.base, exported.off)) == 0);
    if (baseline != NULL)
        records(server, baseline, client, 1);
    ptls_buffer_dispose(&exported);
    ptls_buffer_dispose(&sbuf);
    ptls_buffer_dispose(&cbuf);
    if (baseline != NULL)
        ptls_free(baseline);
    ptls_free(server);
    ptls_free(client);
}

static ptls_t *import_tls12(ptls_context_t *ctx, ptls_cipher_suite_t *cipher, int server)
{
    uint8_t master_secret[PTLS_TLS12_MASTER_SECRET_SIZE], randoms[PTLS_HELLO_RANDOM_SIZE * 2];
    for (size_t i = 0; i != sizeof(master_secret); ++i)
        master_secret[i] = (uint8_t)(0x40 + i);
    for (size_t i = 0; i != sizeof(randoms); ++i)
        randoms[i] = (uint8_t)(0x80 + i);
    ptls_buffer_t params;
    ptls_buffer_init_tx(&params, "", 0);
    ptls_t *tls = NULL;
    int ret = ptls_build_tls12_export_params(ctx, &params, server, 0, cipher, master_secret, randoms, 1, "localhost",
                                            ptls_iovec_init(NULL, 0));
    if (ret == 0)
        ret = ptls_import(ctx, &tls, ptls_iovec_init(params.base, params.off));
    ptls_buffer_dispose(&params);
    return ret == 0 ? tls : NULL;
}

static void tls12(ptls_cipher_suite_t *cipher)
{
    ptls_cipher_suite_t *suites[] = {cipher, NULL};
    ptls_context_t ctx = {.random_bytes = ptls_openssl_random_bytes, .get_time = &ptls_get_time, .tls12_cipher_suites = suites};
    ptls_t *client = import_tls12(&ctx, cipher, 0), *baseline = import_tls12(&ctx, cipher, 0),
           *server = import_tls12(&ctx, cipher, 1);
    ok(client != NULL && baseline != NULL && server != NULL);
    if (client != NULL && baseline != NULL && server != NULL)
        records(client, baseline, server, 0);
    ptls_free(server);
    ptls_free(baseline);
    ptls_free(client);
}

int main(void)
{
    subtest("tls13-openssl-vectors", tls13, 0);
    if (ptls_fusion_is_supported_by_cpu())
        subtest("tls13-fusion-vectors", tls13, 1);
    else
        note("skipping Fusion vectors: CPU lacks required instructions");
    subtest("tls12-explicit-iv-vectors", tls12, &ptls_openssl_tls12_ecdhe_rsa_aes128gcmsha256);
#if PTLS_OPENSSL_HAVE_CHACHA20_POLY1305
    subtest("tls12-implicit-iv-vectors", tls12, &ptls_openssl_tls12_ecdhe_rsa_chacha20poly1305sha256);
#endif
    return done_testing();
}
