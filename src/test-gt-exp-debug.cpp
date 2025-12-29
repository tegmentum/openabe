// Test program to debug GT exponentiation differences between native and WASM
#include <stdio.h>
#include <stdint.h>
#include <openabe/openabe.h>

using namespace oabe;

int main() {
    fprintf(stderr, "=== GT Exponentiation Debug Test ===\n");

    InitializeOpenABE();

    // Create a pairing context
    std::unique_ptr<OpenABEPairing> pairing(new OpenABEPairing(OpenABE_ZPSAFE_CURVE_BLS12_381));

    // Create a fixed RNG with deterministic seed for reproducibility
    std::unique_ptr<OpenABERNG> rng(new OpenABERNG);

    // Generate a random scalar s
    ZP s = pairing->randomZP(rng.get());
    fprintf(stderr, "[DEBUG] Generated scalar s\n");

#if defined(BP_WITH_MCL)
    uint8_t s_bytes[32];
    size_t s_len = mclBnFr_serialize(s_bytes, sizeof(s_bytes), &s.m_ZP);
    fprintf(stderr, "[DEBUG] s (%zu bytes): ", s_len);
    for (size_t i = 0; i < s_len; i++) {
        fprintf(stderr, "%02x", s_bytes[i]);
    }
    fprintf(stderr, "\n");
#endif

    // Generate g1, g2 generators
    G1 g1 = pairing->randomG1(rng.get());
    G2 g2 = pairing->randomG2(rng.get());
    fprintf(stderr, "[DEBUG] Generated G1, G2 elements\n");

    // Compute GT element via pairing
    GT gt_base = pairing->pairing(g1, g2);
    fprintf(stderr, "[DEBUG] Computed GT base via e(g1, g2)\n");

#if defined(BP_WITH_MCL)
    fprintf(stderr, "[DEBUG] GT base: isZero=%d, isOne=%d\n",
            mclBnGT_isZero(&gt_base.m_GT), mclBnGT_isOne(&gt_base.m_GT));
    uint8_t gt_base_bytes[576];
    size_t gt_base_len = mclBnGT_serialize(gt_base_bytes, sizeof(gt_base_bytes), &gt_base.m_GT);
    fprintf(stderr, "[DEBUG] GT base serialized (%zu bytes, first 32): ", gt_base_len);
    for (size_t i = 0; i < 32 && i < gt_base_len; i++) {
        fprintf(stderr, "%02x", gt_base_bytes[i]);
    }
    fprintf(stderr, "\n");
#endif

    // Now perform exponentiation: GT_result = GT_base^s
    GT gt_exp = gt_base.exp(s);
    fprintf(stderr, "[DEBUG] Computed GT^s exponentiation\n");

#if defined(BP_WITH_MCL)
    fprintf(stderr, "[DEBUG] GT^s result: isZero=%d, isOne=%d\n",
            mclBnGT_isZero(&gt_exp.m_GT), mclBnGT_isOne(&gt_exp.m_GT));
    uint8_t gt_exp_bytes[576];
    size_t gt_exp_len = mclBnGT_serialize(gt_exp_bytes, sizeof(gt_exp_bytes), &gt_exp.m_GT);
    fprintf(stderr, "[DEBUG] GT^s serialized (%zu bytes, FULL):\n", gt_exp_len);
    for (size_t i = 0; i < gt_exp_len; i++) {
        fprintf(stderr, "%02x", gt_exp_bytes[i]);
        if ((i + 1) % 32 == 0) fprintf(stderr, "\n");
    }
    if (gt_exp_len % 32 != 0) fprintf(stderr, "\n");
#endif

    // Hash GT to bytes to simulate key derivation
    OpenABEByteString key_bytes;
    gt_exp.hashToBytes(key_bytes);
    fprintf(stderr, "[DEBUG] Hashed GT^s to %d bytes\n", (int)key_bytes.size());
    fprintf(stderr, "[DEBUG] Key (first 16 bytes): ");
    for (size_t i = 0; i < 16 && i < key_bytes.size(); i++) {
        fprintf(stderr, "%02x", key_bytes.at(i));
    }
    fprintf(stderr, "\n");

    fprintf(stderr, "=== Test Complete ===\n");
    ShutdownOpenABE();
    return 0;
}
