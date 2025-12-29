// Test the exact CP-ABE Waters decryption formula with proper scheme math
// Based on Waters CP-ABE from OpenABE implementation

#include <iostream>
#include <iomanip>
#include <cstring>
#include <mcl/bn254.hpp>

using namespace mcl::bn;

void printHex(const char* label, const void* data, size_t len) {
    const uint8_t* bytes = (const uint8_t*)data;
    std::cout << label << ": ";
    for (size_t i = 0; i < std::min(len, (size_t)32); i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)bytes[i];
    }
    if (len > 32) std::cout << "...";
    std::cout << std::dec << std::endl;
}

void printGT(const char* label, const GT& gt) {
    uint8_t buffer[576];
    size_t len = gt.serialize(buffer, sizeof(buffer));
    printHex(label, buffer, len);
}

int main() {
    std::cout << "Testing CP-ABE Waters scheme decryption with MCL" << std::endl;
    std::cout << "=================================================" << std::endl;

    // Initialize MCL
    initPairing(mcl::BN254);

    // Setup phase: Master secret key (alpha, a) and public key
    Fr alpha, a, t, s;
    G1 g1, g1a, H1, H2;  // G1 generators and hashes
    G2 g2;               // G2 generator

    alpha.setByCSPRNG();
    a.setByCSPRNG();
    t.setByCSPRNG();
    s.setByCSPRNG();

    hashAndMapToG1(g1, "g1");
    hashAndMapToG2(g2, "g2");
    G1::mul(g1a, g1, a);  // g1a = g1^a
    hashAndMapToG1(H1, "attr1");
    hashAndMapToG1(H2, "attr2");

    // Public key: A = e(g1, g2)^alpha
    GT A;
    pairing(A, g1, g2);
    GT::pow(A, A, alpha);

    std::cout << "\n=== Setup Complete ===" << std::endl;
    std::cout << "Master secret: alpha, a" << std::endl;
    std::cout << "Public params: g1, g2, g1a, A" << std::endl;

    // Encryption for policy (attr1 AND attr2) with LSSS shares
    // For AND policy with 2 attributes, shares are (s, s)
    Fr share1 = s;
    Fr share2 = s;
    Fr r1, r2;
    r1.setByCSPRNG();
    r2.setByCSPRNG();

    // C = A^s = e(g1, g2)^(alpha*s)
    GT C;
    GT::pow(C, A, s);

    // Cprime = g1^s
    G1 Cprime;
    G1::mul(Cprime, g1, s);

    // For each attribute:
    // C_i = g1a^{share_i} * H(attr_i)^{-r_i}
    // D_i = g2^{r_i}
    G1 C1, C2;
    G2 D1, D2;

    G1 temp1, temp2;
    G1::mul(temp1, g1a, share1);  // g1a^share1
    Fr neg_r1 = -r1;
    G1::mul(temp2, H1, neg_r1);   // H1^{-r1}
    C1 = temp1 + temp2;           // C1 = g1a^share1 * H1^{-r1}

    G1::mul(temp1, g1a, share2);  // g1a^share2
    Fr neg_r2 = -r2;
    G1::mul(temp2, H2, neg_r2);   // H2^{-r2}
    C2 = temp1 + temp2;           // C2 = g1a^share2 * H2^{-r2}

    G2::mul(D1, g2, r1);          // D1 = g2^r1
    G2::mul(D2, g2, r2);          // D2 = g2^r2

    std::cout << "\n=== Encryption Complete ===" << std::endl;
    printGT("C = e(g1,g2)^(alpha*s)", C);

    // Key generation for attributes {attr1, attr2}
    // K = g2^(alpha + at)
    // L = g2^t
    // KX_i = H(attr_i)^t
    Fr alpha_plus_at = alpha + (a * t);
    G2 K, L;
    G1 KX1, KX2;

    G2::mul(K, g2, alpha_plus_at);  // K = g2^(alpha + at)
    G2::mul(L, g2, t);              // L = g2^t
    G1::mul(KX1, H1, t);            // KX1 = H(attr1)^t
    G1::mul(KX2, H2, t);            // KX2 = H(attr2)^t

    std::cout << "\n=== Key Generation Complete ===" << std::endl;

    // Decryption
    // For AND policy, coefficients are (1, 1)
    Fr coeff1 = Fr(1);
    Fr coeff2 = Fr(1);

    // prod1 = product of C_i^{coeff_i}
    G1 prod1;
    G1 C1_coeff, C2_coeff;
    G1::mul(C1_coeff, C1, coeff1);
    G1::mul(C2_coeff, C2, coeff2);
    prod1 = C1_coeff + C2_coeff;

    // prodT = product of e(KX_i^{coeff_i}, D_i)
    GT prodT;
    G1 KX1_coeff, KX2_coeff;
    G1::mul(KX1_coeff, KX1, coeff1);
    G1::mul(KX2_coeff, KX2, coeff2);

    GT e1, e2;
    pairing(e1, KX1_coeff, D1);
    pairing(e2, KX2_coeff, D2);
    prodT = e1 * e2;

    std::cout << "\n=== Decryption Formula ===" << std::endl;
    std::cout << "Computing: final = e(Cprime, K) / (prodT * e(prod1, L))" << std::endl;

    // Step 1: Compute e(Cprime, K)
    GT e_Cprime_K;
    pairing(e_Cprime_K, Cprime, K);
    printGT("e(Cprime, K)", e_Cprime_K);

    // Step 2: Compute e(prod1, L)
    GT e_prod1_L;
    pairing(e_prod1_L, prod1, L);
    printGT("e(prod1, L)", e_prod1_L);

    // Step 3: Compute prodT * e(prod1, L)
    printGT("prodT", prodT);
    GT denominator = prodT * e_prod1_L;
    printGT("prodT * e(prod1, L)", denominator);

    // Step 4: Compute final = e(Cprime, K) / denominator
    GT final = e_Cprime_K / denominator;
    printGT("final (decrypted)", final);

    std::cout << "\n=== Verification ===" << std::endl;
    if (C == final) {
        std::cout << "✓ SUCCESS: Decrypted GT matches original C!" << std::endl;
        std::cout << "✓ CP-ABE decryption formula works correctly with MCL" << std::endl;
        return 0;
    } else {
        std::cout << "✗ FAILURE: Decrypted GT does NOT match original C!" << std::endl;
        std::cout << "✗ This confirms the CP-ABE decryption formula produces wrong result with MCL." << std::endl;

        // Debug: try serializing and comparing
        uint8_t buf1[576], buf2[576];
        size_t len1 = C.serialize(buf1, sizeof(buf1));
        size_t len2 = final.serialize(buf2, sizeof(buf2));
        std::cout << "\nSerialized lengths: C=" << len1 << ", final=" << len2 << std::endl;
        if (len1 == len2) {
            bool bytewise_equal = (memcmp(buf1, buf2, len1) == 0);
            std::cout << "Bytewise comparison: " << (bytewise_equal ? "EQUAL" : "NOT EQUAL") << std::endl;
        }

        return 1;
    }
}
