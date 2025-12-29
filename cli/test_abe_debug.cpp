/**
 * Detailed ABE debug test - traces the full encryption/decryption computation
 */

#include <iostream>
#include <string>
#include <openabe/openabe.h>

using namespace std;
using namespace oabe;

void printGT(const char* label, GT& gt) {
    OpenABEByteString bytes;
    gt.serialize(bytes);
    printf("%s (first 32 bytes): ", label);
    for (size_t i = 0; i < min(bytes.size(), (size_t)32); i++) {
        printf("%02x", bytes[i]);
    }
    printf("\n");
}

void printG1(const char* label, G1& g1) {
    OpenABEByteString bytes;
    g1.serialize(bytes);
    printf("%s (first 32 bytes): ", label);
    for (size_t i = 0; i < min(bytes.size(), (size_t)32); i++) {
        printf("%02x", bytes[i]);
    }
    printf("\n");
}

void printG2(const char* label, G2& g2) {
    OpenABEByteString bytes;
    g2.serialize(bytes);
    printf("%s (first 32 bytes): ", label);
    for (size_t i = 0; i < min(bytes.size(), (size_t)32); i++) {
        printf("%02x", bytes[i]);
    }
    printf("\n");
}

void printZP(const char* label, ZP& zp) {
    OpenABEByteString bytes;
    zp.serialize(bytes);
    printf("%s (first 32 bytes): ", label);
    for (size_t i = 0; i < min(bytes.size(), (size_t)32); i++) {
        printf("%02x", bytes[i]);
    }
    printf("\n");
}

int main() {
    cout << "=== Detailed ABE Debug Test ===" << endl;

    InitializeOpenABE();

    // Create pairing and RNG
    OpenABEPairing pairing("BLS12_P381");
    OpenABERNG rng;
    OpenABEByteString k;
    rng.getRandomBytes(&k, 32);  // hash function key prefix

    cout << "\n=== SETUP PHASE ===" << endl;

    // Generate random generators
    G1 g1 = pairing.randomG1(&rng);
    G2 g2 = pairing.randomG2(&rng);
    printG1("g1", g1);
    printG2("g2", g2);

    // Generate secrets
    ZP alpha = pairing.randomZP(&rng);
    ZP a = pairing.randomZP(&rng);
    printZP("alpha", alpha);
    printZP("a", a);

    // Compute public parameters
    G1 g1a = g1.exp(a);
    G2 g2a = g2.exp(a);
    G2 g2alpha = g2.exp(alpha);
    GT A = pairing.pairing(g1, g2).exp(alpha);

    printG1("g1a = g1^a", g1a);
    printG2("g2a = g2^a", g2a);
    printG2("g2alpha = g2^alpha", g2alpha);
    printGT("A = e(g1,g2)^alpha", A);

    cout << "\n=== KEY GENERATION (for attr A, B) ===" << endl;

    // Generate key for attributes A, B
    ZP t = pairing.randomZP(&rng);
    printZP("t (random for key)", t);

    // K = g2^alpha * (g2^a)^t = g2^(alpha + at)
    G2 K = g2.exp(alpha) * g2a.exp(t);
    printG2("K = g2^alpha * g2a^t", K);

    // L = g2^t
    G2 L = g2.exp(t);
    printG2("L = g2^t", L);

    // Hash attributes to G1 and compute KX_attr = H(attr)^t
    G1 H_A = pairing.hashToG1(k, "A");
    G1 H_B = pairing.hashToG1(k, "B");
    printG1("H(A) = hashToG1(A)", H_A);
    printG1("H(B) = hashToG1(B)", H_B);

    G1 KX_A = H_A.exp(t);
    G1 KX_B = H_B.exp(t);
    printG1("KX_A = H(A)^t", KX_A);
    printG1("KX_B = H(B)^t", KX_B);

    cout << "\n=== ENCRYPTION (policy: A AND B) ===" << endl;

    // Pick encryption randomness s
    ZP s = pairing.randomZP(&rng);
    printZP("s (encryption random)", s);

    // Compute ciphertext: C = e(g1^s, g2^alpha) = e(g1,g2)^(alpha*s)
    G1 g1s = g1.exp(s);
    GT C = pairing.pairing(g1s, g2alpha);
    printG1("g1^s", g1s);
    printGT("C = e(g1^s, g2^alpha)", C);

    // Verify: this should equal A^s
    GT A_s = A.exp(s);
    printGT("A^s (should match C)", A_s);

    OpenABEByteString CBytes, AsBytes;
    C.serialize(CBytes);
    A_s.serialize(AsBytes);
    bool cMatch = (CBytes == AsBytes);
    cout << "C == A^s: " << (cMatch ? "TRUE" : "FALSE") << endl;

    // Cprime = g1^s
    G1 Cprime = g1.exp(s);
    printG1("Cprime = g1^s", Cprime);

    // For policy "A AND B", LSSS shares: share_A = s, share_B = s (for threshold 2-of-2)
    // Actually for "A AND B" with 2-of-2, the shares are computed differently
    // Let's use simplified shares: share_1 = s * r1, share_2 = s - s*r1 = s*(1-r1)
    // where reconstruction gives: coeff_1 * share_1 + coeff_2 * share_2 = s

    // For simplicity, use: share_A = s, share_B = s with coefficients that sum to 1
    // This is a simplification - the actual LSSS is more complex

    // Actually, let me just use the standard 2-of-2 LSSS:
    // share_1 = s (for row [1, 1])
    // share_2 = s (for row [1, 2])
    // Recovery: c1 * s + c2 * s = s implies c1 + c2 = 1
    // For 2-of-2, the Lagrange coefficients are c1 = -1, c2 = 2 (or c1 = 2, c2 = -1)
    // Actually for rows [1,1] and [1,2], we need to recover [1,0]
    // [1,0] = c1*[1,1] + c2*[1,2] => 1 = c1 + c2, 0 = c1 + 2*c2 => c1 = 2, c2 = -1

    // Let me just compute with simple coefficients that I know work
    // Use proper initialization with the pairing to get the order set
    ZP one = pairing.initZP();
    zml_bignum_setuint(one.m_ZP, 1);
    ZP neg_one = -one;
    ZP two = pairing.initZP();
    zml_bignum_setuint(two.m_ZP, 2);

    // For 2-of-2 threshold with LSSS matrix rows [1,1] and [1,2]:
    // secret vector = [s, r] where r is random blinding
    // share_A = 1*s + 1*r = s + r
    // share_B = 1*s + 2*r = s + 2r
    // Reconstruction: 2*(s+r) + (-1)*(s+2r) = 2s + 2r - s - 2r = s ✓
    ZP r = pairing.randomZP(&rng);
    printZP("r (LSSS blinding)", r);

    ZP share_A = s + r;        // s + r
    ZP share_B = s + two * r;  // s + 2r
    printZP("share_A (s + r)", share_A);
    printZP("share_B (s + 2r)", share_B);

    // Coefficients for reconstruction: 2*share_A + (-1)*share_B = s
    ZP coeff_A = two;        // 2
    ZP coeff_B = neg_one;    // -1
    printZP("coeff_A (2)", coeff_A);
    printZP("coeff_B (-1)", coeff_B);

    // Verify: 2*(s+r) + (-1)*(s+2r) = 2s + 2r - s - 2r = s

    // Random values for each attribute ciphertext component
    ZP r_A = pairing.randomZP(&rng);
    ZP r_B = pairing.randomZP(&rng);
    printZP("r_A (random for A)", r_A);
    printZP("r_B (random for B)", r_B);

    // C_attr = g1a^{share} * H(attr)^{-r}
    G1 C_A = g1a.exp(share_A) * H_A.exp(-r_A);
    G1 C_B = g1a.exp(share_B) * H_B.exp(-r_B);
    printG1("C_A = g1a^share_A * H(A)^{-r_A}", C_A);
    printG1("C_B = g1a^share_B * H(B)^{-r_B}", C_B);

    // D_attr = g2^r
    G2 D_A = g2.exp(r_A);
    G2 D_B = g2.exp(r_B);
    printG2("D_A = g2^r_A", D_A);
    printG2("D_B = g2^r_B", D_B);

    cout << "\n=== DECRYPTION ===" << endl;

    // prod1 = prod_{attr} C_attr^{coeff_attr}
    G1 prod1 = C_A.exp(coeff_A) * C_B.exp(coeff_B);
    printG1("prod1 = C_A^coeff_A * C_B^coeff_B", prod1);

    // prodT = prod_{attr} e(KX_attr^{coeff_attr}, D_attr)
    G1 KX_A_exp = KX_A.exp(coeff_A);
    G1 KX_B_exp = KX_B.exp(coeff_B);
    printG1("KX_A^coeff_A", KX_A_exp);
    printG1("KX_B^coeff_B", KX_B_exp);

    GT pair_A = pairing.pairing(KX_A_exp, D_A);
    GT pair_B = pairing.pairing(KX_B_exp, D_B);
    printGT("e(KX_A^coeff_A, D_A)", pair_A);
    printGT("e(KX_B^coeff_B, D_B)", pair_B);

    GT prodT = pair_A * pair_B;
    printGT("prodT = prod of pairings", prodT);

    // pairing1 = e(Cprime, K)
    GT pairing1 = pairing.pairing(Cprime, K);
    printGT("pairing1 = e(Cprime, K)", pairing1);

    // pairing2 = e(prod1, L)
    GT pairing2 = pairing.pairing(prod1, L);
    printGT("pairing2 = e(prod1, L)", pairing2);

    // denominator = prodT * pairing2
    GT denominator = prodT * pairing2;
    printGT("denominator = prodT * pairing2", denominator);

    // final = pairing1 / denominator
    GT final = pairing1 / denominator;
    printGT("final = pairing1 / denominator", final);

    cout << "\n=== VERIFICATION ===" << endl;

    // final should equal C (the encryption result)
    OpenABEByteString finalBytes;
    final.serialize(finalBytes);

    bool keysMatch = (CBytes == finalBytes);
    cout << "C == final: " << (keysMatch ? "TRUE (SUCCESS!)" : "FALSE (FAILURE!)") << endl;

    if (!keysMatch) {
        cout << "\nEncryption C: ";
        for (size_t i = 0; i < min(CBytes.size(), (size_t)64); i++) {
            printf("%02x", CBytes[i]);
        }
        cout << endl;

        cout << "Decryption final: ";
        for (size_t i = 0; i < min(finalBytes.size(), (size_t)64); i++) {
            printf("%02x", finalBytes[i]);
        }
        cout << endl;
    }

    ShutdownOpenABE();
    return keysMatch ? 0 : 1;
}
