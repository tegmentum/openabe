#include <openabe/openabe.h>
#include <iostream>

using namespace oabe;

void printGT(const std::string& label, const GT& gt) {
    std::cout << label << ": ";
    OpenABEByteString bytes;
    gt.serialize(bytes);
    std::cout << bytes.toHex().substr(0, 32) << "..." << std::endl;
}

int main() {
    InitializeOpenABE();

    std::cout << "=== Testing CP-ABE Formula with MCL ===" << std::endl;

    OpenABEPairing pairing(DEFAULT_BP_PARAM);
    OpenABERNG rng;

    // Simulate CP-ABE setup
    std::cout << "\n--- Setup Phase ---" << std::endl;
    G1 g1 = pairing.randomG1(&rng);
    G2 g2 = pairing.randomG2(&rng);
    ZP alpha = pairing.randomZP(&rng);
    ZP a = pairing.randomZP(&rng);

    G1 g1a = g1.exp(a);
    G2 g2a = g2.exp(a);
    GT A = pairing.pairing(g1, g2).exp(alpha);

    std::cout << "Generated g1, g2, alpha, a" << std::endl;
    printGT("A = e(g1,g2)^alpha", A);

    // Simulate key generation
    std::cout << "\n--- Key Generation Phase ---" << std::endl;
    ZP t = pairing.randomZP(&rng);
    G2 K = g2.exp(alpha) * g2a.exp(t);
    G2 L = g2.exp(t);

    // For one attribute
    OpenABEByteString attr_bytes;
    attr_bytes.fromHex("6F6E65"); // "one"
    G1 h_attr = pairing.hashToG1(attr_bytes, "");
    G1 KX = h_attr.exp(t);

    std::cout << "Generated key with t" << std::endl;

    // Simulate encryption
    std::cout << "\n--- Encryption Phase ---" << std::endl;
    ZP s = pairing.randomZP(&rng);
    GT C = A.exp(s);
    G1 Cprime = g1.exp(s);

    // For the attribute in the policy
    ZP lambda = pairing.randomZP(&rng);  // LSSS share
    ZP r_i = pairing.randomZP(&rng);
    G1 C_attr = g1a.exp(lambda) * h_attr.exp(-r_i);  // h^(-r_i)
    G2 D_attr = g2.exp(r_i);

    std::cout << "Encrypted with s, lambda, r_i" << std::endl;
    printGT("C (encrypted GT)", C);

    // Simulate decryption
    std::cout << "\n--- Decryption Phase ---" << std::endl;

    // LSSS recovery: for single attribute, coefficient w = 1/lambda
    ZP w = ZP(1) / lambda;

    std::cout << "LSSS coefficient w = 1/lambda" << std::endl;

    // Compute prod1 = C_attr^w
    G1 prod1 = C_attr.exp(w);
    std::cout << "Computed prod1 = C_attr^w" << std::endl;

    // Compute prodT = e(KX^w, D_attr)
    G1 KX_w = KX.exp(w);
    GT prodT = pairing.pairing(KX_w, D_attr);
    printGT("prodT = e(KX^w, D)", prodT);

    // Compute e(Cprime, K)
    GT e_Cprime_K = pairing.pairing(Cprime, K);
    printGT("e(Cprime, K)", e_Cprime_K);

    // Compute e(prod1, L)
    GT e_prod1_L = pairing.pairing(prod1, L);
    printGT("e(prod1, L)", e_prod1_L);

    // Compute denominator
    GT denominator = prodT * e_prod1_L;
    printGT("denominator = prodT * e(prod1, L)", denominator);

    // Compute final
    GT final = e_Cprime_K / denominator;
    printGT("final = e(Cprime,K) / denom", final);

    std::cout << "\n--- Verification ---" << std::endl;
    std::cout << "Encrypted C and decrypted final should match:" << std::endl;
    printGT("C (from encryption)", C);
    printGT("final (from decryption)", final);
    std::cout << "Match: " << (C == final ? "YES ✓" : "NO ✗") << std::endl;

    // Let's manually verify the math
    std::cout << "\n--- Manual Verification ---" << std::endl;

    // e(Cprime, K) = e(g1^s, g2^alpha * g2a^t)
    //              = e(g1, g2)^(s*alpha) * e(g1, g2)^(s*a*t)
    //              = e(g1, g2)^(s*(alpha + a*t))
    GT manual_eCK = pairing.pairing(g1, g2).exp(s * (alpha + a * t));
    printGT("Manual e(Cprime,K)", manual_eCK);
    printGT("Actual e(Cprime,K)", e_Cprime_K);
    std::cout << "Match: " << (manual_eCK == e_Cprime_K ? "YES ✓" : "NO ✗") << std::endl;

    // prodT = e(KX^w, D) = e(h^(t*w), g2^r)
    //       = e(h, g2)^(t*w*r)
    GT manual_prodT = pairing.pairing(h_attr, g2).exp(t * w * r_i);
    printGT("Manual prodT", manual_prodT);
    printGT("Actual prodT", prodT);
    std::cout << "Match: " << (manual_prodT == prodT ? "YES ✓" : "NO ✗") << std::endl;

    // prod1 = C_attr^w = (g1a^lambda * h^(-r))^w
    //       = g1^(a*lambda*w) * h^(-r*w)
    //       = g1^a * h^(-r*w)  [since lambda*w = 1]
    G1 manual_prod1 = g1a * h_attr.exp(-(r_i * w));
    std::cout << "Manual prod1 matches actual: " << (manual_prod1 == prod1 ? "YES ✓" : "NO ✗") << std::endl;

    // e(prod1, L) = e(g1^a * h^(-r*w), g2^t)
    //             = e(g1^a, g2^t) * e(h^(-r*w), g2^t)
    //             = e(g1, g2)^(a*t) * e(h, g2)^(-r*w*t)
    GT manual_epL_part1 = pairing.pairing(g1, g2).exp(a * t);
    GT manual_epL_part2 = pairing.pairing(h_attr, g2).exp(r_i * w * t);
    GT manual_epL = manual_epL_part1 / manual_epL_part2;  // Division is inverse in GT
    printGT("Manual e(prod1,L)", manual_epL);
    printGT("Actual e(prod1,L)", e_prod1_L);
    std::cout << "Match: " << (manual_epL == e_prod1_L ? "YES ✓" : "NO ✗") << std::endl;

    // denominator = prodT * e(prod1, L)
    //             = e(h, g2)^(t*w*r) * [e(g1,g2)^(a*t) * e(h,g2)^(-r*w*t)]
    //             = e(g1,g2)^(a*t) * e(h,g2)^(t*w*r) * e(h,g2)^(-r*w*t)
    //             = e(g1,g2)^(a*t) * e(h,g2)^0
    //             = e(g1,g2)^(a*t)
    GT manual_denom = pairing.pairing(g1, g2).exp(a * t);
    printGT("Manual denominator", manual_denom);
    printGT("Actual denominator", denominator);
    std::cout << "Match: " << (manual_denom == denominator ? "YES ✓" : "NO ✗") << std::endl;

    // final = e(Cprime, K) / denominator
    //       = e(g1,g2)^(s*(alpha + a*t)) / e(g1,g2)^(a*t)
    //       = e(g1,g2)^(s*alpha + s*a*t - a*t)
    //       = e(g1,g2)^(s*alpha)  [only if s*a*t - a*t = 0, which is NOT true!]

    std::cout << "\n=== Mathematical Analysis ===" << std::endl;
    std::cout << "The formula assumes s*a*t - a*t = 0" << std::endl;
    std::cout << "This requires s = 1, which is NOT the case!" << std::endl;
    std::cout << "There's a fundamental issue with the decryption formula!" << std::endl;

    return 0;
}
