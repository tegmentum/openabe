#include <openabe/openabe.h>
#include <iostream>
#include <iomanip>

using namespace oabe;

void printGT(const std::string& label, const GT& gt) {
    std::cout << label << ": ";
    OpenABEByteString bytes;
    gt.serialize(bytes);
    std::cout << bytes.toHex().substr(0, 32) << "..." << std::endl;
}

int main() {
    InitializeOpenABE();

    std::cout << "=== Testing MCL Pairing Bilinearity ===" << std::endl;

    OpenABEPairing pairing(DEFAULT_BP_PARAM);
    OpenABERNG rng;

    // Generate random elements
    G1 g1 = pairing.randomG1(&rng);
    G2 g2 = pairing.randomG2(&rng);
    ZP a = pairing.randomZP(&rng);
    ZP b = pairing.randomZP(&rng);

    std::cout << "\nGenerated random elements g1, g2, a, b" << std::endl;

    // Test 1: e(g1^a, g2) = e(g1, g2)^a
    std::cout << "\n--- Test 1: e(g1^a, g2) = e(g1, g2)^a ---" << std::endl;
    G1 g1_a = g1.exp(a);
    GT left1 = pairing.pairing(g1_a, g2);
    GT eg1g2 = pairing.pairing(g1, g2);
    GT right1 = eg1g2.exp(a);
    printGT("e(g1^a, g2)", left1);
    printGT("e(g1, g2)^a", right1);
    std::cout << "Match: " << (left1 == right1 ? "YES ✓" : "NO ✗") << std::endl;

    // Test 2: e(g1, g2^b) = e(g1, g2)^b
    std::cout << "\n--- Test 2: e(g1, g2^b) = e(g1, g2)^b ---" << std::endl;
    G2 g2_b = g2.exp(b);
    GT left2 = pairing.pairing(g1, g2_b);
    GT right2 = eg1g2.exp(b);
    printGT("e(g1, g2^b)", left2);
    printGT("e(g1, g2)^b", right2);
    std::cout << "Match: " << (left2 == right2 ? "YES ✓" : "NO ✗") << std::endl;

    // Test 3: e(g1^a, g2^b) = e(g1, g2)^(a*b)
    std::cout << "\n--- Test 3: e(g1^a, g2^b) = e(g1, g2)^(a*b) ---" << std::endl;
    G2 g2b = g2.exp(b);
    GT left3 = pairing.pairing(g1_a, g2b);
    ZP ab = a * b;
    GT right3 = eg1g2.exp(ab);
    printGT("e(g1^a, g2^b)", left3);
    printGT("e(g1, g2)^(a*b)", right3);
    std::cout << "Match: " << (left3 == right3 ? "YES ✓" : "NO ✗") << std::endl;

    // Test 4: e(g1_1 * g1_2, g2) = e(g1_1, g2) * e(g1_2, g2)
    std::cout << "\n--- Test 4: e(g1_1 * g1_2, g2) = e(g1_1, g2) * e(g1_2, g2) ---" << std::endl;
    G1 g1_1 = pairing.randomG1(&rng);
    G1 g1_2 = pairing.randomG1(&rng);
    G1 g1_sum = g1_1 * g1_2;
    GT left4 = pairing.pairing(g1_sum, g2);
    GT e1 = pairing.pairing(g1_1, g2);
    GT e2 = pairing.pairing(g1_2, g2);
    GT right4 = e1 * e2;
    printGT("e(g1_1 * g1_2, g2)", left4);
    printGT("e(g1_1, g2) * e(g1_2, g2)", right4);
    std::cout << "Match: " << (left4 == right4 ? "YES ✓" : "NO ✗") << std::endl;

    // Test 5: e(g1, g2_1 * g2_2) = e(g1, g2_1) * e(g1, g2_2)
    std::cout << "\n--- Test 5: e(g1, g2_1 * g2_2) = e(g1, g2_1) * e(g1, g2_2) ---" << std::endl;
    G2 g2_1 = pairing.randomG2(&rng);
    G2 g2_2 = pairing.randomG2(&rng);
    G2 g2_sum = g2_1 * g2_2;
    GT left5 = pairing.pairing(g1, g2_sum);
    GT e1_5 = pairing.pairing(g1, g2_1);
    GT e2_5 = pairing.pairing(g1, g2_2);
    GT right5 = e1_5 * e2_5;
    printGT("e(g1, g2_1 * g2_2)", left5);
    printGT("e(g1, g2_1) * e(g1, g2_2)", right5);
    std::cout << "Match: " << (left5 == right5 ? "YES ✓" : "NO ✗") << std::endl;

    // Test 6: GT division/multiplication roundtrip
    std::cout << "\n--- Test 6: (a / b) * b = a ---" << std::endl;
    GT gt_a = pairing.pairing(g1_1, g2_1);
    GT gt_b = pairing.pairing(g1_2, g2_2);
    GT div_result = gt_a / gt_b;
    GT product = div_result * gt_b;
    printGT("a", gt_a);
    printGT("(a / b) * b", product);
    std::cout << "Match: " << (product == gt_a ? "YES ✓" : "NO ✗") << std::endl;

    // Test 8: Multi-pairing vs individual pairings
    std::cout << "\n--- Test 8: Multi-pairing vs manual multiplication ---" << std::endl;
    std::vector<G1> g1_vec;
    std::vector<G2> g2_vec;
    g1_vec.push_back(g1_1);
    g1_vec.push_back(g1_2);
    g2_vec.push_back(g2_1);
    g2_vec.push_back(g2_2);

    GT multi_result = pairing.initGT();
    pairing.multi_pairing(multi_result, g1_vec, g2_vec);

    GT manual_result = pairing.pairing(g1_vec[0], g2_vec[0]) * pairing.pairing(g1_vec[1], g2_vec[1]);

    printGT("Multi-pairing", multi_result);
    printGT("Manual product", manual_result);
    std::cout << "Match: " << (multi_result == manual_result ? "YES ✓" : "NO ✗") << std::endl;

    std::cout << "\n=== All Tests Complete ===" << std::endl;

    return 0;
}
