#include <openabe/openabe.h>
#include <iostream>

using namespace oabe;

void printG1(const std::string& label, const G1& g1) {
    std::cout << label << ": ";
    OpenABEByteString bytes;
    g1.serialize(bytes);
    std::cout << bytes.toHex().substr(0, 32) << "..." << std::endl;
}

int main() {
    InitializeOpenABE();

    std::cout << "=== Testing MCL G1 Exponentiation Distributive Law ===" << std::endl;

    OpenABEPairing pairing(DEFAULT_BP_PARAM);
    OpenABERNG rng;

    // Generate random elements
    G1 A = pairing.randomG1(&rng);
    G1 B = pairing.randomG1(&rng);
    ZP x = pairing.randomZP(&rng);
    ZP y = pairing.randomZP(&rng);

    std::cout << "\n--- Test 1: (A * B)^x = A^x * B^x ---" << std::endl;
    G1 AB = A * B;
    G1 left1 = AB.exp(x);
    G1 Ax = A.exp(x);
    G1 Bx = B.exp(x);
    G1 right1 = Ax * Bx;
    printG1("(A * B)^x", left1);
    printG1("A^x * B^x", right1);
    std::cout << "Match: " << (left1 == right1 ? "YES ✓" : "NO ✗") << std::endl;

    std::cout << "\n--- Test 2: (A^x)^y = A^(x*y) ---" << std::endl;
    G1 Ax_exp_y = Ax.exp(y);
    ZP xy = x * y;
    G1 A_exp_xy = A.exp(xy);
    printG1("(A^x)^y", Ax_exp_y);
    printG1("A^(x*y)", A_exp_xy);
    std::cout << "Match: " << (Ax_exp_y == A_exp_xy ? "YES ✓" : "NO ✗") << std::endl;

    std::cout << "\n--- Test 3: A^(-x) with negative exponent ---" << std::endl;
    ZP zero = pairing.initZP();
    ZP neg_x = zero - x;  // Negative x
    G1 A_neg_x = A.exp(neg_x);
    G1 A_x = A.exp(x);
    G1 identity = A_x * A_neg_x;
    printG1("A^x", A_x);
    printG1("A^(-x)", A_neg_x);
    printG1("A^x * A^(-x) (should be identity)", identity);
    G1 expected_identity = pairing.initG1();
    std::cout << "Is identity: " << (identity == expected_identity ? "YES ✓" : "NO ✗") << std::endl;

    std::cout << "\n--- Test 4: Reproduce CP-ABE formula issue ---" << std::endl;
    // This replicates the exact pattern from CP-ABE
    G1 g1a = pairing.randomG1(&rng);
    G1 h_attr = pairing.randomG1(&rng);
    ZP lambda = pairing.randomZP(&rng);
    ZP r_i = pairing.randomZP(&rng);

    // Build C_attr = g1a^lambda * h^(-r_i)
    G1 g1a_lambda = g1a.exp(lambda);
    ZP zero2 = pairing.initZP();
    ZP neg_r_i = zero2 - r_i;
    G1 h_neg_r = h_attr.exp(neg_r_i);
    G1 C_attr = g1a_lambda * h_neg_r;

    // Compute w = 1/lambda
    ZP w = ZP(1) / lambda;

    // Method 1: C_attr^w
    G1 prod1_method1 = C_attr.exp(w);

    // Method 2: g1a^(lambda*w) * h^(-r_i*w) = g1a^1 * h^(-r_i*w) = g1a * h^(-r_i*w)
    ZP lambda_w = lambda * w;
    ZP neg_r_i_w = neg_r_i * w;
    G1 prod1_method2 = g1a.exp(lambda_w) * h_attr.exp(neg_r_i_w);

    // Method 3: g1a * h^(-r_i*w)  [assuming lambda*w = 1]
    G1 prod1_method3 = g1a * h_attr.exp(neg_r_i_w);

    printG1("Method 1: C_attr^w", prod1_method1);
    printG1("Method 2: g1a^(lambda*w) * h^(-r_i*w)", prod1_method2);
    printG1("Method 3: g1a * h^(-r_i*w)", prod1_method3);

    std::cout << "Method 1 == Method 2: " << (prod1_method1 == prod1_method2 ? "YES ✓" : "NO ✗") << std::endl;
    std::cout << "Method 1 == Method 3: " << (prod1_method1 == prod1_method3 ? "YES ✓" : "NO ✗") << std::endl;
    std::cout << "Method 2 == Method 3: " << (prod1_method2 == prod1_method3 ? "YES ✓" : "NO ✗") << std::endl;

    std::cout << "\nVerify lambda*w = 1:" << std::endl;
    std::cout << "lambda*w == 1: " << (lambda_w == ZP(1) ? "YES ✓" : "NO ✗") << std::endl;

    std::cout << "\n=== All Tests Complete ===" << std::endl;

    return 0;
}
