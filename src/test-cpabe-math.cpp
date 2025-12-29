// Manually verify Waters CP-ABE mathematics using OpenABE API
// This tests if the formula: final = e(Cprime, K) / (prodT * e(prod1, L))
// correctly recovers C when all components are computed correctly

#include <iostream>
#include <iomanip>
#include <openabe/openabe.h>

using namespace std;
using namespace oabe;

void printGT(const char* label, const GT& gt) {
    OpenABEByteString bs;
    gt.serialize(bs);
    cout << label << ": " << bs.toHex().substr(0, 32) << "..." << endl;
}

int main() {
    cout << "Testing Waters CP-ABE Formula Mathematics" << endl;
    cout << "=========================================" << endl;

    InitializeOpenABE();

    // Create pairing group
    auto group = make_shared<BPGroup>(BPGROUP_BN254);

    // Generate random values
    ZP alpha = group->randomZP();
    ZP a = group->randomZP();
    ZP s = group->randomZP();
    ZP t = group->randomZP();

    // Generate random G1, G2 generators
    G1 g1 = group->randomG1();
    G2 g2 = group->randomG2();

    cout << "\n=== Setup Phase ===" << endl;
    cout << "Generated random: alpha, a, s, t, g1, g2" << endl;

    // Public parameters
    G1 g1a = g1.exp(a);
    GT A = group->pairing(g1, g2).exp(alpha);

    // Encryption: C = A^s
    GT C = A.exp(s);
    printGT("C (should recover this)", C);

    // Ciphertext components for simple AND policy (attr1, attr2)
    // Shares are (s, s) for AND
    G1 Cprime = g1.exp(s);

    // For simplicity, use fixed r values (in real scheme they're random)
    ZP r1 = group->randomZP();
    ZP r2 = group->randomZP();

    // Hash to G1 for attributes (simplified)
    G1 H1 = group->randomG1();  // H(attr1)
    G1 H2 = group->randomG1();  // H(attr2)

    // Ciphertext components
    G1 C1 = g1a.exp(s) * H1.exp(-r1);  // g1a^s * H1^(-r1)
    G1 C2 = g1a.exp(s) * H2.exp(-r2);  // g1a^s * H2^(-r2)
    G2 D1 = g2.exp(r1);
    G2 D2 = g2.exp(r2);

    cout << "\n=== Encryption Complete ===" << endl;
    printGT("Encrypted C", C);

    // Key generation
    ZP alpha_plus_at = alpha + (a * t);
    G2 K = g2.exp(alpha_plus_at);  // K = g2^(alpha + at)
    G2 L = g2.exp(t);               // L = g2^t
    G1 KX1 = H1.exp(t);             // KX1 = H1^t
    G1 KX2 = H2.exp(t);             // KX2 = H2^t

    cout << "\n=== Key Generation Complete ===" << endl;

    // Decryption with coefficients (1, 1) for AND policy
    ZP coeff1(1);
    ZP coeff2(1);

    // prod1 = C1^coeff1 * C2^coeff2
    G1 prod1 = C1.exp(coeff1) * C2.exp(coeff2);

    // prodT = e(KX1^coeff1, D1) * e(KX2^coeff2, D2)
    GT e1 = group->pairing(KX1.exp(coeff1), D1);
    GT e2 = group->pairing(KX2.exp(coeff2), D2);
    GT prodT = e1 * e2;

    cout << "\n=== Decryption Formula ===" << endl;
    printGT("prodT", prodT);

    // Numerator: e(Cprime, K)
    GT numerator = group->pairing(Cprime, K);
    printGT("e(Cprime, K)", numerator);

    // Denominator component: e(prod1, L)
    GT e_prod1_L = group->pairing(prod1, L);
    printGT("e(prod1, L)", e_prod1_L);

    // Denominator: prodT * e(prod1, L)
    GT denominator = prodT * e_prod1_L;
    printGT("denominator", denominator);

    // Final: numerator / denominator
    GT final = numerator / denominator;
    printGT("final (decrypted)", final);

    cout << "\n=== Verification ===" << endl;
    if (C == final) {
        cout << "✓ SUCCESS: Decrypted GT equals original C!" << endl;
        cout << "✓ Waters CP-ABE formula is mathematically correct" << endl;

        ShutdownOpenABE();
        return 0;
    } else {
        cout << "✗ FAILURE: Decrypted GT does NOT equal original C!" << endl;
        cout << "✗ There is a bug in the formula or implementation" << endl;

        // Additional debugging
        cout << "\n=== Detailed Analysis ===" << endl;

        // Verify pairing bilinearity
        GT test1 = group->pairing(g1, g2);
        GT test2 = group->pairing(g1.exp(alpha), g2);
        GT test3 = test1.exp(alpha);

        if (test2 == test3) {
            cout << "✓ Pairing bilinearity verified: e(g1^alpha, g2) == e(g1, g2)^alpha" << endl;
        } else {
            cout << "✗ Pairing bilinearity FAILED!" << endl;
        }

        // Check if operations are reversible
        GT temp = C * denominator;
        if (temp == numerator) {
            cout << "✓ Division is consistent: C * denominator == numerator" << endl;
            cout << "  This means: final / denominator == numerator / denominator" << endl;
            cout << "  So the issue is NOT in GT division" << endl;
        } else {
            cout << "✗ Inconsistency detected!" << endl;
            printGT("C * denominator", temp);
            printGT("numerator (expected)", numerator);
        }

        ShutdownOpenABE();
        return 1;
    }
}
