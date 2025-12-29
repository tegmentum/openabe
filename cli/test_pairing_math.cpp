/**
 * Minimal pairing bilinearity test for RABE backend
 * Tests: e(g1^a, g2^b) == e(g1, g2)^(ab)
 */

#include <iostream>
#include <string>
#include <openabe/openabe.h>

using namespace std;
using namespace oabe;

int main() {
    cout << "=== Pairing Bilinearity Test ===" << endl;

    InitializeOpenABE();

    // Create pairing group
    OpenABEPairing pairing("BLS12_P381");
    OpenABERNG rng;

    cout << "Pairing group created" << endl;

    // Get random generators
    G1 g1 = pairing.randomG1(&rng);
    G2 g2 = pairing.randomG2(&rng);

    cout << "Random generators created" << endl;

    // Create random scalars
    ZP a = pairing.randomZP(&rng);
    ZP b = pairing.randomZP(&rng);
    ZP ab = a * b;

    cout << "Random scalars a, b created" << endl;

    // Compute g1^a and g2^b
    G1 g1_a = g1.exp(a);
    G2 g2_b = g2.exp(b);

    cout << "Computed g1^a and g2^b" << endl;

    // Compute e(g1^a, g2^b)
    GT left = pairing.pairing(g1_a, g2_b);
    cout << "Computed e(g1^a, g2^b)" << endl;

    // Compute e(g1, g2)^(ab)
    GT egg = pairing.pairing(g1, g2);
    cout << "Computed e(g1, g2)" << endl;

    // Check if e(g1, g2) is identity
    bool eggIsIdentity = egg.isInfinity();
    cout << "e(g1, g2) is identity: " << (eggIsIdentity ? "TRUE (BAD!)" : "FALSE (Good)") << endl;

    GT right = egg.exp(ab);
    cout << "Computed e(g1, g2)^(ab)" << endl;

    // Serialize both for comparison
    OpenABEByteString leftBytes, rightBytes;
    left.serialize(leftBytes);
    right.serialize(rightBytes);

    // Check if they're equal
    bool isEqual = (leftBytes == rightBytes);

    cout << endl;
    cout << "=== RESULT ===" << endl;
    cout << "e(g1^a, g2^b) == e(g1, g2)^(ab): " << (isEqual ? "TRUE (Good)" : "FALSE (BAD!)") << endl;

    if (!isEqual) {
        cout << "Left GT (first 64 bytes): ";
        for (size_t i = 0; i < min(leftBytes.size(), (size_t)64); i++) {
            printf("%02x", leftBytes[i]);
        }
        cout << endl;

        cout << "Right GT (first 64 bytes): ";
        for (size_t i = 0; i < min(rightBytes.size(), (size_t)64); i++) {
            printf("%02x", rightBytes[i]);
        }
        cout << endl;
    }

    // Test: e(g1^a, g2) == e(g1, g2)^a
    cout << endl << "=== Simpler bilinearity test ===" << endl;
    GT left2 = pairing.pairing(g1_a, g2);
    GT right2 = egg.exp(a);
    OpenABEByteString left2Bytes, right2Bytes;
    left2.serialize(left2Bytes);
    right2.serialize(right2Bytes);
    bool isEqual2 = (left2Bytes == right2Bytes);
    cout << "e(g1^a, g2) == e(g1, g2)^a: " << (isEqual2 ? "TRUE (Good)" : "FALSE (BAD!)") << endl;

    // Test: e(g1, g2^b) == e(g1, g2)^b
    GT left3 = pairing.pairing(g1, g2_b);
    GT right3 = egg.exp(b);
    OpenABEByteString left3Bytes, right3Bytes;
    left3.serialize(left3Bytes);
    right3.serialize(right3Bytes);
    bool isEqual3 = (left3Bytes == right3Bytes);
    cout << "e(g1, g2^b) == e(g1, g2)^b: " << (isEqual3 ? "TRUE (Good)" : "FALSE (BAD!)") << endl;

    // Test GT division: (e(g1,g2) * e(g1,g2)) / e(g1,g2) == e(g1,g2)
    cout << endl << "=== GT division test ===" << endl;
    GT doubled = egg * egg;  // e(g1,g2)^2
    GT divided = doubled / egg;  // should be e(g1,g2)^1
    OpenABEByteString eggBytes, dividedBytes;
    egg.serialize(eggBytes);
    divided.serialize(dividedBytes);
    bool divEqual = (eggBytes == dividedBytes);
    cout << "(e * e) / e == e: " << (divEqual ? "TRUE (Good)" : "FALSE (BAD!)") << endl;

    // Test GT exponentiation vs repeated multiplication
    cout << endl << "=== GT exponentiation consistency ===" << endl;
    ZP two(2);
    GT exp_2 = egg.exp(two);
    OpenABEByteString exp2Bytes, doubledBytes;
    exp_2.serialize(exp2Bytes);
    doubled.serialize(doubledBytes);
    bool expEqual = (exp2Bytes == doubledBytes);
    cout << "e^2 (exp) == e * e: " << (expEqual ? "TRUE (Good)" : "FALSE (BAD!)") << endl;

    if (!expEqual) {
        cout << "e^2 (exp): ";
        for (size_t i = 0; i < min(exp2Bytes.size(), (size_t)64); i++) {
            printf("%02x", exp2Bytes[i]);
        }
        cout << endl;

        cout << "e * e:     ";
        for (size_t i = 0; i < min(doubledBytes.size(), (size_t)64); i++) {
            printf("%02x", doubledBytes[i]);
        }
        cout << endl;
    }

    ShutdownOpenABE();

    bool allPassed = isEqual && isEqual2 && isEqual3 && divEqual && expEqual;
    cout << endl << "=== ALL TESTS: " << (allPassed ? "PASSED" : "FAILED") << " ===" << endl;

    return allPassed ? 0 : 1;
}
