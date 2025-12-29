#include <iostream>
#include <iomanip>
#include <openabe/openabe.h>

using namespace std;
using namespace oabe;

// Test GT element serialization with MCL 3.04
int main() {
    cout << "=== GT Serialization Test with MCL 3.04 ===" << endl;

    InitializeOpenABE();

    // Create pairing context
    shared_ptr<OpenABEPairing> pairing = OpenABE_createNewPairing(OpenABE_SCHEME_CP_WATERS);
    if (!pairing) {
        cerr << "Failed to create pairing" << endl;
        return 1;
    }

    // Create a deterministic GT element by computing a pairing
    // This ensures we get the same element every time
    G1 g1 = pairing->initG1();
    G2 g2 = pairing->initG2();
    GT gt1 = pairing->initGT();
    GT gt2 = pairing->initGT();

    // Create deterministic RNG for reproducibility
    OpenABERNG rng;
    uint8_t seed[32];
    for (int i = 0; i < 32; i++) seed[i] = i;
    rng.setSeed(seed, 32);

    // Generate deterministic g1 and g2 elements
    g1.setRandom(&rng);
    g2.setRandom(&rng);

    cout << "\nG1 element: " << g1 << endl;
    cout << "G2 element: " << g2 << endl;

    // Compute GT element via pairing
    gt1 = pairing->pairing(g1, g2);

    cout << "\nGT element from pairing: " << gt1 << endl;

    // Test 1: Serialize GT element (uncompressed)
    OpenABEByteString serialized1;
    gt1.disableCompression();
    gt1.serialize(serialized1);
    cout << "\n[TEST 1] GT serialized (uncompressed): " << endl;
    cout << "  Size: " << serialized1.size() << " bytes" << endl;
    cout << "  Hex (first 64 bytes): " << serialized1.toHex().substr(0, 128) << endl;

    // Test 2: Serialize GT element (compressed)
    OpenABEByteString serialized2;
    gt1.enableCompression();
    gt1.serialize(serialized2);
    cout << "\n[TEST 2] GT serialized (compressed): " << endl;
    cout << "  Size: " << serialized2.size() << " bytes" << endl;
    cout << "  Hex (first 64 bytes): " << serialized2.toHex().substr(0, 128) << endl;

    // Test 3: Deserialize and re-serialize to check round-trip
    GT gt_recovered = pairing->initGT();
    OpenABEByteString copy1 = serialized1;
    gt_recovered.deserialize(copy1);

    OpenABEByteString reserialized;
    gt_recovered.disableCompression();
    gt_recovered.serialize(reserialized);

    cout << "\n[TEST 3] Round-trip serialization:" << endl;
    cout << "  Original == Recovered: " << (gt1 == gt_recovered ? "YES" : "NO") << endl;
    cout << "  Original bytes == Reserialized bytes: " << (serialized1 == reserialized ? "YES" : "NO") << endl;

    if (serialized1 != reserialized) {
        cout << "  ERROR: Serialization not consistent!" << endl;
        cout << "  Original size: " << serialized1.size() << endl;
        cout << "  Reserialized size: " << reserialized.size() << endl;
    }

    // Test 4: Hash the GT element to get symmetric key (this is what OpenABE does)
    shared_ptr<OpenABESymKey> key1(new OpenABESymKey);
    shared_ptr<OpenABESymKey> key2(new OpenABESymKey);

    key1->hashToSymmetricKey(gt1, 32, HASH_FUNCTION_TYPE_SHA256);
    key2->hashToSymmetricKey(gt_recovered, 32, HASH_FUNCTION_TYPE_SHA256);

    cout << "\n[TEST 4] Symmetric key derivation:" << endl;
    cout << "  Key from original GT: " << key1->toString() << endl;
    cout << "  Key from recovered GT: " << key2->toString() << endl;
    cout << "  Keys match: " << (key1->toString() == key2->toString() ? "YES" : "NO") << endl;

    // Test 5: Multiple pairings (simulate CP-ABE decrypt operation)
    cout << "\n[TEST 5] Multiple pairings (like CP-ABE decrypt):" << endl;

    G1 g1_a = pairing->initG1();
    G2 g2_a = pairing->initG2();
    G1 g1_b = pairing->initG1();
    G2 g2_b = pairing->initG2();

    // Reset RNG with different seed
    for (int i = 0; i < 32; i++) seed[i] = i + 100;
    rng.setSeed(seed, 32);

    g1_a.setRandom(&rng);
    g2_a.setRandom(&rng);
    g1_b.setRandom(&rng);
    g2_b.setRandom(&rng);

    // Compute e(g1_a, g2_a) * e(g1_b, g2_b)
    GT gt_multi1 = pairing->pairing(g1_a, g2_a);
    GT gt_multi2 = pairing->pairing(g1_b, g2_b);
    GT gt_product = gt_multi1 * gt_multi2;

    cout << "  GT from multi-pairing: " << gt_product << endl;

    // Serialize and hash
    OpenABEByteString serialized_multi;
    gt_product.disableCompression();
    gt_product.serialize(serialized_multi);

    shared_ptr<OpenABESymKey> key_multi(new OpenABESymKey);
    key_multi->hashToSymmetricKey(gt_product, 32, HASH_FUNCTION_TYPE_SHA256);

    cout << "  Serialized size: " << serialized_multi.size() << " bytes" << endl;
    cout << "  Derived key: " << key_multi->toString() << endl;

    // Test 6: Check if GT identity element is handled correctly
    cout << "\n[TEST 6] GT identity element:" << endl;
    GT gt_identity = pairing->initGT();
    gt_identity.setIdentity();

    cout << "  Is identity: " << (gt_identity.isInfinity() ? "YES" : "NO") << endl;

    OpenABEByteString serialized_identity;
    gt_identity.disableCompression();
    gt_identity.serialize(serialized_identity);
    cout << "  Serialized size: " << serialized_identity.size() << " bytes" << endl;
    cout << "  Hex: " << serialized_identity.toHex().substr(0, 64) << endl;

    // Test 7: GT multiplication with identity
    GT gt_times_identity = gt1 * gt_identity;
    cout << "\n[TEST 7] GT * identity:" << endl;
    cout << "  gt1 == (gt1 * identity): " << (gt1 == gt_times_identity ? "YES" : "NO") << endl;

    if (gt1 != gt_times_identity) {
        cout << "  ERROR: GT * identity should equal GT!" << endl;

        OpenABEByteString ser_original, ser_product;
        gt1.disableCompression();
        gt1.serialize(ser_original);
        gt_times_identity.disableCompression();
        gt_times_identity.serialize(ser_product);

        cout << "  Original: " << ser_original.toHex().substr(0, 64) << endl;
        cout << "  Product:  " << ser_product.toHex().substr(0, 64) << endl;
    }

    cout << "\n=== Test Complete ===" << endl;

    ShutdownOpenABE();
    return 0;
}
