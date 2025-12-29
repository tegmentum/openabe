///
/// OpenABE CBOR Cross-Platform Testing CLI
///
/// This CLI tool generates and verifies CBOR test vectors for cross-platform
/// compatibility testing between native and WASM builds.
///

#include <iostream>
#include <fstream>
#include <iomanip>
#include <vector>
#include <cstring>
#include <openabe/openabe.h>
#include <openabe/cbor/zcbor_wrapper.h>
#include <openabe/cbor/zcbor_group_elements.h>
#include <openabe/cbor/zcbor_attributes.h>
#include <openabe/cbor/zcbor_policy.h>

using namespace std;
using namespace oabe;
using namespace oabe::cbor;

// Command-line modes
enum class Mode {
    GENERATE,
    VERIFY,
    ROUNDTRIP,
    HELP
};

void printUsage(const char* prog) {
    cout << "OpenABE CBOR Cross-Platform Testing Tool\n";
    cout << "=========================================\n\n";
    cout << "Usage: " << prog << " <mode> [options]\n\n";
    cout << "Modes:\n";
    cout << "  generate <outfile>    Generate a random CBOR test vector\n";
    cout << "  verify <infile>       Verify CBOR round-trip from file\n";
    cout << "  roundtrip             Quick round-trip test (no file I/O)\n";
    cout << "  help                  Show this help message\n\n";
    cout << "Examples:\n";
    cout << "  " << prog << " generate g1.cbor\n";
    cout << "  " << prog << " verify g1.cbor\n";
    cout << "  " << prog << " roundtrip\n";
}

void printHex(const vector<uint8_t>& data, size_t max_bytes = 32) {
    for (size_t i = 0; i < min(data.size(), max_bytes); i++) {
        cout << hex << setw(2) << setfill('0') << static_cast<int>(data[i]);
        if (i < data.size() - 1) cout << " ";
    }
    if (data.size() > max_bytes) {
        cout << " ... (" << dec << data.size() << " bytes)";
    }
    cout << dec << endl;
}

bool writeFile(const string& filename, const vector<uint8_t>& data) {
    ofstream file(filename, ios::binary);
    if (!file) {
        cerr << "Error: Cannot write to file: " << filename << endl;
        return false;
    }
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
    file.close();
    return true;
}

bool readFile(const string& filename, vector<uint8_t>& data) {
    ifstream file(filename, ios::binary | ios::ate);
    if (!file) {
        cerr << "Error: Cannot read file: " << filename << endl;
        return false;
    }

    streamsize size = file.tellg();
    file.seekg(0, ios::beg);

    data.resize(size);
    if (!file.read(reinterpret_cast<char*>(data.data()), size)) {
        cerr << "Error: Failed to read file: " << filename << endl;
        return false;
    }
    file.close();
    return true;
}

int cmdGenerate(const string& filename) {
    cout << "Generating CBOR test vector...\n";

    InitializeOpenABE();

    try {
        OpenABEPairing pairing("BLS12_P381");
        OpenABERNG rng;

        // Generate random G1 element
        G1 g1 = pairing.randomG1(&rng);

        // Encode to CBOR
        GroupElementSerializer ge_ser(GEEncoding::IETF_COMPRESSED, Endianness::BIG);
        ZCBOREncoder encoder;
        ge_ser.encodeG1(encoder, g1);
        auto encoded = encoder.getEncoded();

        // Write to file
        if (!writeFile(filename, encoded)) {
            ShutdownOpenABE();
            return 1;
        }

        cout << "✓ Generated " << encoded.size() << " bytes\n";
        cout << "  Output: " << filename << "\n";
        cout << "  Data: ";
        printHex(encoded);

        ShutdownOpenABE();
        return 0;

    } catch (const exception& e) {
        cerr << "Error: " << e.what() << endl;
        ShutdownOpenABE();
        return 1;
    }
}

int cmdVerify(const string& filename) {
    cout << "Verifying CBOR test vector: " << filename << "\n";

    InitializeOpenABE();

    try {
        // Read file
        vector<uint8_t> original;
        if (!readFile(filename, original)) {
            ShutdownOpenABE();
            return 1;
        }

        cout << "✓ Read " << original.size() << " bytes\n";
        cout << "  Data: ";
        printHex(original);

        // Decode
        OpenABEPairing pairing("BLS12_P381");
        GroupElementSerializer ge_ser(GEEncoding::IETF_COMPRESSED, Endianness::BIG);

        ZCBORDecoder decoder(original);
        G1 g1 = pairing.initG1();
        ge_ser.decodeG1(decoder, g1, OpenABE_BLS12_P381_ID);

        cout << "✓ Decoded G1 element successfully\n";

        // Re-encode
        ZCBOREncoder encoder;
        ge_ser.encodeG1(encoder, g1);
        auto reencoded = encoder.getEncoded();

        cout << "✓ Re-encoded " << reencoded.size() << " bytes\n";

        // Verify bit-for-bit match
        if (original == reencoded) {
            cout << "✓ Round-trip verification PASSED\n";
            cout << "  Encoding is deterministic and lossless\n";
            ShutdownOpenABE();
            return 0;
        } else {
            cerr << "✗ Round-trip verification FAILED\n";
            cerr << "  Original and re-encoded data differ\n";
            ShutdownOpenABE();
            return 1;
        }

    } catch (const exception& e) {
        cerr << "Error: " << e.what() << endl;
        ShutdownOpenABE();
        return 1;
    }
}

int cmdRoundtrip() {
    cout << "Quick CBOR Round-Trip Test\n";
    cout << "===========================\n\n";

    InitializeOpenABE();

    int passed = 0;
    int failed = 0;

    try {
        OpenABEPairing pairing("BLS12_P381");
        OpenABERNG rng;
        GroupElementSerializer ge_ser(GEEncoding::IETF_COMPRESSED, Endianness::BIG);

        // Test 1: G1 element
        cout << "Test 1: G1 element round-trip\n";
        try {
            G1 g1 = pairing.randomG1(&rng);
            ZCBOREncoder enc1;
            ge_ser.encodeG1(enc1, g1);
            auto data1 = enc1.getEncoded();

            ZCBORDecoder dec1(data1);
            G1 g1_decoded = pairing.initG1();
            ge_ser.decodeG1(dec1, g1_decoded, OpenABE_BLS12_P381_ID);

            ZCBOREncoder enc2;
            ge_ser.encodeG1(enc2, g1_decoded);
            auto data2 = enc2.getEncoded();

            if (data1 == data2) {
                cout << "  ✓ PASSED (" << data1.size() << " bytes)\n";
                passed++;
            } else {
                cout << "  ✗ FAILED (data mismatch)\n";
                failed++;
            }
        } catch (const exception& e) {
            cout << "  ✗ FAILED (" << e.what() << ")\n";
            failed++;
        }

        // Test 2: Attribute
        cout << "\nTest 2: Attribute round-trip\n";
        try {
            AttributeValue attr;
            attr.type = AttributeType::STRING;
            attr.string_value = "test_attribute";

            AttributeSerializer attr_ser;
            ZCBOREncoder enc1;
            attr_ser.encodeAttribute(enc1, attr);
            auto data1 = enc1.getEncoded();

            ZCBORDecoder dec1(data1);
            AttributeValue attr_decoded = attr_ser.decodeAttribute(dec1);

            ZCBOREncoder enc2;
            attr_ser.encodeAttribute(enc2, attr_decoded);
            auto data2 = enc2.getEncoded();

            if (data1 == data2 && attr.string_value == attr_decoded.string_value) {
                cout << "  ✓ PASSED (" << data1.size() << " bytes)\n";
                passed++;
            } else {
                cout << "  ✗ FAILED (data mismatch)\n";
                failed++;
            }
        } catch (const exception& e) {
            cout << "  ✗ FAILED (" << e.what() << ")\n";
            failed++;
        }

        // Test 3: Policy
        cout << "\nTest 3: Policy round-trip\n";
        try {
            unique_ptr<OpenABEPolicy> policy(new OpenABEPolicy());
            unique_ptr<OpenABETreeNode> root(new OpenABETreeNode());
            root->setNodeType(GATE_TYPE_AND);

            unique_ptr<OpenABETreeNode> leaf1(new OpenABETreeNode());
            leaf1->setNodeType(GATE_TYPE_LEAF);
            leaf1->setLabel("attr1");

            unique_ptr<OpenABETreeNode> leaf2(new OpenABETreeNode());
            leaf2->setNodeType(GATE_TYPE_LEAF);
            leaf2->setLabel("attr2");

            root->addSubnode(leaf1.release());
            root->addSubnode(leaf2.release());
            policy->setRootNode(root.release());

            PolicySerializer pol_ser;
            ZCBOREncoder enc1;
            pol_ser.encodeBooleanAST(enc1, *policy);
            auto data1 = enc1.getEncoded();

            ZCBORDecoder dec1(data1);
            unique_ptr<OpenABEPolicy> policy_decoded = pol_ser.decodeBooleanAST(dec1);

            ZCBOREncoder enc2;
            pol_ser.encodeBooleanAST(enc2, *policy_decoded);
            auto data2 = enc2.getEncoded();

            if (data1 == data2) {
                cout << "  ✓ PASSED (" << data1.size() << " bytes)\n";
                passed++;
            } else {
                cout << "  ✗ FAILED (data mismatch)\n";
                failed++;
            }
        } catch (const exception& e) {
            cout << "  ✗ FAILED (" << e.what() << ")\n";
            failed++;
        }

        cout << "\n===========================\n";
        cout << "Results: " << passed << " passed, " << failed << " failed\n";

        ShutdownOpenABE();
        return (failed == 0) ? 0 : 1;

    } catch (const exception& e) {
        cerr << "Fatal error: " << e.what() << endl;
        ShutdownOpenABE();
        return 1;
    }
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printUsage(argv[0]);
        return 1;
    }

    string mode_str = argv[1];
    Mode mode = Mode::HELP;

    if (mode_str == "generate") mode = Mode::GENERATE;
    else if (mode_str == "verify") mode = Mode::VERIFY;
    else if (mode_str == "roundtrip") mode = Mode::ROUNDTRIP;
    else if (mode_str == "help" || mode_str == "--help" || mode_str == "-h") mode = Mode::HELP;
    else {
        cerr << "Error: Unknown mode '" << mode_str << "'\n\n";
        printUsage(argv[0]);
        return 1;
    }

    switch (mode) {
        case Mode::GENERATE:
            if (argc < 3) {
                cerr << "Error: generate requires output filename\n";
                printUsage(argv[0]);
                return 1;
            }
            return cmdGenerate(argv[2]);

        case Mode::VERIFY:
            if (argc < 3) {
                cerr << "Error: verify requires input filename\n";
                printUsage(argv[0]);
                return 1;
            }
            return cmdVerify(argv[2]);

        case Mode::ROUNDTRIP:
            return cmdRoundtrip();

        case Mode::HELP:
        default:
            printUsage(argv[0]);
            return 0;
    }
}
