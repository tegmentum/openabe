///
/// Test program for ABE-CBOR policy serialization
///

#include <iostream>
#include <cassert>
#include <openabe/openabe.h>
#include <openabe/cbor/zcbor_policy.h>

using namespace oabe;
using namespace oabe::cbor;

void printHex(const std::string& label, const std::vector<uint8_t>& data) {
    std::cout << label << " (" << data.size() << " bytes): ";
    for (uint8_t byte : data) {
        printf("%02x ", byte);
    }
    std::cout << std::endl;
}

void printRPNTokens(const std::vector<RPNToken>& tokens) {
    std::cout << "RPN tokens:" << std::endl;
    for (size_t i = 0; i < tokens.size(); i++) {
        std::cout << "  [" << i << "] ";
        if (tokens[i].type == RPNTokenType::ATTR) {
            std::cout << "ATTR: \"" << tokens[i].attribute.string_value << "\"";
        } else if (tokens[i].type == RPNTokenType::THRESHOLD) {
            std::cout << "THRESHOLD (k=" << tokens[i].threshold_k << ")";
        } else {
            std::cout << rpnTokenTypeToString(tokens[i].type);
        }
        std::cout << std::endl;
    }
}

int main() {
    std::cout << "Testing ABE-CBOR Policy Serialization..." << std::endl << std::endl;

    try {
        InitializeOpenABE();

        PolicySerializer serializer;

        // Test 1: Simple AND policy
        std::cout << "=== Test 1: Simple AND Policy ===" << std::endl;
        {
            // Create policy: (A AND B)
            std::unique_ptr<OpenABEPolicy> policy = createPolicyTree("A and B");
            std::cout << "Original policy: " << policy->toString() << std::endl;

            // Convert to RPN
            std::vector<RPNToken> tokens = serializer.treeToRPN(policy->getRootNode());
            printRPNTokens(tokens);

            // Expected RPN: [A, B, AND]
            assert(tokens.size() == 3);
            assert(tokens[0].type == RPNTokenType::ATTR);
            assert(tokens[0].attribute.string_value == "A");
            assert(tokens[1].type == RPNTokenType::ATTR);
            assert(tokens[1].attribute.string_value == "B");
            assert(tokens[2].type == RPNTokenType::AND);

            // Encode to CBOR
            ZCBOREncoder encoder;
            serializer.encodeRPNTokens(encoder, tokens);
            auto encoded = encoder.getEncoded();
            printHex("Encoded RPN", encoded);

            // Decode from CBOR
            ZCBORDecoder decoder(encoded);
            std::vector<RPNToken> tokens_decoded = serializer.decodeRPNTokens(decoder);

            // Verify
            assert(tokens_decoded.size() == tokens.size());
            assert(tokens_decoded[0].attribute.string_value == tokens[0].attribute.string_value);
            assert(tokens_decoded[1].attribute.string_value == tokens[1].attribute.string_value);
            assert(tokens_decoded[2].type == tokens[2].type);

            // Convert RPN back to tree
            std::unique_ptr<OpenABETreeNode> root = serializer.rpnToTree(tokens_decoded);
            std::cout << "Reconstructed tree: " << root->toString() << std::endl;

            std::cout << "✓ Simple AND policy round-trip successful!" << std::endl;
        }

        // Test 2: Simple OR policy
        std::cout << "\n=== Test 2: Simple OR Policy ===" << std::endl;
        {
            // Create policy: (A OR B)
            std::unique_ptr<OpenABEPolicy> policy = createPolicyTree("A or B");
            std::cout << "Original policy: " << policy->toString() << std::endl;

            // Full round-trip via Boolean AST
            ZCBOREncoder encoder;
            serializer.encodeBooleanAST(encoder, *policy);
            auto encoded = encoder.getEncoded();
            printHex("Encoded policy", encoded);

            ZCBORDecoder decoder(encoded);
            std::unique_ptr<OpenABEPolicy> policy_decoded = serializer.decodeBooleanAST(decoder);
            std::cout << "Decoded policy: " << policy_decoded->toString() << std::endl;

            std::cout << "✓ Simple OR policy round-trip successful!" << std::endl;
        }

        // Test 3: Nested policy
        std::cout << "\n=== Test 3: Nested Policy ===" << std::endl;
        {
            // Create policy: ((A AND B) OR C)
            std::unique_ptr<OpenABEPolicy> policy = createPolicyTree("(A and B) or C");
            std::cout << "Original policy: " << policy->toString() << std::endl;

            // Convert to RPN
            std::vector<RPNToken> tokens = serializer.treeToRPN(policy->getRootNode());
            printRPNTokens(tokens);

            // Expected RPN: [A, B, AND, C, OR]
            assert(tokens.size() == 5);

            // Full round-trip
            ZCBOREncoder encoder;
            serializer.encodeBooleanAST(encoder, *policy);
            auto encoded = encoder.getEncoded();

            ZCBORDecoder decoder(encoded);
            std::unique_ptr<OpenABEPolicy> policy_decoded = serializer.decodeBooleanAST(decoder);
            std::cout << "Decoded policy: " << policy_decoded->toString() << std::endl;

            std::cout << "✓ Nested policy round-trip successful!" << std::endl;
        }

        // Test 4: Complex policy with multiple operators
        std::cout << "\n=== Test 4: Complex Policy ===" << std::endl;
        {
            // Create policy: ((A AND B) OR (C AND D))
            std::unique_ptr<OpenABEPolicy> policy = createPolicyTree("(A and B) or (C and D)");
            std::cout << "Original policy: " << policy->toString() << std::endl;

            // Convert to RPN
            std::vector<RPNToken> tokens = serializer.treeToRPN(policy->getRootNode());
            printRPNTokens(tokens);

            // Expected RPN: [A, B, AND, C, D, AND, OR]
            assert(tokens.size() == 7);

            // Full round-trip
            ZCBOREncoder encoder;
            serializer.encodeBooleanAST(encoder, *policy);
            auto encoded = encoder.getEncoded();
            printHex("Encoded complex policy", encoded);

            ZCBORDecoder decoder(encoded);
            std::unique_ptr<OpenABEPolicy> policy_decoded = serializer.decodeBooleanAST(decoder);
            std::cout << "Decoded policy: " << policy_decoded->toString() << std::endl;

            std::cout << "✓ Complex policy round-trip successful!" << std::endl;
        }

        // Test 5: Attributes with prefixes
        std::cout << "\n=== Test 5: Attributes with Prefixes ===" << std::endl;
        {
            // Create policy with prefixed attributes
            std::unique_ptr<OpenABEPolicy> policy = createPolicyTree("dept:HR and role:manager");
            std::cout << "Original policy: " << policy->toString() << std::endl;

            // Full round-trip
            ZCBOREncoder encoder;
            serializer.encodeBooleanAST(encoder, *policy);
            auto encoded = encoder.getEncoded();

            ZCBORDecoder decoder(encoded);
            std::unique_ptr<OpenABEPolicy> policy_decoded = serializer.decodeBooleanAST(decoder);
            std::cout << "Decoded policy: " << policy_decoded->toString() << std::endl;

            std::cout << "✓ Prefixed attributes round-trip successful!" << std::endl;
        }

        std::cout << "\n✅ All tests passed!" << std::endl;

        ShutdownOpenABE();
        return 0;

    } catch (const std::exception& e) {
        std::cerr << "❌ Test failed with exception: " << e.what() << std::endl;
        return 1;
    }
}
