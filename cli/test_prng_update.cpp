#include <openabe/openabe.h>
#include <iostream>
#include <iomanip>

using namespace oabe;

int main() {
    // Initialize OpenABE
    InitializeOpenABE();

    // Create a simple CP-ABE context which will trigger PRNG usage
    std::unique_ptr<OpenABEContextABE> context = OpenABE_createContextABE(OpenABE_SCHEME_CP_WATERS);

    if (context == nullptr) {
        std::cerr << "Failed to create CP-ABE context" << std::endl;
        return 1;
    }

    // Generate parameters - this will use the PRNG and trigger update_internal
    context->generateParams("BLS12_381");

    // Generate a simple encryption which will trigger more PRNG calls
    std::string mpkID = "mpk_test";
    std::string mskID = "msk_test";
    context->keygen("|attr1|attr2", "key_test", "Alice", mskID);

    // Encrypt a simple message
    std::string plaintext = "Hello World";
    std::string policy = "(attr1 or attr2)";
    std::string ciphertext;
    context->encrypt(mpkID, policy, plaintext, ciphertext);

    std::cout << "Test completed successfully" << std::endl;

    ShutdownOpenABE();
    return 0;
}
