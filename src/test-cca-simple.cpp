#include <stdio.h>
#include <memory>
#include <openabe/openabe.h>

using namespace oabe;
using namespace std;

int main() {
    try {
        InitializeOpenABE();
        fprintf(stderr, "[TEST] OpenABE initialized\n");

        // Create CP-ABE context with CCA security
        unique_ptr<OpenABEContextSchemeCCA> ccaContext = OpenABE_createContextABESchemeCCA(OpenABE_SCHEME_CP_WATERS_CCA);
        fprintf(stderr, "[TEST] CCA context created\n");

        // Generate parameters for BLS12-381
        ccaContext->generateParams("BLS12_381", "mpk", "msk");
        fprintf(stderr, "[TEST] Parameters generated\n");

        // Generate a key for attributes "|one|two|three|"
        OpenABEAttributeList attrList;
        attrList.addAttribute("one");
        attrList.addAttribute("two");
        attrList.addAttribute("three");
        ccaContext->keygen(&attrList, "key1", "mpk", "msk");

        // Create a policy "(one and two) or three"
        string policy = "(one and two) or three";
        unique_ptr<OpenABEFunctionInput> funcInput = createPolicyTree(policy);

        // Create ciphertexts
        unique_ptr<OpenABECiphertext> ct1(new OpenABECiphertext);
        unique_ptr<OpenABECiphertext> ct2(new OpenABECiphertext);

        // Encrypt a message
        string plaintext = "Hello, World!";
        fprintf(stderr, "[TEST] Encrypting message: %s\n", plaintext.c_str());
        OpenABE_ERROR result = ccaContext->encrypt("mpk", funcInput.get(), plaintext, ct1.get(), ct2.get());
        if (result != OpenABE_NOERROR) {
            fprintf(stderr, "[TEST] FAILURE: Encryption failed with error %d\n", result);
            ShutdownOpenABE();
            return 1;
        }
        fprintf(stderr, "[TEST] Encryption successful\n");

        // Decrypt the message
        string decrypted;
        result = ccaContext->decrypt("mpk", "key1", decrypted, ct1.get(), ct2.get());
        if (result != OpenABE_NOERROR) {
            fprintf(stderr, "[TEST] FAILURE: Decryption failed with error %d\n", result);
            fprintf(stderr, "[TEST] Error string: %s\n", OpenABE_errorToString(result));
            ShutdownOpenABE();
            return 1;
        }

        fprintf(stderr, "[TEST] Decryption successful\n");
        fprintf(stderr, "[TEST] Decrypted message: %s\n", decrypted.c_str());

        if (decrypted == plaintext) {
            fprintf(stderr, "[TEST] SUCCESS: Plaintext matches!\n");
        } else {
            fprintf(stderr, "[TEST] FAILURE: Plaintext mismatch!\n");
            fprintf(stderr, "[TEST] Expected: %s\n", plaintext.c_str());
            fprintf(stderr, "[TEST] Got: %s\n", decrypted.c_str());
            ShutdownOpenABE();
            return 1;
        }

        fprintf(stderr, "[TEST] ALL TESTS PASSED!\n");
        ShutdownOpenABE();
        return 0;
    } catch (OpenABE_ERROR& error) {
        fprintf(stderr, "[TEST] CAUGHT OpenABE_ERROR: %d (%s)\n", error, OpenABE_errorToString(error));
        ShutdownOpenABE();
        return 1;
    } catch (...) {
        fprintf(stderr, "[TEST] CAUGHT unknown exception\n");
        ShutdownOpenABE();
        return 1;
    }
}
