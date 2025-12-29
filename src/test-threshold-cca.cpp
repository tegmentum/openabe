#include <iostream>
#include <string>
#include <openabe/openabe.h>

using namespace std;
using namespace oabe;

int main() {
    // Initialize OpenABE
    InitializeOpenABE();

    // Create CP-ABE context
    unique_ptr<OpenABECryptoContext> cpabe = OpenABE_createContextABESchemeCCA(OpenABE_SCHEME_CP_WATERS);

    // Generate parameters and keys
    cpabe->generateParams();

    // Create user key with attributes
    vector<string> attrs = {"one", "two", "three"};
    cpabe->keygen(attrs, "user");

    // Test policy
    string policy = "2 of (one, two, three)";
    string plaintext = "Test message";
    string ct1_str, ct2_str, recovered;

    // Encrypt
    cout << "Encrypting with policy: " << policy << endl;
    cpabe->encrypt(policy, plaintext, ct1_str);

    // Parse policy to get canonical form
    unique_ptr<OpenABEPolicy> pol = createPolicyTree(policy);
    string canonical1 = pol->toCanonicalString();
    cout << "Original canonical form: " << canonical1 << endl;

    // Decrypt (this will re-encrypt internally for CCA check)
    cout << "Decrypting..." << endl;
    bool result = cpabe->decrypt("user", ct1_str, recovered);

    if (result) {
        cout << "Decryption succeeded!" << endl;
        cout << "Recovered: " << recovered << endl;
    } else {
        cout << "Decryption failed!" << endl;
    }

    // Encrypt again to check if we get same canonical form
    cpabe->encrypt(canonical1, plaintext, ct2_str);
    unique_ptr<OpenABEPolicy> pol2 = createPolicyTree(canonical1);
    string canonical2 = pol2->toCanonicalString();
    cout << "Re-encrypted canonical form: " << canonical2 << endl;

    if (canonical1 == canonical2) {
        cout << "Canonical forms match!" << endl;
    } else {
        cout << "Canonical forms DIFFER!" << endl;
        cout << "  Original: '" << canonical1 << "'" << endl;
        cout << "  Re-encrypted: '" << canonical2 << "'" << endl;
    }

    ShutdownOpenABE();
    return 0;
}
