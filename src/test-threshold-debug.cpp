#include <iostream>
#include <string>
#include <cassert>
#include <openabe/openabe.h>
#include <openabe/zsymcrypto.h>

using namespace std;
using namespace oabe;
using namespace oabe::crypto;

// Custom RNG wrapper to log all calls
class DebugRNG : public OpenABERNG {
private:
    unique_ptr<OpenABERNG> m_inner;
    int m_call_count;
    string m_label;

public:
    DebugRNG(unique_ptr<OpenABERNG> inner, const string& label)
        : m_inner(std::move(inner)), m_call_count(0), m_label(label) {}

    void setSeed(OpenABEByteString& seed) override {
        fprintf(stderr, "[%s] setSeed called\n", m_label.c_str());
        m_inner->setSeed(seed);
        m_call_count = 0;  // Reset counter when seed is set
    }

    void getRandomBytes(OpenABEByteString *byteString, uint32_t length) override {
        m_call_count++;
        fprintf(stderr, "[%s] getRandomBytes #%d: length=%u\n", m_label.c_str(), m_call_count, length);
        m_inner->getRandomBytes(byteString, length);
        // Print first 8 bytes for debugging
        if (byteString->size() >= 8) {
            fprintf(stderr, "[%s]   First 8 bytes: %02x %02x %02x %02x %02x %02x %02x %02x\n",
                    m_label.c_str(),
                    (*byteString)[0], (*byteString)[1], (*byteString)[2], (*byteString)[3],
                    (*byteString)[4], (*byteString)[5], (*byteString)[6], (*byteString)[7]);
        }
    }

    uint8_t *getRandomBytes(uint32_t length) override {
        m_call_count++;
        fprintf(stderr, "[%s] getRandomBytes #%d: length=%u (raw)\n", m_label.c_str(), m_call_count, length);
        return m_inner->getRandomBytes(length);
    }
};

int main() {
    try {
        // Initialize OpenABE
        InitializeOpenABE();

        // We'll manually implement a simplified CCA encryption/decryption
        // to see what's happening

        // Create CP-ABE context (non-CCA first)
        unique_ptr<OpenABEContextSchemeCPWaters> cpabe(new OpenABEContextSchemeCPWaters());

        // Generate parameters
        OpenABERNG *setupRNG = new OpenABECTR_DRBG();
        cpabe->generateParams("default", setupRNG);
        delete setupRNG;

        // Generate user key
        vector<string> attrs = {"one", "two", "three"};
        OpenABEAttributeList attrList;
        for (const auto& attr : attrs) {
            attrList.addAttribute(attr);
        }
        OpenABERNG *keygenRNG = new OpenABECTR_DRBG();
        cpabe->keygen(keygenRNG, "default", "user", &attrList);
        delete keygenRNG;

        // Create policy
        string policy_str = "2 of (one, two, three)";
        unique_ptr<OpenABEPolicy> policy = createPolicyTree(policy_str);
        policy->canonicalize();
        string canonical = policy->toCanonicalString();
        fprintf(stderr, "\n=== Policy ===\n");
        fprintf(stderr, "Input: %s\n", policy_str.c_str());
        fprintf(stderr, "Canonical: %s\n", canonical.c_str());

        // Simulate CCA encryption
        fprintf(stderr, "\n=== First Encryption ===\n");

        // Create deterministic RNG from a fixed seed
        OpenABEByteString seed;
        seed.fromHex("0123456789ABCDEF0123456789ABCDEF");
        unique_ptr<OpenABERNG> rng1(new OpenABECTR_DRBG());
        rng1->setSeed(seed);

        // Wrap in debug RNG
        unique_ptr<OpenABERNG> debugRNG1(new DebugRNG(std::move(rng1), "ENC1"));

        // Encrypt
        unique_ptr<OpenABECiphertext> ct1(new OpenABECiphertext());
        unique_ptr<OpenABESymKey> key1(new OpenABESymKey());
        OpenABE_ERROR result = cpabe->encryptKEM(debugRNG1.get(), "default", policy.get(), 32, key1.get(), ct1.get());
        assert(result == OpenABE_NOERROR);

        // Second encryption with same seed
        fprintf(stderr, "\n=== Second Encryption (Re-encryption) ===\n");

        unique_ptr<OpenABERNG> rng2(new OpenABECTR_DRBG());
        rng2->setSeed(seed);
        unique_ptr<OpenABERNG> debugRNG2(new DebugRNG(std::move(rng2), "ENC2"));

        unique_ptr<OpenABECiphertext> ct2(new OpenABECiphertext());
        unique_ptr<OpenABESymKey> key2(new OpenABESymKey());
        result = cpabe->encryptKEM(debugRNG2.get(), "default", policy.get(), 32, key2.get(), ct2.get());
        assert(result == OpenABE_NOERROR);

        // Compare ciphertexts
        fprintf(stderr, "\n=== Comparison ===\n");
        if (*ct1 == *ct2) {
            fprintf(stderr, "SUCCESS: Ciphertexts match!\n");
        } else {
            fprintf(stderr, "FAILURE: Ciphertexts differ!\n");

            // Print components
            vector<string> keys1 = ct1->getKeys();
            vector<string> keys2 = ct2->getKeys();

            fprintf(stderr, "\nCT1 components: ");
            for (const auto& k : keys1) {
                fprintf(stderr, "%s ", k.c_str());
            }
            fprintf(stderr, "\n");

            fprintf(stderr, "CT2 components: ");
            for (const auto& k : keys2) {
                fprintf(stderr, "%s ", k.c_str());
            }
            fprintf(stderr, "\n");
        }

        ShutdownOpenABE();
        return 0;

    } catch (exception& e) {
        cerr << "Exception: " << e.what() << endl;
        return 1;
    }
}
