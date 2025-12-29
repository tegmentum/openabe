#include <iostream>
#include <openabe/openabe.h>

using namespace std;
using namespace oabe;

int main() {
    InitializeOpenABE();
    
    cout << "Creating PKE context..." << endl;
    unique_ptr<OpenABERNG> rng(new OpenABERNG);
    OpenABEContextPKE *kemContext = OpenABE_createContextPKE(&rng, OpenABE_SCHEME_PK_OPDH);
    
    if (!kemContext) {
        cerr << "Failed to create KEM context" << endl;
        return 1;
    }
    
    cout << "Calling generateParams..." << endl;
    OpenABE_ERROR err = kemContext->generateParams("NIST_P256");
    
    if (err != OpenABE_NOERROR) {
        cerr << "generateParams failed with error: " << err << endl;
        return 1;
    }
    
    cout << "SUCCESS: generateParams completed" << endl;
    
    cout << "Calling generateDecryptionKey..." << endl;
    err = kemContext->generateDecryptionKey("ID_A", "public_A", "private_A");
    
    if (err != OpenABE_NOERROR) {
        cerr << "generateDecryptionKey failed with error: " << err << endl;
        return 1;
    }
    
    cout << "SUCCESS: All tests passed!" << endl;
    
    delete kemContext;
    ShutdownOpenABE();
    return 0;
}
