#include <openabe/openabe.h>
#include <iostream>

using namespace oabe;

int main() {
    InitializeOpenABE();
    
    std::cout << "Testing BLS12-381 curve initialization..." << std::endl;
    
    // Try to initialize BLS12-381
    OpenABECurveID curveID = OpenABE_convertStringToCurveID("BLS12_381");
    std::cout << "Curve ID: " << (int)curveID << std::endl;
    
    // Try to create a pairing group
    std::shared_ptr<ZGroup> group = nullptr;
    OpenABE_setGroupObject(group, curveID);
    
    if (group) {
        std::cout << "Group created successfully!" << std::endl;
    } else {
        std::cout << "Failed to create group!" << std::endl;
    }
    
    ShutdownOpenABE();
    return 0;
}
