#include <iostream>
#include <openabe/openabe.h>

using namespace oabe;

int main() {
    InitializeOpenABE();
    
    std::cout << "Testing BLS12-381 initialization..." << std::endl;
    
    try {
        // Try to create a pairing group with BLS12-381
        std::shared_ptr<ZGroup> group;
        OpenABE_setGroupObject(group, OpenABE_BLS12_P381_ID);
        
        if (!group) {
            std::cerr << "Failed to create group!" << std::endl;
            return 1;
        }
        
        std::cout << "Group created successfully" << std::endl;
        std::cout << "Group order: " << group->getOrder() << std::endl;
        
        // Try to generate a random element
        std::cout << "Generating random G1 element..." << std::endl;
        ZP rand_zp = group->randomZP();
        std::cout << "Random ZP: " << rand_zp.toString() << std::endl;
        
        std::cout << "Generating random G1 element..." << std::endl;
        G1 g1 = group->randomG1();
        std::cout << "Random G1 generated" << std::endl;
        
        std::cout << "SUCCESS!" << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
        return 1;
    }
    
    ShutdownOpenABE();
    return 0;
}
