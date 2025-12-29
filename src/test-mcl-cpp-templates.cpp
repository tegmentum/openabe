///
/// \file   test-mcl-cpp-templates.cpp
///
/// \brief  Test if MCL's C++ template API compiles to WebAssembly
///
/// This is a minimal test to verify that MCL's C++ templates can be
/// instantiated and compiled with wasi-sdk/emscripten for WebAssembly.
///
/// If this compiles successfully, we can eliminate all the C API wrapper
/// macros in zelement.h and use MCL's native C++ API directly.
///

#include <iostream>
#include <mcl/bls12_381.hpp>  // Use BLS12-381 specific header

using namespace mcl::bls12;

// Initialize MCL for BLS12-381
void initMCL() {
    initPairing(mcl::BLS12_381);
    std::cout << "MCL initialized for BLS12-381" << std::endl;
}

// Test basic Fr (scalar field) operations using C++ API
bool testFrOperations() {
    std::cout << "Testing Fr (scalar field) operations..." << std::endl;

    // Create Fr elements using C++ classes (no C API wrappers!)
    Fr a, b, c;

    // Set values using setStr (MCL's method)
    a.setStr("5");
    b.setStr("3");

    // Test addition using C++ operator (no macro!)
    c = a + b;
    std::cout << "  5 + 3 = " << c.getStr() << std::endl;

    // Test multiplication using C++ operator (no macro!)
    c = a * b;
    std::cout << "  5 * 3 = " << c.getStr() << std::endl;

    // Test subtraction
    c = a - b;
    std::cout << "  5 - 3 = " << c.getStr() << std::endl;

    // Test division using C++ operator (no macro!)
    c = a / b;
    std::cout << "  5 / 3 = " << c.getStr() << std::endl;

    return true;
}

// Test G1 (group element) operations using C++ API
bool testG1Operations() {
    std::cout << "Testing G1 (group element) operations..." << std::endl;

    // Create G1 elements using C++ classes
    G1 P, Q, R;
    Fr scalar;

    // Hash to G1 point
    hashAndMapToG1(P, "test_point");

    // Scalar multiplication using static method
    scalar.setStr("5");
    G1::mul(Q, P, scalar);  // Q = P * scalar

    std::cout << "  P * 5 computed successfully" << std::endl;

    // Point addition using C++ operator
    R = P + Q;  // No macro needed!

    std::cout << "  P + Q computed successfully" << std::endl;

    return true;
}

// Test pairing operations using C++ API
bool testPairingOperations() {
    std::cout << "Testing pairing operations..." << std::endl;

    G1 P;
    G2 Q;
    GT e;

    // Hash to groups
    hashAndMapToG1(P, "test_g1");
    hashAndMapToG2(Q, "test_g2");

    // Compute pairing using C++ function
    pairing(e, P, Q);

    std::cout << "  Pairing computed successfully" << std::endl;

    return true;
}

int main() {
    std::cout << "MCL C++ Template API Test for WebAssembly" << std::endl;
    std::cout << "==========================================" << std::endl;

    // Initialize MCL
    initMCL();
    std::cout << std::endl;

    // Run tests
    if (!testFrOperations()) {
        std::cerr << "Fr operations test failed!" << std::endl;
        return 1;
    }
    std::cout << std::endl;

    if (!testG1Operations()) {
        std::cerr << "G1 operations test failed!" << std::endl;
        return 1;
    }
    std::cout << std::endl;

    if (!testPairingOperations()) {
        std::cerr << "Pairing operations test failed!" << std::endl;
        return 1;
    }
    std::cout << std::endl;

    std::cout << "==========================================" << std::endl;
    std::cout << "SUCCESS: All C++ template operations work!" << std::endl;
    std::cout << "This means we CAN use MCL's C++ API and eliminate wrapper macros!" << std::endl;

    return 0;
}
