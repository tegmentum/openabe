/// Test to compare MCL C API vs C++ API initialization
/// to see if they produce identical cryptographic operations

#include <iostream>
#include <iomanip>
#include <cstring>
#include <mcl/bn.h>
#include <mcl/bn.hpp>

void print_hex(const char* label, const uint8_t* data, size_t len) {
    std::cout << label << ": ";
    for (size_t i = 0; i < len && i < 32; i++) {
        std::cout << std::hex << std::setfill('0') << std::setw(2) << (int)data[i];
    }
    if (len > 32) std::cout << "...";
    std::cout << std::dec << std::endl;
}

int main() {
    std::cout << "=== MCL Initialization Comparison Test ===" << std::endl;

    // Test 1: C++ API initialization
    std::cout << "\n--- Test 1: C++ API (mcl::bn::initPairing) ---" << std::endl;
    mcl::bn::initPairing(mcl::BLS12_381);
    mclBn_setETHserialization(0);

    mclBnG1 g1_cpp;
    mclBnG2 g2_cpp;
    mclBnGT gt_cpp;
    mclBnFr scalar_cpp;

    // Set to generator
    mclBnG1_hashAndMapTo(&g1_cpp, "test", 4);
    mclBnG2_hashAndMapTo(&g2_cpp, "test", 4);
    mclBn_pairing(&gt_cpp, &g1_cpp, &g2_cpp);
    mclBnFr_setInt(&scalar_cpp, 42);

    // Serialize
    uint8_t g1_buf_cpp[128], g2_buf_cpp[256], gt_buf_cpp[576];
    size_t g1_len_cpp = mclBnG1_serialize(g1_buf_cpp, sizeof(g1_buf_cpp), &g1_cpp);
    size_t g2_len_cpp = mclBnG2_serialize(g2_buf_cpp, sizeof(g2_buf_cpp), &g2_cpp);
    size_t gt_len_cpp = mclBnGT_serialize(gt_buf_cpp, sizeof(gt_buf_cpp), &gt_cpp);

    print_hex("G1 (C++)", g1_buf_cpp, g1_len_cpp);
    print_hex("G2 (C++)", g2_buf_cpp, g2_len_cpp);
    print_hex("GT (C++)", gt_buf_cpp, gt_len_cpp);
    std::cout << "G1 len: " << g1_len_cpp << ", G2 len: " << g2_len_cpp << ", GT len: " << gt_len_cpp << std::endl;

    // Test 2: C API initialization (reinitialize)
    std::cout << "\n--- Test 2: C API (mclBn_init) ---" << std::endl;
    int ret = mclBn_init(mclBls12_CurveFp381, 46);  // BLS12-381: FR=256bit(4units), FP=384bit(6units)
    if (ret != 0) {
        std::cerr << "C API initialization failed!" << std::endl;
        return 1;
    }
    mclBn_setETHserialization(0);

    mclBnG1 g1_c;
    mclBnG2 g2_c;
    mclBnGT gt_c;
    mclBnFr scalar_c;

    // Set to same generator
    mclBnG1_hashAndMapTo(&g1_c, "test", 4);
    mclBnG2_hashAndMapTo(&g2_c, "test", 4);
    mclBn_pairing(&gt_c, &g1_c, &g2_c);
    mclBnFr_setInt(&scalar_c, 42);

    // Serialize
    uint8_t g1_buf_c[128], g2_buf_c[256], gt_buf_c[576];
    size_t g1_len_c = mclBnG1_serialize(g1_buf_c, sizeof(g1_buf_c), &g1_c);
    size_t g2_len_c = mclBnG2_serialize(g2_buf_c, sizeof(g2_buf_c), &g2_c);
    size_t gt_len_c = mclBnGT_serialize(gt_buf_c, sizeof(gt_buf_c), &gt_c);

    print_hex("G1 (C)  ", g1_buf_c, g1_len_c);
    print_hex("G2 (C)  ", g2_buf_c, g2_len_c);
    print_hex("GT (C)  ", gt_buf_c, gt_len_c);
    std::cout << "G1 len: " << g1_len_c << ", G2 len: " << g2_len_c << ", GT len: " << gt_len_c << std::endl;

    // Compare
    std::cout << "\n--- Comparison ---" << std::endl;
    bool g1_match = (g1_len_cpp == g1_len_c) && (memcmp(g1_buf_cpp, g1_buf_c, g1_len_cpp) == 0);
    bool g2_match = (g2_len_cpp == g2_len_c) && (memcmp(g2_buf_cpp, g2_buf_c, g2_len_cpp) == 0);
    bool gt_match = (gt_len_cpp == gt_len_c) && (memcmp(gt_buf_cpp, gt_buf_c, gt_len_cpp) == 0);

    std::cout << "G1 match: " << (g1_match ? "YES ✓" : "NO ✗") << std::endl;
    std::cout << "G2 match: " << (g2_match ? "YES ✓" : "NO ✗") << std::endl;
    std::cout << "GT match: " << (gt_match ? "YES ✓" : "NO ✗") << std::endl;

    if (g1_match && g2_match && gt_match) {
        std::cout << "\n✓ C++ API and C API produce IDENTICAL results!" << std::endl;
        return 0;
    } else {
        std::cout << "\n✗ C++ API and C API produce DIFFERENT results!" << std::endl;
        return 1;
    }
}
