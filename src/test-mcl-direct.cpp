#include <mcl/bn_c384_256.h>
#include <iostream>
#include <iomanip>

void printFr(const char* label, const mclBnFr* fr) {
    char buf[128];
    mclBnFr_getStr(buf, sizeof(buf), fr, 10);
    std::cout << label << ": " << buf << std::endl;
}

void printG1(const char* label, const mclBnG1* g1) {
    char buf[256];
    mclBnG1_getStr(buf, sizeof(buf), g1, 16);
    std::cout << label << ": " << std::string(buf).substr(0, 40) << "..." << std::endl;
}

int main() {
    // Initialize MCL
    int ret = mclBn_init(mclBn_CurveFp254BNb, MCLBN_COMPILED_TIME_VAR);
    if (ret != 0) {
        std::cerr << "MCL init failed: " << ret << std::endl;
        return 1;
    }

    std::cout << "=== Testing MCL Direct API ===" << std::endl;

    // Generate random G1 point
    mclBnG1 A;
    mclBnG1_hashAndMapTo(&A, "test", 4);

    // Generate random scalar x
    mclBnFr x;
    mclBnFr_setByCSPRNG(&x);

    printG1("Base point A", &A);
    printFr("Scalar x", &x);

    // Compute A^x
    mclBnG1 Ax;
    mclBnG1_mul(&Ax, &A, &x);
    printG1("A^x", &Ax);

    // Compute -x (additive inverse in Fr)
    mclBnFr neg_x;
    mclBnFr_neg(&neg_x, &x);
    printFr("Scalar -x (neg)", &neg_x);

    // Compute A^(-x)
    mclBnG1 A_neg_x;
    mclBnG1_mul(&A_neg_x, &A, &neg_x);
    printG1("A^(-x) using neg", &A_neg_x);

    // Compute A^x * A^(-x)
    mclBnG1 product;
    mclBnG1_add(&product, &Ax, &A_neg_x);
    printG1("A^x + A^(-x)", &product);

    // Check if it's zero/identity
    int is_zero = mclBnG1_isZero(&product);
    std::cout << "Is identity (zero): " << (is_zero ? "YES ✓" : "NO ✗") << std::endl;

    // Alternative: compute x + (-x) and check if it's zero
    mclBnFr sum;
    mclBnFr_add(&sum, &x, &neg_x);
    printFr("x + (-x)", &sum);
    int is_zero_fr = mclBnFr_isZero(&sum);
    std::cout << "x + (-x) is zero: " << (is_zero_fr ? "YES ✓" : "NO ✗") << std::endl;

    // Now compute A^(x + (-x)) = A^0 which should be identity
    mclBnG1 A_zero;
    mclBnG1_mul(&A_zero, &A, &sum);
    printG1("A^(x + (-x)) = A^0", &A_zero);
    int is_zero2 = mclBnG1_isZero(&A_zero);
    std::cout << "A^0 is identity: " << (is_zero2 ? "YES ✓" : "NO ✗") << std::endl;

    return 0;
}
