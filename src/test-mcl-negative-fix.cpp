#include <iostream>
#include <iomanip>
#include <mcl/bn_c256.h>

void printFr(const char* label, const mclBnFr* x) {
    char buf[1024];
    mclBnFr_getStr(buf, sizeof(buf), x, 10);
    std::cout << label << buf << std::endl;
}

void printG1(const char* label, const mclBnG1* p) {
    char buf[2048];
    mclBnG1_getStr(buf, sizeof(buf), p, 10);
    std::cout << label << buf << std::endl;
}

int main() {
    // Initialize MCL for BN254
    if (mclBn_init(MCL_BN254, MCLBN_COMPILED_TIME_VAR) != 0) {
        std::cerr << "Failed to initialize MCL" << std::endl;
        return 1;
    }

    std::cout << "=== Testing MCL Negative Exponent Approaches ===" << std::endl << std::endl;

    // Get the curve order
    mclBnFr order;
    char orderBuf[1024];
    mclBn_getCurveOrder(orderBuf, sizeof(orderBuf));
    std::cout << "Curve order: " << orderBuf << std::endl << std::endl;

    // Create test values
    mclBnG1 A, g;
    mclBnFr x, neg_x, adjusted_neg_x;

    // Set generator
    mclBnG1_hashAndMapTo(&g, "test", 4);

    // Set A = g
    A = g;

    // Set x to a small test value
    mclBnFr_setInt(&x, 42);

    // Method 1: Direct negation (BROKEN in MCL)
    std::cout << "--- Method 1: Direct negation (BROKEN) ---" << std::endl;
    mclBnFr_neg(&neg_x, &x);
    printFr("x = ", &x);
    printFr("-x = ", &neg_x);

    mclBnG1 A_x, A_neg_x, result1;
    mclBnG1_mul(&A_x, &A, &x);
    mclBnG1_mul(&A_neg_x, &A, &neg_x);
    mclBnG1_add(&result1, &A_x, &A_neg_x);

    std::cout << "A^x * A^(-x) is identity: " << (mclBnG1_isZero(&result1) ? "YES ✓" : "NO ✗") << std::endl;
    std::cout << std::endl;

    // Method 2: Convert negative to positive using order
    // If we have -x, we can compute order - x to get the equivalent positive value
    // since A^(-x) = A^(order - x) in the group
    std::cout << "--- Method 2: Convert -x to (order - x) ---" << std::endl;

    // Get the order as Fr element
    mclBnFr fr_order;
    mclBnFr_setStr(&fr_order, orderBuf, strlen(orderBuf), 10);

    // Compute adjusted_neg_x = order + neg_x (since neg_x is already negative, this gives order - x)
    mclBnFr_add(&adjusted_neg_x, &fr_order, &neg_x);

    printFr("Adjusted -x = ", &adjusted_neg_x);

    // Now compute A^(order - x)
    mclBnG1 A_adjusted;
    mclBnG1_mul(&A_adjusted, &A, &adjusted_neg_x);

    // Check if A^x * A^(order-x) = identity
    mclBnG1 result2;
    mclBnG1_add(&result2, &A_x, &A_adjusted);

    std::cout << "A^x * A^(order-x) is identity: " << (mclBnG1_isZero(&result2) ? "YES ✓" : "NO ✗") << std::endl;
    std::cout << std::endl;

    // Method 3: Use point negation instead
    // A^(-x) = -(A^x)
    std::cout << "--- Method 3: Compute A^x then negate point ---" << std::endl;

    mclBnG1 neg_A_x;
    mclBnG1_mul(&neg_A_x, &A, &x);
    mclBnG1_neg(&neg_A_x, &neg_A_x);

    // Check if A^x * (-(A^x)) = identity
    mclBnG1 result3;
    mclBnG1_add(&result3, &A_x, &neg_A_x);

    std::cout << "A^x * (-(A^x)) is identity: " << (mclBnG1_isZero(&result3) ? "YES ✓" : "NO ✗") << std::endl;
    std::cout << std::endl;

    // Method 4: Check if isNegative correctly identifies our negated value
    std::cout << "--- Method 4: Check mclBnFr_isNegative behavior ---" << std::endl;
    std::cout << "mclBnFr_isNegative(x): " << mclBnFr_isNegative(&x) << std::endl;
    std::cout << "mclBnFr_isNegative(-x): " << mclBnFr_isNegative(&neg_x) << std::endl;
    std::cout << "mclBnFr_isNegative(order-x): " << mclBnFr_isNegative(&adjusted_neg_x) << std::endl;
    std::cout << std::endl;

    // Method 5: Test with a value that would naturally be in upper half
    std::cout << "--- Method 5: Test with order/2 (naturally in upper half) ---" << std::endl;
    mclBnFr half_order;
    mclBnFr two;
    mclBnFr_setInt(&two, 2);
    mclBnFr_div(&half_order, &fr_order, &two);

    printFr("order/2 = ", &half_order);
    std::cout << "mclBnFr_isNegative(order/2): " << mclBnFr_isNegative(&half_order) << std::endl;

    // This should work normally (not be treated as negative)
    mclBnG1 A_half1, A_half2, A_full;
    mclBnG1_mul(&A_half1, &A, &half_order);
    mclBnG1_mul(&A_half2, &A, &half_order);
    mclBnG1_add(&A_full, &A_half1, &A_half2);

    // Compute A^order (should be identity)
    mclBnG1 A_order;
    mclBnG1_mul(&A_order, &A, &fr_order);
    std::cout << "A^order is identity: " << (mclBnG1_isZero(&A_order) ? "YES ✓" : "NO ✗") << std::endl;

    // Compare
    std::cout << "A^(order/2) * A^(order/2) equals A^order: " << (mclBnG1_isEqual(&A_full, &A_order) ? "YES ✓" : "NO ✗") << std::endl;
    std::cout << std::endl;

    return 0;
}
