///
/// Test curve info database
///

#include <iostream>
#include <stdio.h>

extern "C" {
#include <openabe/utils/zconstants.h>

const char* OpenABE_getCurveName(OpenABECurveID id);
const char* OpenABE_getCurveDisplayName(OpenABECurveID id);
uint32_t OpenABE_getCurveSecurityLevel(OpenABECurveID id);
const char* OpenABE_getCurveFamily(OpenABECurveID id);
int OpenABE_getCurveFieldBits(OpenABECurveID id);
int OpenABE_getCurveEmbeddingDegree(OpenABECurveID id);
const char* OpenABE_getCurveStatus(OpenABECurveID id);
const char* OpenABE_getCurveNotes(OpenABECurveID id);
const char* OpenABE_getCurveRelicID(OpenABECurveID id);
OpenABECurveID OpenABE_getCurveIDByName(const char* name);
bool OpenABE_isCurveSupported(const char* name);
int OpenABE_listAllCurves(const char*** names_out, int* count_out);
int OpenABE_listRecommendedCurves(const char*** names_out, int* count_out);
void OpenABE_printCurveInfo(OpenABECurveID id);
void OpenABE_printCurveWarnings(OpenABECurveID id);
void OpenABE_printAllCurves(void);
}

using namespace std;

int main() {
    printf("==============================================\n");
    printf("OpenABE Curve Info Database Test\n");
    printf("==============================================\n\n");

    // Test 1: Print all curves
    printf("TEST 1: Print all available curves\n");
    printf("-------------------------------------------\n");
    OpenABE_printAllCurves();

    // Test 2: Test specific curve lookup
    printf("\nTEST 2: Lookup BLS12-381 (recommended curve)\n");
    printf("-------------------------------------------\n");
    OpenABECurveID bls12_381 = OpenABE_getCurveIDByName("BLS12_381");
    if (bls12_381 != OpenABE_NONE_ID) {
        OpenABE_printCurveInfo(bls12_381);
    } else {
        printf("ERROR: BLS12-381 not found\n");
        return 1;
    }

    // Test 3: Test legacy curve warning
    printf("\nTEST 3: Check BN254 (legacy curve with warning)\n");
    printf("-------------------------------------------\n");
    OpenABECurveID bn254 = OpenABE_getCurveIDByName("BN254");
    if (bn254 != OpenABE_NONE_ID) {
        OpenABE_printCurveInfo(bn254);
        OpenABE_printCurveWarnings(bn254);
    } else {
        printf("ERROR: BN254 not found\n");
        return 1;
    }

    // Test 4: List recommended curves
    printf("\nTEST 4: List recommended curves only\n");
    printf("-------------------------------------------\n");
    const char** recommended = nullptr;
    int rec_count = 0;
    if (OpenABE_listRecommendedCurves(&recommended, &rec_count) == 0) {
        printf("Found %d recommended curves:\n", rec_count);
        for (int i = 0; i < rec_count; i++) {
            OpenABECurveID id = OpenABE_getCurveIDByName(recommended[i]);
            printf("  - %s (%d-bit security)\n",
                   OpenABE_getCurveDisplayName(id),
                   OpenABE_getCurveSecurityLevel(id));
        }
    } else {
        printf("ERROR: Failed to list recommended curves\n");
        return 1;
    }

    // Test 5: Test curve support check
    printf("\nTEST 5: Check curve support\n");
    printf("-------------------------------------------\n");
    const char* test_curves[] = {"BLS12_381", "BLS12_377", "BN254", "INVALID_CURVE"};
    for (int i = 0; i < 4; i++) {
        bool supported = OpenABE_isCurveSupported(test_curves[i]);
        printf("  %s: %s\n", test_curves[i], supported ? "SUPPORTED" : "NOT SUPPORTED");
    }

    printf("\n==============================================\n");
    printf("All tests completed successfully!\n");
    printf("==============================================\n");

    return 0;
}
