///
/// Copyright (c) 2018 Zeutro, LLC. All rights reserved.
///
/// This file is part of Zeutro's OpenABE.
///
/// OpenABE is free software: you can redistribute it and/or modify
/// it under the terms of the GNU Affero General Public License as published by
/// the Free Software Foundation, either version 3 of the License, or
/// (at your option) any later version.
///
/// OpenABE is distributed in the hope that it will be useful,
/// but WITHOUT ANY WARRANTY; without even the implied warranty of
/// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
/// GNU Affero General Public License for more details.
///
/// You should have received a copy of the GNU Affero General Public
/// License along with OpenABE. If not, see <http://www.gnu.org/licenses/>.
///

#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <string>
#include <getopt.h>

extern "C" {
#include <openabe/utils/zconstants.h>

const char* OpenABE_getCurveName(OpenABECurveID id);
const char* OpenABE_getCurveDisplayName(OpenABECurveID id);
OpenABESecurityLevel OpenABE_getCurveSecurityLevel(OpenABECurveID id);
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

void printUsage(const char* progname) {
    printf("Usage: %s [OPTIONS]\n\n", progname);
    printf("Options:\n");
    printf("  -l, --list             List all available curves\n");
    printf("  -r, --recommended      List only recommended curves\n");
    printf("  -i, --info CURVE       Show detailed info for specific curve\n");
    printf("  -c, --check CURVE      Check if curve is supported\n");
    printf("  -h, --help             Show this help message\n");
    printf("\n");
    printf("Examples:\n");
    printf("  %s --list                     # List all curves\n", progname);
    printf("  %s --recommended              # List recommended curves\n", progname);
    printf("  %s --info BLS12_381           # Show BLS12-381 details\n", progname);
    printf("  %s --check BN254              # Check if BN254 is supported\n", progname);
    printf("\n");
}

void listAllCurves() {
    OpenABE_printAllCurves();
}

void listRecommendedCurves() {
    const char** names = nullptr;
    int count = 0;

    if (OpenABE_listRecommendedCurves(&names, &count) != 0) {
        fprintf(stderr, "ERROR: Failed to list recommended curves\n");
        return;
    }

    printf("\n");
    printf("Recommended Pairing-Friendly Curves\n");
    printf("====================================\n");
    printf("\n");

    for (int i = 0; i < count; i++) {
        OpenABECurveID id = OpenABE_getCurveIDByName(names[i]);
        const char* display_name = OpenABE_getCurveDisplayName(id);
        int field_bits = OpenABE_getCurveFieldBits(id);
        int security = OpenABE_getCurveSecurityLevel(id);
        const char* notes = OpenABE_getCurveNotes(id);

        printf("  %-20s %3d-bit field, %3d-bit security\n", display_name, field_bits, security);
        printf("    %s\n", notes);
        printf("\n");
    }

    printf("Default: BLS12-381 (industry standard)\n");
    printf("\n");
}

void showCurveInfo(const char* curve_name) {
    if (!OpenABE_isCurveSupported(curve_name)) {
        fprintf(stderr, "ERROR: Curve '%s' is not supported\n", curve_name);
        fprintf(stderr, "Run '%s --list' to see available curves\n", "oabe_curves");
        return;
    }

    OpenABECurveID id = OpenABE_getCurveIDByName(curve_name);
    printf("\n");
    OpenABE_printCurveInfo(id);
    OpenABE_printCurveWarnings(id);
}

void checkCurveSupport(const char* curve_name) {
    if (OpenABE_isCurveSupported(curve_name)) {
        OpenABECurveID id = OpenABE_getCurveIDByName(curve_name);
        const char* status = OpenABE_getCurveStatus(id);
        int security = OpenABE_getCurveSecurityLevel(id);

        printf("Curve '%s' is supported\n", curve_name);
        printf("  Status: %s\n", status);
        printf("  Security: %d bits\n", security);

        if (strcmp(status, "weak") == 0 || strcmp(status, "legacy") == 0) {
            printf("  WARNING: This curve has security concerns. See --info for details.\n");
        }
    } else {
        printf("Curve '%s' is NOT supported\n", curve_name);
        printf("Run '%s --list' to see available curves\n", "oabe_curves");
    }
}

int main(int argc, char **argv) {
    static struct option long_options[] = {
        {"list",        no_argument,       0, 'l'},
        {"recommended", no_argument,       0, 'r'},
        {"info",        required_argument, 0, 'i'},
        {"check",       required_argument, 0, 'c'},
        {"help",        no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    if (argc == 1) {
        // No arguments - show all curves by default
        listAllCurves();
        return 0;
    }

    int opt;
    int option_index = 0;

    while ((opt = getopt_long(argc, argv, "lri:c:h", long_options, &option_index)) != -1) {
        switch (opt) {
        case 'l':
            listAllCurves();
            break;

        case 'r':
            listRecommendedCurves();
            break;

        case 'i':
            showCurveInfo(optarg);
            break;

        case 'c':
            checkCurveSupport(optarg);
            break;

        case 'h':
            printUsage(argv[0]);
            return 0;

        default:
            printUsage(argv[0]);
            return 1;
        }
    }

    return 0;
}
