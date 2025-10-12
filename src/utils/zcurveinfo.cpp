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
/// You can be released from the requirements of the GNU Affero General
/// Public License and obtain additional features by purchasing a
/// commercial license. Buying such a license is mandatory if you
/// engage in commercial activities involving OpenABE that do not
/// comply with the open source requirements of the GNU Affero General
/// Public License. For more information on commerical licenses,
/// visit <http://www.zeutro.com>.
///
/// \file   zcurveinfo.cpp
///
/// \brief  Comprehensive curve metadata database for all supported pairing-friendly curves
///
/// \author J. Ayo Akinyele
///

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <vector>
#include <map>
#include <stdint.h>
#include <openabe/utils/zconstants.h>

using namespace std;

namespace oabe {

// Forward declare the type (defined as uint32_t in openabe.h)
typedef uint32_t OpenABESecurityLevel;

/// @struct CurveInfo
///
/// @brief Metadata for a pairing-friendly curve
struct CurveInfo {
    OpenABECurveID id;
    const char* name;
    const char* display_name;
    const char* family;
    int field_bits;
    int embedding_degree;
    OpenABESecurityLevel security_level;
    const char* status;  // "recommended", "good", "legacy", "weak", "deprecated"
    const char* notes;
    const char* relic_id; // RELIC curve constant (e.g., "BN_P254", "B12_P381")
};

// Comprehensive curve database
static const CurveInfo CURVE_DATABASE[] = {
    // BN curves (k=12, pairing-friendly)
    {
        OpenABE_BN_P158_ID,
        "BN158",
        "BN-158",
        "BN",
        158,
        12,
        OpenABE_SECURITY_WEAK,
        "weak",
        "Only for testing - too weak for production use",
        "BN_P158"
    },
    {
        OpenABE_BN_P254_ID,
        "BN254",
        "BN-254",
        "BN",
        254,
        12,
        OpenABE_SECURITY_LEGACY,
        "legacy",
        "Security downgraded to ~100 bits due to recent attacks. Use BLS12-381 for new systems.",
        "BN_P254"
    },
    {
        OpenABE_BN_P256_ID,
        "BN256",
        "BN-256",
        "BN",
        256,
        12,
        OpenABE_SECURITY_LEGACY,
        "legacy",
        "Similar security to BN254. Prefer BLS12-381 for new systems.",
        "BN_P256"
    },
    {
        OpenABE_BN_P382_ID,
        "BN382",
        "BN-382",
        "BN",
        382,
        12,
        OpenABE_SECURITY_STANDARD,
        "good",
        "128-bit security. BLS12-381 recommended instead for better standardization.",
        "BN_P382"
    },
    {
        OpenABE_BN_P446_ID,
        "BN446",
        "BN-446",
        "BN",
        446,
        12,
        OpenABE_SECURITY_HIGH,
        "good",
        "192-bit security. BLS24 curves may offer better performance at this level.",
        "BN_P446"
    },
    {
        OpenABE_BN_P638_ID,
        "BN638",
        "BN-638",
        "BN",
        638,
        12,
        OpenABE_SECURITY_VERY_HIGH,
        "good",
        "256-bit security. Very high security but slower than lower security levels.",
        "BN_P638"
    },

    // BLS12 curves (k=12, pairing-friendly, recommended)
    {
        OpenABE_BLS12_P377_ID,
        "BLS12_377",
        "BLS12-377",
        "BLS12",
        377,
        12,
        OpenABE_SECURITY_STANDARD,
        "recommended",
        "128-bit security. Used in Zexe/Celo. Excellent performance.",
        "B12_P377"
    },
    {
        OpenABE_BLS12_P381_ID,
        "BLS12_381",
        "BLS12-381",
        "BLS12",
        381,
        12,
        OpenABE_SECURITY_STANDARD,
        "recommended",
        "128-bit security. Industry standard (Zcash, Ethereum 2.0, Filecoin). Default choice.",
        "B12_P381"
    },
    {
        OpenABE_BLS12_P446_ID,
        "BLS12_446",
        "BLS12-446",
        "BLS12",
        446,
        12,
        OpenABE_SECURITY_HIGH,
        "recommended",
        "192-bit security. High security with good performance.",
        "B12_P446"
    },
    {
        OpenABE_BLS12_P455_ID,
        "BLS12_455",
        "BLS12-455",
        "BLS12",
        455,
        12,
        OpenABE_SECURITY_HIGH,
        "recommended",
        "192-bit security. Alternative to BLS12-446.",
        "B12_P455"
    },
    {
        OpenABE_BLS12_P638_ID,
        "BLS12_638",
        "BLS12-638",
        "BLS12",
        638,
        12,
        OpenABE_SECURITY_VERY_HIGH,
        "recommended",
        "256-bit security. Maximum security for long-term protection.",
        "B12_P638"
    },

    // BLS24 curves (k=24, pairing-friendly)
    {
        OpenABE_BLS24_P315_ID,
        "BLS24_315",
        "BLS24-315",
        "BLS24",
        315,
        24,
        OpenABE_SECURITY_STANDARD,
        "good",
        "128-bit security. Higher embedding degree may offer better performance for some operations.",
        "B24_P315"
    },
    {
        OpenABE_BLS24_P317_ID,
        "BLS24_317",
        "BLS24-317",
        "BLS24",
        317,
        24,
        OpenABE_SECURITY_STANDARD,
        "good",
        "128-bit security. Alternative to BLS24-315.",
        "B24_P317"
    },
    {
        OpenABE_BLS24_P509_ID,
        "BLS24_509",
        "BLS24-509",
        "BLS24",
        509,
        24,
        OpenABE_SECURITY_HIGH,
        "good",
        "192-bit security with k=24.",
        "B24_P509"
    },

    // BLS48 curves (k=48, pairing-friendly)
    {
        OpenABE_BLS48_P575_ID,
        "BLS48_575",
        "BLS48-575",
        "BLS48",
        575,
        48,
        OpenABE_SECURITY_VERY_HIGH,
        "good",
        "256-bit security. Very high embedding degree for specialized applications.",
        "B48_P575"
    },

    // KSS curves (k=16 or k=18, pairing-friendly)
    {
        OpenABE_KSS16_P339_ID,
        "KSS16_339",
        "KSS16-339",
        "KSS",
        339,
        16,
        OpenABE_SECURITY_STANDARD,
        "good",
        "128-bit security. KSS curves with k=16.",
        "K16_P339"
    }
};

#define MAX_CURVES 100  // Maximum curves we might support
static const int CURVE_DATABASE_SIZE = sizeof(CURVE_DATABASE) / sizeof(CurveInfo);

// Map from curve name (string) to curve info
static map<string, const CurveInfo*> curve_name_map;
static bool curve_name_map_initialized = false;

static void initializeCurveNameMap() {
    if (curve_name_map_initialized) {
        return;
    }

    for (int i = 0; i < CURVE_DATABASE_SIZE; i++) {
        const CurveInfo* info = &CURVE_DATABASE[i];
        curve_name_map[string(info->name)] = info;
        curve_name_map[string(info->display_name)] = info;
    }

    curve_name_map_initialized = true;
}

// Get curve info by ID
const CurveInfo* getCurveInfo(OpenABECurveID id) {
    for (int i = 0; i < CURVE_DATABASE_SIZE; i++) {
        if (CURVE_DATABASE[i].id == id) {
            return &CURVE_DATABASE[i];
        }
    }
    return nullptr;
}

// Get curve info by name
const CurveInfo* getCurveInfoByName(const char* name) {
    initializeCurveNameMap();

    auto it = curve_name_map.find(string(name));
    if (it != curve_name_map.end()) {
        return it->second;
    }
    return nullptr;
}

// Public API functions

extern "C" {

const char* OpenABE_getCurveName(OpenABECurveID id) {
    const CurveInfo* info = getCurveInfo(id);
    return info ? info->name : nullptr;
}

const char* OpenABE_getCurveDisplayName(OpenABECurveID id) {
    const CurveInfo* info = getCurveInfo(id);
    return info ? info->display_name : nullptr;
}

OpenABESecurityLevel OpenABE_getCurveSecurityLevel(OpenABECurveID id) {
    const CurveInfo* info = getCurveInfo(id);
    return info ? info->security_level : OpenABE_SECURITY_WEAK;
}

const char* OpenABE_getCurveFamily(OpenABECurveID id) {
    const CurveInfo* info = getCurveInfo(id);
    return info ? info->family : nullptr;
}

int OpenABE_getCurveFieldBits(OpenABECurveID id) {
    const CurveInfo* info = getCurveInfo(id);
    return info ? info->field_bits : 0;
}

int OpenABE_getCurveEmbeddingDegree(OpenABECurveID id) {
    const CurveInfo* info = getCurveInfo(id);
    return info ? info->embedding_degree : 0;
}

const char* OpenABE_getCurveStatus(OpenABECurveID id) {
    const CurveInfo* info = getCurveInfo(id);
    return info ? info->status : nullptr;
}

const char* OpenABE_getCurveNotes(OpenABECurveID id) {
    const CurveInfo* info = getCurveInfo(id);
    return info ? info->notes : nullptr;
}

const char* OpenABE_getCurveRelicID(OpenABECurveID id) {
    const CurveInfo* info = getCurveInfo(id);
    return info ? info->relic_id : nullptr;
}

OpenABECurveID OpenABE_getCurveIDByName(const char* name) {
    if (!name) {
        return OpenABE_NONE_ID;
    }

    const CurveInfo* info = getCurveInfoByName(name);
    return info ? info->id : OpenABE_NONE_ID;
}

bool OpenABE_isCurveSupported(const char* name) {
    return getCurveInfoByName(name) != nullptr;
}

int OpenABE_listAllCurves(const char*** names_out, int* count_out) {
    if (!names_out || !count_out) {
        return -1;
    }

    static const char* curve_names[MAX_CURVES];
    for (int i = 0; i < CURVE_DATABASE_SIZE; i++) {
        curve_names[i] = CURVE_DATABASE[i].name;
    }

    *names_out = curve_names;
    *count_out = CURVE_DATABASE_SIZE;
    return 0;
}

int OpenABE_listRecommendedCurves(const char*** names_out, int* count_out) {
    if (!names_out || !count_out) {
        return -1;
    }

    static const char* recommended_curves[MAX_CURVES];
    int recommended_count = 0;

    for (int i = 0; i < CURVE_DATABASE_SIZE; i++) {
        if (strcmp(CURVE_DATABASE[i].status, "recommended") == 0) {
            recommended_curves[recommended_count++] = CURVE_DATABASE[i].name;
        }
    }

    *names_out = recommended_curves;
    *count_out = recommended_count;
    return 0;
}

void OpenABE_printCurveInfo(OpenABECurveID id) {
    const CurveInfo* info = getCurveInfo(id);
    if (!info) {
        fprintf(stderr, "Unknown curve ID: 0x%02X\n", id);
        return;
    }

    printf("Curve: %s (%s)\n", info->display_name, info->name);
    printf("  Family: %s (k=%d)\n", info->family, info->embedding_degree);
    printf("  Field size: %d bits\n", info->field_bits);
    printf("  Security level: %d bits\n", info->security_level);
    printf("  Status: %s\n", info->status);
    printf("  Notes: %s\n", info->notes);
}

void OpenABE_printCurveWarnings(OpenABECurveID id) {
    const CurveInfo* info = getCurveInfo(id);
    if (!info) {
        return;
    }

    if (strcmp(info->status, "weak") == 0) {
        fprintf(stderr, "\n");
        fprintf(stderr, "========================================\n");
        fprintf(stderr, "WARNING: WEAK CURVE\n");
        fprintf(stderr, "========================================\n");
        fprintf(stderr, "Curve: %s\n", info->display_name);
        fprintf(stderr, "Security: %d bits (WEAK)\n", info->security_level);
        fprintf(stderr, "%s\n", info->notes);
        fprintf(stderr, "========================================\n");
        fprintf(stderr, "\n");
    } else if (strcmp(info->status, "legacy") == 0) {
        fprintf(stderr, "\n");
        fprintf(stderr, "========================================\n");
        fprintf(stderr, "WARNING: LEGACY CURVE\n");
        fprintf(stderr, "========================================\n");
        fprintf(stderr, "Curve: %s\n", info->display_name);
        fprintf(stderr, "Security: %d bits (LEGACY)\n", info->security_level);
        fprintf(stderr, "%s\n", info->notes);
        fprintf(stderr, "Recommended: Use BLS12-381 instead\n");
        fprintf(stderr, "========================================\n");
        fprintf(stderr, "\n");
    } else if (strcmp(info->status, "deprecated") == 0) {
        fprintf(stderr, "\n");
        fprintf(stderr, "========================================\n");
        fprintf(stderr, "ERROR: DEPRECATED CURVE\n");
        fprintf(stderr, "========================================\n");
        fprintf(stderr, "Curve: %s\n", info->display_name);
        fprintf(stderr, "%s\n", info->notes);
        fprintf(stderr, "This curve should not be used.\n");
        fprintf(stderr, "========================================\n");
        fprintf(stderr, "\n");
    }
}

void OpenABE_printAllCurves(void) {
    printf("\n");
    printf("OpenABE Supported Pairing-Friendly Curves\n");
    printf("==========================================\n");
    printf("\n");

    // Group by family
    const char* families[] = {"BN", "BLS12", "BLS24", "BLS48", "KSS"};
    int num_families = sizeof(families) / sizeof(families[0]);

    for (int f = 0; f < num_families; f++) {
        const char* family = families[f];
        printf("%s Curves:\n", family);
        printf("----------------------------------------\n");

        for (int i = 0; i < CURVE_DATABASE_SIZE; i++) {
            const CurveInfo* info = &CURVE_DATABASE[i];
            if (strcmp(info->family, family) == 0) {
                printf("  %-20s %3d bits, k=%-2d, %3d-bit security [%s]\n",
                       info->display_name,
                       info->field_bits,
                       info->embedding_degree,
                       info->security_level,
                       info->status);
            }
        }
        printf("\n");
    }

    printf("Status Legend:\n");
    printf("  recommended = Industry standard, best choice for new systems\n");
    printf("  good        = Solid choice, well-supported\n");
    printf("  legacy      = Outdated, use only for compatibility\n");
    printf("  weak        = Too weak for production, testing only\n");
    printf("\n");
    printf("Default curve: BLS12-381 (128-bit security, industry standard)\n");
    printf("\n");
}

} // extern "C"

} // namespace oabe
