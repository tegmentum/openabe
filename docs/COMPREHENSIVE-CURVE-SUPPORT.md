# Comprehensive Pairing-Friendly Curve Support

## Philosophy: Support All Available Curves

Instead of limiting to a single "recommended" curve, OpenABE should expose all pairing-friendly curves available in the underlying math libraries (RELIC, MCL). This provides:

1. **Flexibility**: Users choose based on their security/performance tradeoff
2. **Compatibility**: Match curve choices of other systems for interoperability
3. **Future-proofing**: New curves can be added without API changes
4. **Migration**: Smooth transition from legacy curves (BN254) to modern ones

## Available Curves in RELIC 0.7.0

### BN Curves (Barreto-Naehrig)

| Curve | Embedding Degree | Security Level | Status | Notes |
|-------|------------------|----------------|--------|-------|
| **BN158** | k=12 | ~70 bits | ⚠️ Weak | Academic only |
| **BN254** | k=12 | ~100 bits | ⚠️ Marginal | Legacy, deprecated |
| **BN382** | k=12 | ~128 bits | ✅ Good | Larger BN curve |
| **BN446** | k=12 | ~128 bits | ✅ Good | Extra margin |
| **BN638** | k=12 | ~192 bits | ✅ High | Future-proof |

### BLS12 Curves (Barreto-Lynn-Scott, k=12)

| Curve | Field Size | Security Level | Status | Notes |
|-------|-----------|----------------|--------|-------|
| **BLS12-377** | 377-bit | ~120 bits | ✅ Good | Used by Aleo |
| **BLS12-381** | 381-bit | ~128 bits | ✅✅ **Recommended** | Industry standard |
| **BLS12-446** | 446-bit | ~128 bits | ✅ Good | Extra security margin |
| **BLS12-455** | 455-bit | ~128 bits | ✅ Good | Alternative |
| **BLS12-638** | 638-bit | ~192 bits | ✅ High | Future-proof |

### BLS24 Curves (Barreto-Lynn-Scott, k=24)

| Curve | Field Size | Security Level | Status | Notes |
|-------|-----------|----------------|--------|-------|
| **BLS24-315** | 315-bit | ~128 bits | ✅ Good | Higher embedding degree |
| **BLS24-317** | 317-bit | ~128 bits | ✅ Good | Alternative |
| **BLS24-509** | 509-bit | ~192 bits | ✅ High | Very secure |

### BLS48 Curves (Barreto-Lynn-Scott, k=48)

| Curve | Field Size | Security Level | Status | Notes |
|-------|-----------|----------------|--------|-------|
| **BLS48-575** | 575-bit | ~256 bits | 🔒 Extreme | Maximum security |

### KSS Curves (Kachisa-Schaefer-Scott)

| Curve | Embedding Degree | Security Level | Status | Notes |
|-------|------------------|----------------|--------|-------|
| **KSS16-339** | k=16 | ~128 bits | ✅ Good | Different structure |

### Security Level Mapping

```
~70 bits:   Broken (academic only)
~100 bits:  Marginal (legacy support only)
~120 bits:  Acceptable (performance-critical)
~128 bits:  Standard (recommended minimum)
~192 bits:  High (government, long-term)
~256 bits:  Extreme (maximum available)
```

## Implementation

### 1. Constants Definition

**File: `src/include/openabe/utils/zconstants.h`**

```cpp
/// @typedef    OpenABECurveID
/// @brief      Enumeration of supported elliptic curves
typedef enum _OpenABECurveID {
  OpenABE_NONE_ID = 0,

  // ECDSA Curves (for signatures, not pairings)
  OpenABE_NIST_P256_ID = 1,
  OpenABE_NIST_P384_ID = 2,
  OpenABE_NIST_P521_ID = 3,

  // BN Curves (Barreto-Naehrig, embedding degree k=12)
  OpenABE_BN_P158_ID = 10,   // ~70 bits  - WEAK, academic only
  OpenABE_BN_P254_ID = 11,   // ~100 bits - DEPRECATED, legacy only
  OpenABE_BN_P256_ID = 12,   // ~100 bits - DEPRECATED, legacy only
  OpenABE_BN_P382_ID = 13,   // ~128 bits - good
  OpenABE_BN_P446_ID = 14,   // ~128 bits - good
  OpenABE_BN_P638_ID = 15,   // ~192 bits - high security

  // BLS12 Curves (Barreto-Lynn-Scott, k=12, RECOMMENDED FAMILY)
  OpenABE_BLS12_377_ID = 20, // ~120 bits - good, used by Aleo
  OpenABE_BLS12_381_ID = 21, // ~128 bits - RECOMMENDED (Ethereum 2.0, Zcash)
  OpenABE_BLS12_446_ID = 22, // ~128 bits - good with margin
  OpenABE_BLS12_455_ID = 23, // ~128 bits - good alternative
  OpenABE_BLS12_638_ID = 24, // ~192 bits - high security

  // BLS24 Curves (Barreto-Lynn-Scott, k=24)
  OpenABE_BLS24_315_ID = 30, // ~128 bits - good
  OpenABE_BLS24_317_ID = 31, // ~128 bits - good alternative
  OpenABE_BLS24_509_ID = 32, // ~192 bits - high security

  // BLS48 Curves (k=48)
  OpenABE_BLS48_575_ID = 40, // ~256 bits - extreme security

  // KSS Curves (Kachisa-Schaefer-Scott)
  OpenABE_KSS16_339_ID = 50, // ~128 bits - good, k=16

  // Add future curves here...
  // OpenABE_XXX_YYY_ID = 60+
} OpenABECurveID;

/// Security level in bits (symmetric-equivalent)
typedef enum _OpenABESecurityLevel {
  OpenABE_SECURITY_WEAK      = 70,   // Academic only, not recommended
  OpenABE_SECURITY_MARGINAL  = 100,  // Legacy support only
  OpenABE_SECURITY_ACCEPTABLE = 120, // Minimum for new deployments
  OpenABE_SECURITY_STANDARD  = 128,  // Recommended
  OpenABE_SECURITY_HIGH      = 192,  // Government, long-term secrets
  OpenABE_SECURITY_EXTREME   = 256,  // Maximum available
} OpenABESecurityLevel;
```

### 2. Curve Metadata System

**New File: `src/utils/zcurve_info.cpp`**

```cpp
#include <openabe/openabe.h>

namespace oabe {

struct CurveInfo {
    OpenABECurveID id;
    const char* name;
    const char* family;
    int field_bits;
    int embedding_degree;
    OpenABESecurityLevel security_level;
    const char* status;      // "recommended", "good", "legacy", "weak"
    const char* notes;
};

// Comprehensive curve database
static const CurveInfo CURVE_DATABASE[] = {
    // BN Curves
    {
        OpenABE_BN_P158_ID, "BN_P158", "BN",
        158, 12, OpenABE_SECURITY_WEAK,
        "weak", "Academic use only"
    },
    {
        OpenABE_BN_P254_ID, "BN_P254", "BN",
        254, 12, OpenABE_SECURITY_MARGINAL,
        "deprecated", "Legacy support only - use BLS12-381 instead"
    },
    {
        OpenABE_BN_P382_ID, "BN_P382", "BN",
        382, 12, OpenABE_SECURITY_STANDARD,
        "good", "Larger BN curve with standard security"
    },
    {
        OpenABE_BN_P446_ID, "BN_P446", "BN",
        446, 12, OpenABE_SECURITY_STANDARD,
        "good", "BN curve with security margin"
    },
    {
        OpenABE_BN_P638_ID, "BN_P638", "BN",
        638, 12, OpenABE_SECURITY_HIGH,
        "good", "High-security BN curve"
    },

    // BLS12 Curves (RECOMMENDED FAMILY)
    {
        OpenABE_BLS12_377_ID, "BLS12_377", "BLS12",
        377, 12, OpenABE_SECURITY_ACCEPTABLE,
        "good", "Used by Aleo, good performance"
    },
    {
        OpenABE_BLS12_381_ID, "BLS12_381", "BLS12",
        381, 12, OpenABE_SECURITY_STANDARD,
        "recommended", "Industry standard - Ethereum 2.0, Zcash, Filecoin"
    },
    {
        OpenABE_BLS12_446_ID, "BLS12_446", "BLS12",
        446, 12, OpenABE_SECURITY_STANDARD,
        "good", "BLS12 curve with extra security margin"
    },
    {
        OpenABE_BLS12_455_ID, "BLS12_455", "BLS12",
        455, 12, OpenABE_SECURITY_STANDARD,
        "good", "Alternative BLS12 curve"
    },
    {
        OpenABE_BLS12_638_ID, "BLS12_638", "BLS12",
        638, 12, OpenABE_SECURITY_HIGH,
        "good", "High-security BLS12 curve"
    },

    // BLS24 Curves
    {
        OpenABE_BLS24_315_ID, "BLS24_315", "BLS24",
        315, 24, OpenABE_SECURITY_STANDARD,
        "good", "Higher embedding degree (k=24)"
    },
    {
        OpenABE_BLS24_317_ID, "BLS24_317", "BLS24",
        317, 24, OpenABE_SECURITY_STANDARD,
        "good", "Alternative BLS24 curve"
    },
    {
        OpenABE_BLS24_509_ID, "BLS24_509", "BLS24",
        509, 24, OpenABE_SECURITY_HIGH,
        "good", "High-security with k=24"
    },

    // BLS48 Curves
    {
        OpenABE_BLS48_575_ID, "BLS48_575", "BLS48",
        575, 48, OpenABE_SECURITY_EXTREME,
        "good", "Maximum security with k=48"
    },

    // KSS Curves
    {
        OpenABE_KSS16_339_ID, "KSS16_339", "KSS16",
        339, 16, OpenABE_SECURITY_STANDARD,
        "good", "Different curve structure (k=16)"
    },
};

// Get curve information
const CurveInfo* getCurveInfo(OpenABECurveID id) {
    for (size_t i = 0; i < sizeof(CURVE_DATABASE) / sizeof(CurveInfo); i++) {
        if (CURVE_DATABASE[i].id == id) {
            return &CURVE_DATABASE[i];
        }
    }
    return nullptr;
}

// Get curve by name
const CurveInfo* getCurveInfo(const std::string& name) {
    for (size_t i = 0; i < sizeof(CURVE_DATABASE) / sizeof(CurveInfo); i++) {
        if (name == CURVE_DATABASE[i].name) {
            return &CURVE_DATABASE[i];
        }
    }
    return nullptr;
}

// List all curves
std::vector<const CurveInfo*> listAllCurves() {
    std::vector<const CurveInfo*> curves;
    for (size_t i = 0; i < sizeof(CURVE_DATABASE) / sizeof(CurveInfo); i++) {
        curves.push_back(&CURVE_DATABASE[i]);
    }
    return curves;
}

// List curves by security level
std::vector<const CurveInfo*> listCurvesBySecurityLevel(OpenABESecurityLevel min_level) {
    std::vector<const CurveInfo*> curves;
    for (size_t i = 0; i < sizeof(CURVE_DATABASE) / sizeof(CurveInfo); i++) {
        if (CURVE_DATABASE[i].security_level >= min_level) {
            curves.push_back(&CURVE_DATABASE[i]);
        }
    }
    return curves;
}

// List recommended curves
std::vector<const CurveInfo*> listRecommendedCurves() {
    std::vector<const CurveInfo*> curves;
    for (size_t i = 0; i < sizeof(CURVE_DATABASE) / sizeof(CurveInfo); i++) {
        if (strcmp(CURVE_DATABASE[i].status, "recommended") == 0 ||
            strcmp(CURVE_DATABASE[i].status, "good") == 0) {
            curves.push_back(&CURVE_DATABASE[i]);
        }
    }
    return curves;
}

} // namespace oabe
```

### 3. User-Facing API

**Add to `src/include/openabe/openabe.h`**

```cpp
namespace oabe {

// Curve information queries
const char* OpenABE_getCurveName(OpenABECurveID id);
OpenABESecurityLevel OpenABE_getCurveSecurityLevel(OpenABECurveID id);
const char* OpenABE_getCurveStatus(OpenABECurveID id);
const char* OpenABE_getCurveNotes(OpenABECurveID id);

// List curves
std::vector<std::string> OpenABE_listAvailableCurves();
std::vector<std::string> OpenABE_listRecommendedCurves();
std::vector<std::string> OpenABE_listCurvesByMinSecurity(int min_bits);

// Validation
bool OpenABE_isCurveSupported(const std::string& curve_name);
bool OpenABE_isCurveRecommended(const std::string& curve_name);
void OpenABE_printCurveWarnings(const std::string& curve_name);

} // namespace oabe
```

### 4. String Conversion with Validation

**Update `src/openabe.cpp`**

```cpp
OpenABECurveID OpenABE_convertStringToCurveID(const string paramsID) {
    const CurveInfo* info = getCurveInfo(paramsID);

    if (info == nullptr) {
        fprintf(stderr, "ERROR: Unknown curve: %s\n", paramsID.c_str());
        fprintf(stderr, "Supported curves:\n");
        auto curves = listAllCurves();
        for (const auto* curve : curves) {
            fprintf(stderr, "  - %s (%d-bit security)\n",
                    curve->name, curve->security_level);
        }
        return OpenABE_NONE_ID;
    }

    // Print warnings for weak/deprecated curves
    if (strcmp(info->status, "weak") == 0) {
        fprintf(stderr, "WARNING: %s provides only ~%d-bit security\n",
                info->name, info->security_level);
        fprintf(stderr, "         This is INSECURE for production use!\n");
        fprintf(stderr, "         %s\n", info->notes);
    } else if (strcmp(info->status, "deprecated") == 0) {
        fprintf(stderr, "WARNING: %s is DEPRECATED (~%d-bit security)\n",
                info->name, info->security_level);
        fprintf(stderr, "         %s\n", info->notes);
    }

    return info->id;
}

string OpenABE_convertCurveIDToString(OpenABECurveID id) {
    const CurveInfo* info = getCurveInfo(id);
    return info ? string(info->name) : "INVALID";
}

// List available curves
std::vector<std::string> OpenABE_listAvailableCurves() {
    std::vector<std::string> names;
    auto curves = listAllCurves();
    for (const auto* curve : curves) {
        names.push_back(curve->name);
    }
    return names;
}

// List recommended curves only
std::vector<std::string> OpenABE_listRecommendedCurves() {
    std::vector<std::string> names;
    auto curves = listRecommendedCurves();
    for (const auto* curve : curves) {
        names.push_back(curve->name);
    }
    return names;
}
```

### 5. CLI Tool for Curve Information

**New File: `cli/oabe_list_curves.cpp`**

```cpp
#include <openabe/openabe.h>
#include <iostream>
#include <iomanip>

using namespace std;
using namespace oabe;

int main(int argc, char** argv) {
    cout << "OpenABE Supported Curves" << endl;
    cout << "=========================" << endl << endl;

    auto curves = listAllCurves();

    // Group by family
    map<string, vector<const CurveInfo*>> families;
    for (const auto* curve : curves) {
        families[curve->family].push_back(curve);
    }

    for (const auto& [family, family_curves] : families) {
        cout << family << " Family:" << endl;
        cout << string(family.length() + 8, '-') << endl;

        for (const auto* curve : family_curves) {
            cout << left << setw(15) << curve->name;
            cout << setw(10) << (to_string(curve->field_bits) + "-bit");
            cout << setw(15) << (to_string(curve->security_level) + " bits");
            cout << setw(12) << curve->status;
            cout << endl;
            cout << "    " << curve->notes << endl;
        }
        cout << endl;
    }

    cout << "Recommended for New Projects:" << endl;
    cout << "-----------------------------" << endl;
    auto recommended = listRecommendedCurves();
    for (const auto* curve : recommended) {
        if (strcmp(curve->status, "recommended") == 0) {
            cout << "  ★ " << curve->name << " - " << curve->notes << endl;
        }
    }

    return 0;
}
```

Output example:
```
OpenABE Supported Curves
=========================

BLS12 Family:
-------------
BLS12_377      377-bit    120 bits       good
    Used by Aleo, good performance
BLS12_381      381-bit    128 bits       recommended
    Industry standard - Ethereum 2.0, Zcash, Filecoin
BLS12_446      446-bit    128 bits       good
    BLS12 curve with extra security margin
...

Recommended for New Projects:
-----------------------------
  ★ BLS12_381 - Industry standard - Ethereum 2.0, Zcash, Filecoin
```

### 6. Build System: Multi-Curve Support

**Option A: Single Build with Runtime Selection** (BEST)

Support all curves in one build by compiling RELIC with appropriate options:

```cmake
# RELIC supports multiple curves at once!
cmake -DMULTI=PTHREAD \
      -DFP_PRIME=381,446,509,638 \
      -DWITH=BN;DV;FP;FPX;EP;EPX;PP;PC;MD \
      ...
```

**Option B: Build-Time Selection**

```makefile
# User selects curve at build time
PAIRING_CURVE ?= BLS12_381

# Build for that curve
make PAIRING_CURVE=BLS12_381
make PAIRING_CURVE=BLS12_638
```

### 7. Default and Recommendations

**File: `src/include/openabe/openabe.h`**

```cpp
// Recommended default (can be overridden at build time)
#ifndef DEFAULT_BP_PARAM
  #define DEFAULT_BP_PARAM "BLS12_381"  // Industry standard, 128-bit security
#endif

const std::string DEFAULT_BP_PARAM = DEFAULT_BP_PARAM;
const std::string RECOMMENDED_MIN_SECURITY_LEVEL = "128";  // bits
```

## Benefits of Universal Curve Support

### 1. **Security Flexibility** ✅
```cpp
// Performance-critical system
cpabe->generateParams("BLS12_377");  // ~120 bits, fastest

// Standard security
cpabe->generateParams("BLS12_381");  // ~128 bits, recommended

// High security government system
cpabe->generateParams("BLS24_509");  // ~192 bits, future-proof
```

### 2. **Interoperability** ✅
Match other systems' curve choices:
- Ethereum 2.0 → BLS12-381
- Aleo → BLS12-377
- Custom systems → Any supported curve

### 3. **Migration Path** ✅
```cpp
// Old system
decrypt_with_curve("BN_P254", old_ciphertext);  // Works with warning

// New system
encrypt_with_curve("BLS12_381", new_data);  // Recommended

// Transition both supported
```

### 4. **Future-Proofing** ✅
When new curves become available in RELIC/MCL:
1. Add curve ID constant
2. Add entry to CURVE_DATABASE
3. Update string conversion
4. Done! No API changes needed.

## Conclusion

**Supporting all available curves is the right design** because:

1. ✅ **User choice**: Different requirements need different tradeoffs
2. ✅ **Minimal cost**: Curves already implemented in RELIC/MCL
3. ✅ **Future-proof**: Easy to add new curves
4. ✅ **Compatibility**: Can match other systems
5. ✅ **Migration**: Smooth transition from legacy curves

The key is to:
- **Expose all curves** with clear metadata
- **Recommend BLS12-381** as the default
- **Warn about deprecated curves** (BN254)
- **Let users choose** based on their needs

This is much better than artificially limiting to one curve!
