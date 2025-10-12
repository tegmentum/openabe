///
/// \file   zelement_ec_mcl.cpp
///
/// \brief  MCL-based EC operations for secp256k1.
///         Implements EC abstraction layer using MCL's secp256k1 support.
///
/// \author OpenABE Contributors
///

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openabe/zml/zelement.h>
#include <openabe/utils/zconstants.h>

#if defined(EC_WITH_MCL)

#include <mcl/ec.hpp>
#include <mcl/ecdsa.hpp>

namespace {
// MCL EC types for secp256k1
typedef mcl::FpT<> Fp;
typedef mcl::FrT<> Fr;
typedef mcl::EcT<Fp> Ec;

static bool mcl_ec_initialized = false;
static Ec generator;
static mpz_class ec_order;
}

/********************************************************************************
 * EC Group Initialization
 ********************************************************************************/

extern "C" {

int ec_group_init(ec_group_t *group, uint8_t id) {
    (void)id; // MCL only supports secp256k1 currently

    if (!mcl_ec_initialized) {
        // Initialize MCL for secp256k1
        bool pb;
        mcl::initCurve<Ec>(&pb, MCL_SECP256K1, &generator, mcl::ec::Jacobi);
        if (!pb) {
            fprintf(stderr, "MCL EC initialization failed for secp256k1\n");
            return -1;
        }

        // Store the order
        const mcl::EcParam *ecParam = mcl::getEcParam(MCL_SECP256K1);
        if (ecParam) {
            gmp::setStr(&pb, ec_order, ecParam->n);
            if (!pb) {
                fprintf(stderr, "Failed to set EC order\n");
                return -1;
            }
        }

        mcl_ec_initialized = true;
    }

    // Return non-null group handle
    *group = (void*)0x1;
    return 0;
}

void ec_get_order(ec_group_t group, bignum_t order) {
    (void)group;
    // Convert ec_order to bignum_t
    if (mcl_ec_initialized) {
        gmp::getArray(&pb, static_cast<mclBnFr*>(order)->d,
                      sizeof(mclBnFr)/sizeof(uint64_t), ec_order);
    }
}

/********************************************************************************
 * EC Point Operations
 ********************************************************************************/

void ec_point_init(ec_group_t group, ec_point_t *e) {
    (void)group;
    *e = new Ec();
    if (*e) {
        static_cast<Ec*>(*e)->clear();
    }
}

void ec_point_copy(ec_point_t to, const ec_point_t from) {
    if (to && from) {
        *static_cast<Ec*>(to) = *static_cast<const Ec*>(from);
    }
}

void ec_point_set_inf(ec_group_t group, ec_point_t p) {
    (void)group;
    if (p) {
        static_cast<Ec*>(p)->clear();
    }
}

int ec_point_cmp(ec_group_t group, const ec_point_t a, const ec_point_t b) {
    (void)group;
    if (!a || !b) return -1;

    const Ec* pa = static_cast<const Ec*>(a);
    const Ec* pb = static_cast<const Ec*>(b);

    if (*pa == *pb) return 0;
    return 1;
}

int ec_point_is_inf(ec_group_t group, ec_point_t p) {
    (void)group;
    if (!p) return 1;
    return static_cast<Ec*>(p)->isZero() ? 1 : 0;
}

void ec_get_generator(ec_group_t group, ec_point_t p) {
    (void)group;
    if (p && mcl_ec_initialized) {
        *static_cast<Ec*>(p) = generator;
    }
}

void ec_get_coordinates(ec_group_t group, bignum_t x, bignum_t y, const ec_point_t p) {
    (void)group;
    if (!p) return;

    Ec point = *static_cast<const Ec*>(p);
    point.normalize(); // Convert to affine coordinates

    // Convert Fp to bignum_t (mclBnFr)
    // This requires converting MCL's Fp to our bignum format
    // For now, we'll use getStr and setStr as a workaround

    char buf[256];
    size_t len;

    // Get x coordinate
    {
        std::ostringstream oss;
        oss << point.x;
        std::string str = oss.str();
        mclBnFr_setStr(static_cast<mclBnFr*>(x), str.c_str(), str.length(), 10);
    }

    // Get y coordinate
    {
        std::ostringstream oss;
        oss << point.y;
        std::string str = oss.str();
        mclBnFr_setStr(static_cast<mclBnFr*>(y), str.c_str(), str.length(), 10);
    }
}

int ec_convert_to_point(ec_group_t group, ec_point_t p, uint8_t *xstr, int len) {
    (void)group;
    if (!p) return -1;

    // Deserialize point from compressed format
    try {
        std::string str((char*)xstr, len);
        std::istringstream iss(str);
        static_cast<Ec*>(p)->load(iss, mcl::IoSerialize);
        return 0;
    } catch (...) {
        return -1;
    }
}

int ec_point_is_on_curve(ec_group_t group, ec_point_t p) {
    (void)group;
    if (!p) return 0;
    return static_cast<Ec*>(p)->isValid() ? 1 : 0;
}

void ec_point_add(ec_group_t g, ec_point_t r, const ec_point_t x, const ec_point_t y) {
    (void)g;
    if (!r || !x || !y) return;

    Ec::add(*static_cast<Ec*>(r),
            *static_cast<const Ec*>(x),
            *static_cast<const Ec*>(y));
}

void ec_point_mul(ec_group_t g, ec_point_t r, const ec_point_t x, const bignum_t y) {
    (void)g;
    if (!r || !x || !y) return;

    // Convert bignum_t (mclBnFr) to Fr for multiplication
    Fr scalar;
    memcpy(&scalar, y, sizeof(mclBnFr));

    Ec::mul(*static_cast<Ec*>(r),
            *static_cast<const Ec*>(x),
            scalar);
}

/********************************************************************************
 * Serialization Operations
 ********************************************************************************/

size_t ec_point_elem_len(const ec_point_t g) {
    // Compressed point: 1 byte header + 32 bytes x-coordinate
    return 33;
}

void ec_point_elem_in(ec_point_t g, uint8_t *in, size_t len) {
    if (!g) return;

    try {
        cybozu::MemoryInputStream mis(in, len);
        static_cast<Ec*>(g)->load(mis, mcl::IoSerialize);
    } catch (...) {
        fprintf(stderr, "ec_point_elem_in: deserialization failed\n");
    }
}

void ec_point_elem_out(const ec_point_t g, uint8_t *out, size_t len) {
    if (!g) return;

    try {
        cybozu::MemoryOutputStream mos(out, len);
        static_cast<const Ec*>(g)->save(mos, mcl::IoSerialize);
    } catch (...) {
        fprintf(stderr, "ec_point_elem_out: serialization failed\n");
    }
}

} // extern "C"

#endif /* EC_WITH_MCL */
