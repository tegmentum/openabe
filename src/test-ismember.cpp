#include <stdio.h>
#include <openabe/openabe.h>

using namespace oabe;

int main() {
    InitializeOpenABE();

    OpenABECryptoContext cpabe("CP-ABE");

    unique_ptr<OpenABEContextSchemeCPWaters> scheme_context = nullptr;
    scheme_context.reset(new OpenABEContextSchemeCPWaters(false));

    OpenABEPairing *pgroup = scheme_context->getPairing();

    ZP zero, one, two;
    pgroup->initZP(zero, 0);
    pgroup->initZP(one, 1);
    pgroup->initZP(two, 2);

    printf("Zero: %s\n", zero.getBytesAsString().c_str());
    printf("One: %s\n", one.getBytesAsString().c_str());
    printf("Two: %s\n", two.getBytesAsString().c_str());

    ZP z0 = (zero - one) / (two - one);
    printf("z0 = (0 - 1) / (2 - 1) = %s\n", z0.getBytesAsString().c_str());
    printf("z0 ismember: %s\n", z0.ismember() ? "true" : "false");

    // Get the order
    bignum_t order;
    zml_bignum_init(&order);
    pgroup->getOrder(order);

    char order_str[256];
    zml_bignum_toDecimal(order, order_str, sizeof(order_str));
    printf("Curve order: %s\n", order_str);

    // Check comparison
    int cmp_result = zml_bignum_cmp(z0.getBignum(), order);
    printf("cmp(z0, order) = %d (should be %d for LT)\n", cmp_result, BN_CMP_LT);

    int sign = zml_bignum_sign(z0.getBignum());
    printf("sign(z0) = %d (should be %d for POSITIVE)\n", sign, BN_POSITIVE);

    ShutdownOpenABE();
    return 0;
}
