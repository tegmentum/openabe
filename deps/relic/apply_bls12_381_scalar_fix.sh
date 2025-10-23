#!/bin/bash
# Apply Bug #19 fix for BLS12-381 sliding window buffer size
# This script is called automatically during RELIC build process

# Fix all occurrences of RLC_FP_BITS in scalar multiplication functions
# Use [[:space:]]* for whitespace (macOS sed compatible)
sed -i.bak 's/\(^[[:space:]]*l = \)RLC_FP_BITS\( + 1;\)/\1RLC_BN_BITS\2/g' \
    src/ep/relic_ep_mul.c \
    src/ep/relic_ep_mul_fix.c \
    src/epx/relic_ep2_mul.c \
    src/epx/relic_ep3_mul.c \
    src/epx/relic_ep4_mul.c \
    src/epx/relic_ep8_mul.c \
    src/ed/relic_ed_mul.c \
    src/ed/relic_ed_mul_fix.c

echo "Applied BLS12-381 scalar buffer fix (Bug #19)"
