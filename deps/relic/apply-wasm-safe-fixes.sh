#!/bin/bash
# Apply WASM-safe fixes to RELIC 0.7.0 fp_smb.c
# This fixes boolean-to-mask conversions and shift operations that fail in WebAssembly

FILE="$1/src/fp/relic_fp_smb.c"

if [ ! -f "$FILE" ]; then
    echo "Error: File not found: $FILE"
    exit 1
fi

echo "Applying WASM-safe fixes to $FILE..."

# Create backup
cp "$FILE" "$FILE.orig"

# Add helper macros after the "Private definitions" comment
sed -i '' '/^\/\*=*\*\/$/,/^\/\* Private definitions/{
/^\/\* Private definitions/a\
\
/**\
 * WASM-safe helper macros for boolean-to-mask conversions.\
 * These ensure explicit conversions that work correctly in WebAssembly.\
 */\
\
/* Convert boolean condition (0 or 1) to all-bits mask (0x0 or 0xFFFFFFFFFFFFFFFF) */\
#define BOOL_TO_MASK(cond) ((dig_t)0 - (dig_t)((cond) != 0))\
\
/* Safe left shift across two limbs */\
#ifdef __wasm__\
/* WASM-safe version: avoid undefined behavior with conditional */\
#define RLC_LSH_SAFE(H, L, I) \\\
	((I) == 0 ? (H) : ((I) >= RLC_DIG ? (dig_t)0 : (((H) << (I)) | ((L) >> (RLC_DIG - (I))))))\
#else\
/* Original optimized version for native platforms */\
#define RLC_LSH_SAFE(H, L, I) \\\
	(((H) << (I)) | ((L) & -(I != 0)) >> ((RLC_DIG - (I)) & (RLC_DIG - 1)))\
#endif\
\
/* Safe sign bit extraction to mask */\
#define SIGN_TO_MASK(val) BOOL_TO_MASK((val) >> (RLC_DIG - 1))\

}' "$FILE"

# Fix porninstep function variable declaration
sed -i '' 's/dig_t t_lo, t_hi, odd, borrow, xorm;/dig_t t_lo, t_hi, odd, borrow, borrow_cond, xorm;/' "$FILE"

# Fix boolean-to-mask in porninstep (first occurrence)
sed -i '' '/for (size_t i = 0; i < s; i+=2) {/,/k += (f_lo + 2) >> 2;/{
s/odd = 0 - (g_lo & 1);/\/* WASM-safe: Explicit boolean to mask conversion *\/\
		odd = BOOL_TO_MASK(g_lo \& 1);/
}' "$FILE"

# Fix complex borrow calculation (all occurrences)
sed -i '' 's/borrow = -((g_hi < limbx) || (borrow \&\& !limbx));/\/* WASM-safe: Explicit conversion of complex boolean expression *\/\
		borrow_cond = (g_hi < limbx) || (borrow \&\& !limbx);\
		borrow = BOOL_TO_MASK(borrow_cond);/' "$FILE"

# Fix jumpdivstep boolean-to-mask
sed -i '' 's/c1 = -(x & 1);/\/* WASM-safe: Explicit boolean to mask conversion *\/\
		c1 = BOOL_TO_MASK(x \& 1);/' "$FILE"

# Remove old RLC_LSH macro definition in BINAR section
sed -i '' '/#if FP_SMB == BINAR/,/int fp_smb_binar/{
/#define RLC_LSH(H, L, I)/,/^$/d
}' "$FILE"

# Fix sign bit extraction in fp_smb_binar
sed -i '' 's/mask = -(l >> (RLC_DIG - 1));/\/* WASM-safe: Explicit sign bit extraction to mask *\/\
				mask = SIGN_TO_MASK(l);/' "$FILE"

# Fix RLC_LSH usage to use RLC_LSH_SAFE
sed -i '' 's/f_\[0\] = f\[0\], f_\[1\] = RLC_LSH(f_hi, f_lo, len);/\/* WASM-safe: Use safe left shift macro *\/\
			f_[0] = f[0], f_[1] = RLC_LSH_SAFE(f_hi, f_lo, len);/' "$FILE"
sed -i '' 's/g_\[0\] = g\[0\], g_\[1\] = RLC_LSH(g_hi, g_lo, len);/g_[0] = g[0], g_[1] = RLC_LSH_SAFE(g_hi, g_lo, len);/' "$FILE"

# Fix DIVST mask conversions
sed -i '' 's/mask = -d0;/\/* WASM-safe: Explicit conversion *\/\
			mask = BOOL_TO_MASK(d0);/' "$FILE"
sed -i '' 's/g\[j\] ^= s ^ (-d0);/\/* WASM-safe: Explicit conversion *\/\
				g[j] ^= s ^ BOOL_TO_MASK(d0);/' "$FILE"
sed -i '' 's/t\[j\] = f\[j\] & (-g0);/\/* WASM-safe: Explicit conversion *\/\
				t[j] = f[j] \& BOOL_TO_MASK(g0);/' "$FILE"

echo "WASM-safe fixes applied successfully!"
echo "Backup saved as: $FILE.orig"
