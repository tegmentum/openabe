# LSSS Secret Reconstruction Check

For 2-attribute AND policy `(developer and engineering)`, threshold = 2:

## Lagrange Coefficients (for reconstruction at x=0):
- λ₀ = (-2)/(-1) = 2
- λ₁ = (-1)/(1) = -1

## Property: Σ λᵢ should equal number of attributes for AND gate
- λ₀ + λ₁ = 2 + (-1) = 1

**This is WRONG! For an AND gate with threshold=2, we should have Σ λᵢ = 1**

Wait, let me recalculate. For Lagrange interpolation at x=0:
- Points are at x=1 and x=2
- λ₀ = (0-2)/(1-2) = -2/-1 = 2 ✓
- λ₁ = (0-1)/(2-1) = -1/1 = -1 ✓
- λ₀ + λ₁ = 2 + (-1) = 1 ✓

So the sum is correct! The coefficients themselves are correct.

##Question: Are the shares correct?

During encryption with LSSS, for threshold=2:
- Pick random coefficients: a₀ = s (the secret), a₁ = random
- Polynomial: f(x) = a₀ + a₁*x = s + a₁*x
- share₀ = f(1) = s + a₁
- share₁ = f(2) = s + 2*a₁

For reconstruction:
- s = Σ λᵢ * shareᵢ
- s = λ₀*share₀ + λ₁*share₁
- s = 2*(s + a₁) + (-1)*(s + 2*a₁)
- s = 2s + 2a₁ - s - 2a₁
- s = s ✓

So mathematically the LSSS should work!

