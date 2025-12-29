#include <openabe/openabe.h>
#include <iostream>

using namespace oabe;

int main() {
  // Initialize
  InitializeOpenABE();

  auto pairing = std::make_shared<OpenABEPairing>("BN_P254");
  OpenABERNG rng;

  ZP r = pairing->randomZP(&rng);
  ZP neg_r = -r;

  std::cout << "r: " << r << std::endl;
  std::cout << "-r: " << neg_r << std::endl;

  ZP sum = r + neg_r;
  std::cout << "r + (-r): " << sum << std::endl;

  // Check if zero by comparing to zero element
  ZP zero = pairing->initZP();
  std::cout << "sum == zero? " << (sum == zero) << std::endl;

  ShutdownOpenABE();
  return 0;
}
