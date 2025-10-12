#include <openabe/openabe.h>
#include <iostream>

using namespace oabe;

int main() {
  Init initialize
  InitializeOpenABE();
  
  auto pairing = std::make_shared<OpenABEPairing>("BN_P254");
  auto rng = std::make_unique<OpenABERNG>();
  
  ZP r = pairing->randomZP(rng.get());
  ZP neg_r = -r;
  
  std::cout << "r: " << r << std::endl;
  std::cout << "-r: " << neg_r << std::endl;
  
  ZP sum = r + neg_r;
  std::cout << "r + (-r): " << sum << std::endl;
  std::cout << "Is zero? " << sum.isZero() << std::endl;
  
  ShutdownOpenABE();
  return 0;
}
