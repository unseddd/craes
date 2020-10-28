# DO NOT USE THIS LIBRARY

## Shitty, non-optimized (hopefully correct) AES implementation in pure no_std Rust

DO NOT USE THIS LIBRARY FOR REAL SHIT, OR THE WORST THINGS WILL HAPPEN

- Sia will read your private messages
- Phoebe will compromise your eBay purchase
- Ensa will listen to your encrypted phone call

Seriously though, I have done my best to follow the [FIPS-197](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf) specification,
but the library has not been tested for side-channel resistance, or other cryptanalytic attacks.

I coded this AES implementation to learn more about how AES actually works.

To run the tests, and verify the implementation:

```
git clone https://github.com/unseddd/craes.git
cd craes
cargo test --all
```
