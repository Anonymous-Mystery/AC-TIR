# AC-TIR

This is the code for the paper "AC-TIR: Fast Anonymous Credentials with Threshold Issuance and Revocation".

This paper proposes a fast anonymous credential scheme that suport threshold issuance and revocation. The code uses the Charm library in Python. Besides, we also provide the implementation of the following schemes:

1. Coconut, NDSS, 2018 [1]
2. Coconut', eprint Archive, 2022 [2]

All schemes are implemented using asymmetric Type-III pairing groups.

The schemes have been tested with Charm 0.50 and Python 3.9.16 on Ubuntu 22.04. (Note that Charm may not compile on newer Linux systems due to the incompatibility of OpenSSL versions 1.0 and 1.1.).


## Manual Installation

Charm 0.50 can also be installed directly from [this] (https://github.com/JHUISI/charm) page, or by running

```sh
pip install -r requirements.txt
```
Once you have Charm, run
```sh
make && pip install . && python samples/run_cp_schemes.py
```

## References

1. Alberto Sonnino, Mustafa Al-Bassam, Shehar Bano, Sarah Meiklejohn, George Danezis. Coconut: Threshold Issuance Selective Disclosure Credentials with Applications to Distributed Ledgers. Network and Distributed Systems Security (NDSS) Symposium 2019. 
2. Alfredo Rial and Ania M. Piotrowska. Security Analysis of Coconut, an Attribute-Based Credential Scheme with Threshold Issuance. Eprint Archive 2022/011.

