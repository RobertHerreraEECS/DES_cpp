# DES Encryption

DES Encryption is a c++ based application that aims to re-work an initial implementation of the DES cipher that bradosev03 and I did a few years ago. 

OpenSSL supports PKCS padding by default so its recommeded that you use this in PKCS5 padding mode. This padding scheme is more reliable compared to zero padding. Zero padding contains edge cases where you may not be able to guarantee exact recovery the original plaintext data.

DES CPP runs in ECB Mode by default unless otherwise specified on the command line.

## Notes
execute:
<pre>
    # make build environment at root directory level
    mkdir build
    cd build
    cmake ../
    make
    # execute main program
    ./lib/main
    # execute and validate unit tests
    ./lib/unittests/desTest
</pre>


# DES_cpp
Interface layer that handles file reading and encryption/decryption modes.

run ```./bin/main``` to print usage.

# Help
```
usage:

./main INPUT_FILE OUTPUT_FILE -K KEY <OPTIONS...>
-C [enc | dec] (required): cipher mode
-M [ecb | cbc | cfb | ofb]: (ecb by default)
-K [hexlifed 8-byte value] (required): 8-byte hexlified key
-N [hexlifed 8-byte value]: 8-byte IV used in chaining modes.
-P [zero | pkcs] (pkcs by default)

info:
--- DES Encrypt ---
This program is capable of encrypting/decrypting an input file using the
DES cipher. The encrypted/decrypted blobs are compatible with
OpenSSL and have been tested against OpenSSL-generated
encrypted/decrypted blobs.


example:
./main plaintext ciphertext -K deadbeeffacefade -C enc
```

# DES
C Implementation of DES Cipher. The DES Crypto Context accepts input of arbitrary size and generates an allocated buffer. The allocated buffer is sized to nearest block size or 8-byte multiple, and pads using either zero padding or PKCS5 padding scheme.

Zero padding, in this implementation, is defined as implicity allocating the output buffer as an 8-byte (64-bit) multiple and leaving the remaining unfilled data as null-bytes.

CPP main output is compared against OpenSSL in several modes of operation.

# Supported Modes of Operation
* ECB
* CBC
* CFB
* OFB
