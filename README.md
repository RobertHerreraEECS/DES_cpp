# DES Encryption

DES Encryption is a c++ based application that aims to re-work an initial implementation of the DES encryption scheme bradosev03 and I did a few years ago. 


## Notes
* To execute:
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
* Interface layer that handles file reading and encryption/decryption modes

# DES
* C Implementation of DES Cipher
