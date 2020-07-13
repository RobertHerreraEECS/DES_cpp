# DES Encryption

DES Encryption is a c++ based application that aims to re-work an initial implementation of the DES encryption scheme bradosev03 and I did a few years ago. 


## Notes

* Ensure cmake is installed on your machine. You may need to modify the cmake file for right now if your machine is not on MAC OSX

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

## TODO
* <strike> Fix cmake RPATH issue with shared libraries </strike>
* Add more wrapping logic
** Improve random number generation
* Add encryption via file input
* Add user interface to main
* Add ICBC - Interleaved CBC Mode
* <strike> Add CBC/Counter Modes of Operation </strike>
* <strike> Add unit tests </strike>
* <strike> Add zero padding </strike>

# DES_cpp
* Interface layer that handles file reading and encryption/decryption modes

# DES
* C Implementation of DES Cipher
