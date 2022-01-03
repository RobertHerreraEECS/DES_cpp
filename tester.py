#!/usr/bin/env python3.6

import sys, os
import subprocess

des_crypt_cmd = [
            './cryptdes',
            'test.txt',
            'out.bin',
            '-K',
            'deadbeeffaceface'
        ]

openssl_cmd = [
            'openssl',
            'enc',
            '-des-ecb',
            '-nopad',
            '-in',
            'test.txt',
            '-out',
            'test-no.enc',
            '-K',
            '0E329232EA6D0D73'
        ]

def main():
    pass

if __name__ == '__main__':
    main()
