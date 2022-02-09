#!/usr/bin/env python3.6

'''Quick script to test different modes of operation
    and compare against openssl output.
'''

import sys, os
from subprocess import Popen, PIPE


mode_ops = ['ecb', 'cbc', 'cfb', 'ofb']
modes = ['enc', 'dec']

des_crypt_cmd = [
            './cryptdes',
            'test.txt',
            'out.bin',
            '-C',
            'enc',
            '-K',
            '0E329232EA6D0D73'
        ]

openssl_cmd = [
            'openssl',
            'enc',
            '-des-ecb',
            '-in',
            'test.txt',
            '-out',
            'test-no.enc',
            '-K',
            '0E329232EA6D0D73'
        ]

diff_cmd = [
            'diff',
            'file1',
            'file2',
        ]

def run_command(cmd):
    process = Popen(cmd, stdout=PIPE, stderr=PIPE)
    stderr, stdout = process.communicate()
    return process.returncode

def usage():
    print("python tester.py <cryptdes_binary> <infile>")

def main():
    if len(sys.argv) < 3:
        usage()
        sys.exit(-1)

    crypt_bin = sys.argv[1]
    selected_mode_op = "ecb"
    selected_mode = "enc"
    infile = sys.argv[2]
    crypt_out = "crypt.enc"
    openssl_out = "openssl.enc"
   
    des_crypt_cmd[0] = crypt_bin
    des_crypt_cmd[1] = infile
    des_crypt_cmd[2] = crypt_out
    crypt_result = run_command(des_crypt_cmd)
    if crypt_result != 0:
        print('Error running cryptdes command')
        return -1

    openssl_cmd[4] = infile
    openssl_cmd[6] = openssl_out
    openssl_result = run_command(openssl_cmd)
    if openssl_result != 0:
        print('Error running openssl command')
        return -1

    diff_cmd[1] = crypt_out
    diff_cmd[2] = openssl_out
    res = run_command(diff_cmd)
    if res < 0:
        print('An error occurred')
    elif res > 0:
        print("The files differ")
    else:
        print("Files are the same.")
    return 0
    
    
if __name__ == '__main__':
    main()
