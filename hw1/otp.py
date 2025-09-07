#!/usr/bin/env python3
import os, sys       # do not use any other imports/libraries
# took 2.5 hours (please specify here how much time your solution required)

def bi(b):
    # b - bytes to encode as an integer
    # your implementation here
    i = 0
    for num in range(len(b)):
        i = i << 8
        i = i | b[num]
    return i

def ib(i, length):
    # i - an integer to encode as bytes
    # length - specifies in how many bytes the integer should be encoded
    # your implementation here
    b = b''
    for j in range(length):
        shift = (length - 1 - j)*8
        byte = (i >> shift) & 0xff
        b += bytes([byte])
    return b

def encrypt(pfile, kfile, cfile):
    # your implementation here
    pfileD = open(pfile, 'rb').read()
    pfileint = bi(pfileD)
    kfileint = bi(open(kfile, 'rb').read())
    final = pfileint ^ kfileint
    open(cfile, 'wb').write(ib(final, len(pfileD)))
    return 

def decrypt(cfile, kfile, pfile):
    # your implementation here
    cfileD = open(cfile, 'rb').read()
    cfileint = bi(open(cfile, 'rb').read())
    kfileint = bi(open(kfile, 'rb').read())
    final = cfileint ^ kfileint
    open(pfile, 'wb').write(ib(final, len(cfileD)))
    pass

def usage():
    print("Usage:")
    print("encrypt <plaintext file> <output key file> <ciphertext output file>")
    print("decrypt <ciphertext file> <key file> <plaintext output file>")
    sys.exit(1)

if len(sys.argv) != 5:
    usage()
elif sys.argv[1] == 'encrypt':
    encrypt(sys.argv[2], sys.argv[3], sys.argv[4])
elif sys.argv[1] == 'decrypt':
    decrypt(sys.argv[2], sys.argv[3], sys.argv[4])
else:
    usage()
