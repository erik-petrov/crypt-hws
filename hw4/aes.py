#!/usr/bin/env python3

import time, os, sys
from pyasn1.codec.der import decoder

# $ sudo apt-get install python3-pycryptodome
sys.path = sys.path[1:] # removes current directory from aes.py search path
#
from Cryptodome.Cipher import AES          # https://pycryptodome.readthedocs.io/en/latest/src/cipher/classic.html#ecb-mode
from Cryptodome.Util.strxor import strxor  # https://pycryptodome.readthedocs.io/en/latest/src/util/util.html#crypto-util-strxor-module
from hashlib import pbkdf2_hmac
import hashlib, hmac # do not use any other imports/libraries

# took x.y hours (please specify here how much time your solution required)
BLOCK_SIZE = 16
#==== ASN1 encoder start ====
def bi(b):
    # b - bytes to encode as an integer
    # your implementation here
    i = 0
    for num in range(len(b)):
        i = i << 8
        i = i | b[num]
    return i

def asn1_objectidentifier(oid):
    # oid - list of integers representing OID (e.g., [1,2,840,123123])
    # returns DER encoding of OBJECTIDENTIFIER
    tag = bytes([0x06])
    firstTwo = 40*oid[0]+oid[1]
    other=b''
    for i in range(2, len(oid)):
        other += ibOid(oid[i])
    val = bytes([firstTwo])+other
    return tag+asn1_len(val)+val

def asn1_sequence(der):
    # der - DER bytes to encapsulate into sequence
    # returns DER encoding of SEQUENCE
    tag = bytes([0x30])
    ln = asn1_len(der)
    return tag+ln+der

def asn1_octetstring(octets):
    # octets - arbitrary byte string (e.g., b"abc\x01")
    # returns DER encoding of OCTETSTRING
    tag = bytes([0x04])
    len = asn1_len(octets)
    return tag+len+octets

def asn1_integer(i):
    if i < 0:
        raise ValueError
    
    type = bytes([0x02])
    
    if i == 0:
        return type+bytes([0x01])+ib(i)
    
    numBin = ib(i)
    if numBin[0] & 0x80 == 0x80:
        ln = asn1_len(numBin, True)
        numBin = bytes([0x00]) + numBin
    else:
        ln = asn1_len(numBin)

    return type+ln+numBin

def asn1_len(value_bytes, int_ex=False, val=1):
    # helper function - should be used in other functions to calculate length octet(s)
    # value_bytes - bytes containing TLV value byte(s)
    # returns length (L) byte(s) for TLV
    if len(value_bytes) == 0:
        return b'\x00'

    try:
        length = len(value_bytes)
    except:
        length = numOfBytesNeeded(bi(value_bytes))

    #when asn1_integer has MSB == 1 and idk better solutions
    if int_ex:
        length += val

    if length < 128:
        return ib(length)

    return bytes([0x80|numOfBytesNeeded(length)])+ib(length)

def ib(i):
    if i == 0:
        return b'\x00'
    # i - an integer to encode as bytes
    # length - specifies in how many bytes the integer should be encoded
    # your implementation here
    b = b''
    len=numOfBytesNeeded(i)
    for j in range(len):
        shift = (len - 1 - j)*8
        byte = (i >> shift) & 0xff
        b += bytes([byte])
    return b

def ibOid(i):
    b=b''
    ln=numOfBytesNeeded(i, 7)
    for n in range(ln):
        shift = (ln - 1 - n)*7
        byte = (i >> shift) & 0xff
        if shift == 0:
            byte &= 0x7f
        else:
            byte |= 0x80
        b += bytes([byte])
    return b        

def numOfBytesNeeded(num, bits=8):
    if num == 0:
        return 1

    bytes = 0
    while num > 0:
        num >>= bits
        bytes += 1
        
    return bytes

def asn1_null():
    # returns DER encoding of NULL
    return bytes([0x05])+bytes([0x00])
#==== ASN1 encoder end ====


# this function benchmarks how many PBKDF2 iterations
# can be performed in one second on the machine it is executed
def benchmark():
    iter = 10000
    start = time.time()
    # measure time for performing 10000 iterations
    pbkdf2_hmac('sha1', b"passwordofadecentlength", b"0x00"*8, iter, 48)
    end = time.time()
    # extrapolate to 1 second
    iter = int(end-start/10000)
    print("[+] Benchmark: %s PBKDF2 iterations in 1 second" % (iter))

    return iter # returns number of iterations that can be performed in 1 second


def encrypt(pfile, cfile):
    iter = benchmark()

    pswd = input("password: ")
    
    salt = os.urandom(8)
    key = pbkdf2_hmac('sha1', pswd, salt, iter, 48)

    with open(pfile, 'rb') as f:
        data = f.read()
    
    padding_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    padding = bytes([padding_len]) * padding_len 
    padded_data = data + padding

    key_aes = key[:16]
    cipher = AES.new(key_aes, AES.MODE_ECB)
    mac = []
    ivOg = os.urandom(16)
    iv = ivOg
    for i in range(0, len(padded_data), BLOCK_SIZE):
        p_data = padded_data[i:i + BLOCK_SIZE]
        temp = strxor(p_data, iv)
        cipher_e = cipher.encrypt(temp)
        mac.append(cipher_e)

        iv = cipher_e
    
    ciphertext = b"".join(mac)

    mac_k = hmac.new(key[16:], ciphertext, hashlib.sha256).digest()
    
    der = asn1_sequence(
        asn1_sequence(
            asn1_octetstring(salt),
            asn1_integer(iter),
            asn1_integer(48)
        ),
        asn1_sequence(
            asn1_objectidentifier([2,16,840,1,101,3,4,1,2]),
            asn1_octetstring(ivOg)
        ),
        asn1_sequence(
            asn1_sequence(
                asn1_objectidentifier(2,16,840,1,101,3,4,2,1),
                asn1_null()
            ),
            asn1_octetstring(mac_k)
        )
    )
    with open(cfile, 'wb') as f:
        f.write(der + ciphertext)


def decrypt(cfile, pfile):
    # reading DER header and ciphertext
    f = open(cfile, 'rb')
    contents = f.read()
    asn1, ciphertext = decoder.decode(contents)
    f.close()

    pswd = input("password: ")
    
    iter = asn1[0][1]
    salt = asn1[0][0]
    keys = pbkdf2_hmac('sha1', pswd, salt, iter, 48)

    k_e = keys[:16]
    k_m = keys[16:]

    iv = asn1[1][1]
    mac_k = asn1[2[1]]

    mac = hmac.new(k_m, iv+ciphertext, hashlib.sha256).digest()
    
    cipher = AES.new(k_e, AES.MODE_ECB)

    if not hmac.compare_digest(mac, mac_k):
        print("[!] wrong pswd")
        sys.exit(1)

    dec = []

    for i in range(0, len(ciphertext), BLOCK_SIZE):
        c_i = ciphertext[i:i+BLOCK_SIZE]
        temp = cipher.decrypt(c_i)
        p_i = strxor(temp, iv)
        dec.append(p_i)

        iv = c_i

    padded = b"".join(dec)

    plaintext = padded[:-padded[-1]]

    with open(pfile, 'wb') as f:
        f.write(plaintext)

def usage():
    print("Usage:")
    print("-encrypt <plaintextfile> <ciphertextfile>")
    print("-decrypt <ciphertextfile> <plaintextfile>")
    sys.exit(1)

if len(sys.argv) != 4:
    usage()
elif sys.argv[1] == '-encrypt':
    encrypt(sys.argv[2], sys.argv[3])
elif sys.argv[1] == '-decrypt':
    decrypt(sys.argv[2], sys.argv[3])
else:
    usage()
