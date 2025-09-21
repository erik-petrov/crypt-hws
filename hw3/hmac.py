#!/usr/bin/env python3

import codecs, hashlib, sys
from pyasn1.codec.der import decoder
sys.path = sys.path[1:] # don't remove! otherwise the library import below will try to import your hmac.py
import hmac # do not use any other imports/libraries

# took x.y hours (please specify here how much time your solution required)

#==== ASN1 encoder start ====
def bi(b):
    # b - bytes to encode as an integer
    # your implementation here
    i = 0
    for num in range(len(b)):
        i = i << 8
        i = i | b[num]
    return i

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

def asn1_null():
    # returns DER encoding of NULL
    return bytes([0x05])+bytes([0x00])

def asn1_octetstring(octets):
    # octets - arbitrary byte string (e.g., b"abc\x01")
    # returns DER encoding of OCTETSTRING
    tag = bytes([0x04])
    len = asn1_len(octets)
    return tag+len+octets

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

#==== ASN1 encoder end ====

ASN1_OID_SHA256 = [2,16,840,1,101,3,4,2,1]
ASN1_OID_SHA1 = [1,3,14,3,2,26]
ASN1_OID_MD5 = [1,2,840,113549,2,5]

oids = [ASN1_OID_SHA1, ASN1_OID_MD5, ASN1_OID_SHA256]

def mac(filename):
    key = input("[?] Enter key: ").encode()

    h = hmac.new(key, None, hashlib.sha256)

    with open(filename, 'rb') as file:
        for chunk in iter(lambda: file.read(512), b''):
            h.update(chunk)

    digest = h.digest()

    print("[+] Calculated HMAC-SHA256:", digest.hex())

    seq = asn1_sequence(
        asn1_sequence(
            asn1_objectidentifier(ASN1_OID_SHA256)+
            asn1_null()
        )+
        asn1_octetstring(digest)
    )

    print("[+] Writing HMAC DigestInfo to", filename+".hmac")

    with open(filename+".hmac", 'wb') as f:
        f.write(seq)

def verify(filename):
    print("[+] Reading HMAC DigestInfo from", filename+".hmac")

    der = open(filename+".hmac", 'rb').read()

    alg = list(decoder.decode(der)[0][0][0])
    digest = decoder.decode(der)[0][1]

    if alg not in oids:
        print("[-] Invalid OID, exiting")
        exit(0)

    if alg == ASN1_OID_MD5:
        lib = hashlib.md5
    elif alg == ASN1_OID_SHA1:
        lib = hashlib.sha1
    else:
        lib = hashlib.sha256

    libName = lib.__name__.split('_')[1].upper()
    print(f"[+] HMAC-{libName} digest: {bytes(digest).hex()}")

    key = input("[?] Enter key: ").encode()

    h = hmac.new(key, None, lib)

    with open(filename, 'rb') as file:
        for chunk in iter(lambda: file.read(512), b''):
            h.update(chunk)

    digest_calculated = h.digest()

    print("[+] Calculated HMAC-SHA256:", digest_calculated.hex())

    if digest_calculated != digest:
        print("[-] Wrong key or message has been manipulated!")
    else:
        print("[+] HMAC verification successful!")



def usage():
    print("Usage:")
    print("-mac <filename>")
    print("-verify <filename>")
    sys.exit(1)

if len(sys.argv) != 3:
    usage()
elif sys.argv[1] == '-mac':
    mac(sys.argv[2])
elif sys.argv[1] == '-verify':
    verify(sys.argv[2])
else:
    usage()
