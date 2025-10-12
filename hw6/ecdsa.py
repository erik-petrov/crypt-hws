#!/usr/bin/env python3
#took 5 hrs
import codecs, hashlib, os, sys # do not use any other imports/libraries
from secp256r1 import curve
from pyasn1.codec.der import decoder

n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551 #order of the curve

def ib(i, length=False):
    # converts integer to bytes
    b = b''
    if length==False:
        length = (i.bit_length()+7)//8
    for _ in range(length):
        b = bytes([i & 0xff]) + b
        i >>= 8
    return b

def bi(b):
    # converts bytes to integer
    i = 0
    for char in b:
        i <<= 8
        i |= char
    return i

# --------------- asn1 DER encoder
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

def numOfBytesNeeded(num, bits=8):
    if num == 0:
        return 1

    bytes = 0
    while num > 0:
        num >>= bits
        bytes += 1
        
    return bytes

def asn1_sequence(der):
    # der - DER bytes to encapsulate into sequence
    # returns DER encoding of SEQUENCE
    tag = bytes([0x30])
    ln = asn1_len(der)
    return tag+ln+der
# --------------- asn1 DER encoder end

#code from https://github.com/starkbank/ecdsa-python/blob/master/ellipticcurve/math.py
def inv(x, n):
        if x == 0:
            return 0

        lm = 1
        hm = 0
        low = x % n
        high = n

        while low > 1:
            r = high // low
            nm = hm - lm * r
            nw = high - low * r
            high = low
            hm = lm
            low = nw
            lm = nm

        return lm % n

def pem_to_der(content):
    # converts PEM content (if it is PEM) to DER
    if content[:2] == b'--':
        content = content.replace(b"-----BEGIN PUBLIC KEY-----", b"")
        content = content.replace(b"-----END PUBLIC KEY-----", b"")
        content = content.replace(b"-----BEGIN PRIVATE KEY-----", b"")
        content = content.replace(b"-----END PRIVATE KEY-----", b"")
        content = codecs.decode(content, 'base64')
    return content

def get_privkey(filename):
    # reads EC private key file and returns the private key integer (d)
    with open(filename, 'rb') as f:
            data = f.read()
    data = pem_to_der(data)

    der = decoder.decode(data)
    der2 = der[0][2].asOctets()
    der = decoder.decode(der2)
    d = der[0][1].asOctets()

    return bi(d)

def get_pubkey(filename):
    # reads EC public key file and returns coordinates (x, y) of the public key point
    with open(filename, 'rb') as f:
        data = f.read()
    data = pem_to_der(data)

    der = decoder.decode(data)

    cri = der[0][1].asOctets()[1:]
    x = cri[:32]
    y = cri[32:]
    return (x,y)

def ecdsa_sign(keyfile, filetosign, signaturefile):
    # get the private key
    d = get_privkey(keyfile)

    # calculate SHA-384 hash of the file to be signed
    with open(filetosign, 'rb') as f:
        hash = hashlib.sha384(f.read()).digest()
    
    # truncate the hash value to the curve size
    hash = hash[:32]
    # convert hash to integer
    h_i = bi(hash)
    # generate a random nonce k in the range [1, n-1]
    while True:
        k = bi(os.urandom(64)) % 201
        if k > 200:
            continue
        else:
            break
    
    # calculate ECDSA signature components r and s
    while True:
        points = curve.g
        R = curve.mul(points, k)
        r = R[0]
        k_m = pow(k, -1, n)
        s = k_m * (h_i + r * d)

        if s != 0:
            break

    # DER-encode r and s
    der = asn1_sequence(
        asn1_integer(r) + 
        asn1_integer(s)
    )
    # write DER structure to file
    with open(signaturefile, 'wb') as f:
        f.write(der)

def ecdsa_verify(keyfile, signaturefile, filetoverify):
    # prints "Verified OK" or "Verification failure"
    (x,y) = get_pubkey(keyfile)
    x = bi(x)
    y = bi(y)
    with open(filetoverify, 'rb') as f:
        h = bi(hashlib.sha384(f.read()).digest()[:32])

    with open(signaturefile, 'rb') as f:
        der = decoder.decode(f.read())
        r = int(der[0][0])%n
        s = int(der[0][1])%n

    if r not in range(1, n-1) or s not in range(1, n-1):
        print("Verification failure")
        return 
    
    s_m = pow(s, -1, n)

    R = curve.add(
        curve.mul(curve.g,  h*s_m),
        curve.mul((x,y),    r*s_m)
    )

    if R[0] == r:
        print("Verified OK")
    else:
        print("Verification failure")

def usage():
    print("Usage:")
    print("sign <private key file> <file to sign> <signature output file>")
    print("verify <public key file> <signature file> <file to verify>")
    sys.exit(1)

if len(sys.argv) != 5:
    usage()
elif sys.argv[1] == 'sign':
    ecdsa_sign(sys.argv[2], sys.argv[3], sys.argv[4])
elif sys.argv[1] == 'verify':
    ecdsa_verify(sys.argv[2], sys.argv[3], sys.argv[4])
else:
    usage()
