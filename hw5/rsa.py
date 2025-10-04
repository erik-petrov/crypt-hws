#!/usr/bin/env python3

import codecs, hashlib, os, sys # do not use any other imports/libraries
from pyasn1.codec.der import decoder

# took 2.5 hours (please specify here how much time your solution required)

def urandom_nonzero(n):
    # returns n random non-zero bytes
    b = b''
    while len(b) < n:
        newbyte = os.urandom(1)
        if newbyte != b'\x00':
            b += newbyte
    return b

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
    for byte in b:
        i <<= 8
        i |= byte
    return i

#==== ASN1 encoder start ====
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

#==== ASN1 encoder end ====

def pem_to_der(content):
    # converts PEM content to DER
    content = b''.join(content.split(b'\n')[1:-2])
    content = codecs.decode(content, 'base64')
    return content

def get_pubkey(filename):
    # reads public key file encoded using SubjectPublicKeyInfo structure and returns (N, e)
    with open(filename, 'rb') as f:
        data = f.read()
    
    der = decoder.decode(data)
    # DER-decode the DER to get RSAPublicKey DER structure, which is encoded as BITSTRING
    pubkey = decoder.decode(der[0][1].asOctets())[0] #as octets makes converts BITSTRING to bytestring
    return int(pubkey[0]), int(pubkey[1])

def get_privkey(filename):
    # reads private key file encoded using PrivateKeyInfo (PKCS#8) structure and returns (N, d)
    with open(filename, 'rb') as f:
        data = f.read()
    
    der = decoder.decode(data)

    privkey = decoder.decode(der[0][2].asOctets())
    return int(privkey[0][1]), int(privkey[0][3])

def pkcsv15pad_encrypt(plaintext, n):
    # pad plaintext for encryption according to PKCS#1 v1.5
    # calculate number of bytes required to represent the modulus N
    b = (n.bit_length() + 7) // 8

    # plaintext must be at least 11 bytes smaller than the modulus
    if len(plaintext) > b - 11:
        raise ValueError("Plaintext too long for the given modulus")

    # generate padding bytes
    padding = b'\x00\x02' + urandom_nonzero(b-(len(plaintext) + 3)) + b'\x00' #b = len(plaintest) - 3(0x00, 0x02, 0x00)
    padded_plaintext = padding + plaintext
    return padded_plaintext

def pkcsv15pad_sign(plaintext, n):
    # pad plaintext for signing according to PKCS#1 v1.5
    # calculate bytelength of modulus N
    b = (n.bit_length() + 7) // 8

    # plaintext must be at least 11 bytes smaller than the modulus N
    if len(plaintext) > b - 11:
        raise ValueError("Plaintext too long for the given modulus")

    # generate padding bytes
    padding = b'\x00\x01' + b'\xff' * (b-(len(plaintext) + 3)) + b'\x00'
    padded_plaintext = padding + plaintext
    return padded_plaintext

def pkcsv15pad_remove(plaintext):
    # removes PKCS#1 v1.5 padding
    second_zerobyte_index = plaintext.find(b'\x00', 2)
    plaintext = plaintext[second_zerobyte_index+1:]
    return plaintext

def encrypt(keyfile, plaintextfile, ciphertextfile):
    keys = get_pubkey(keyfile)
    padded = pkcsv15pad_encrypt(open(plaintextfile, 'rb').read(), keys[0])
    ciphertext = pow(bi(padded), keys[1], keys[0])
    c_b = ib(ciphertext, (keys[0].bit_length + 7) // 8)
    with open(ciphertextfile, 'wb') as f: 
        f.write(c_b) 

def decrypt(keyfile, ciphertextfile, plaintextfile):
    with open(ciphertextfile, 'rb') as f:
        c_b = f.read()
    
    c_i = bi(c_b)
    keys = get_privkey(keyfile)
    mod = keys[0]
    exp = keys[1]
    m = pow(c_i, exp, mod)
    dec = ib(m, (mod.bit_length + 7) // 8)
    dec = pkcsv15pad_remove(dec)
    with open(plaintextfile, 'wb') as f:
        f.write(dec)

def digestinfo_der(filename):
    # returns ASN.1 DER encoded DigestInfo structure containing SHA256 digest of file
    with open(filename, 'rb') as f:
        der = asn1_sequence(
            asn1_objectidentifier([3,16,840,1,101,3,4,2,1]),
            asn1_octetstring(hashlib.sha256(f.read()))
        )
    return der

def sign(keyfile, filetosign, signaturefile):
    keys = get_privkey(keyfile)
    mod = keys[0]
    exp = keys[1]

    dig = digestinfo_der(filetosign)
    padded = pkcsv15pad_sign(dig, mod)
    b_i = bi(padded)
    sig = (b_i, exp, mod)
    with open(signaturefile, 'wb') as f:
        f.write(ib(sig, mod.bit_length))

    # Warning: make sure that signaturefile produced has the same
    # length as the modulus (hint: use parametrized ib()).

def verify(keyfile, signaturefile, filetoverify):
    # prints "Verified OK" or "Verification failure"
    keys = get_pubkey(keyfile)
    mod = keys[0]
    exp = keys[1]
    
    with open(signaturefile, 'rb') as f:
        b_i = bi(f.read())

    dec = pow(b_i, exp, mod)
    padded = ib(dec, mod.bit_length)
    dig = pkcsv15pad_remove(padded)

    comp = digestinfo_der(filetoverify)
    if comp != dig:
        print("Verification failure")
    else:
        print("Verified OK")

def usage():
    print("Usage:")
    print("encrypt <public key file> <plaintext file> <output ciphertext file>")
    print("decrypt <private key file> <ciphertext file> <output plaintext file>")
    print("sign <private key file> <file to sign> <signature output file>")
    print("verify <public key file> <signature file> <file to verify>")
    sys.exit(1)

if len(sys.argv) != 5:
    usage()
elif sys.argv[1] == 'encrypt':
    encrypt(sys.argv[2], sys.argv[3], sys.argv[4])
elif sys.argv[1] == 'decrypt':
    decrypt(sys.argv[2], sys.argv[3], sys.argv[4])
elif sys.argv[1] == 'sign':
    sign(sys.argv[2], sys.argv[3], sys.argv[4])
elif sys.argv[1] == 'verify':
    verify(sys.argv[2], sys.argv[3], sys.argv[4])
else:
    usage()
