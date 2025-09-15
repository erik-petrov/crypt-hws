#!/usr/bin/env python3
import sys   # do not use any other imports/libraries

# took x.y hours (please specify here how much time your solution required)

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

def asn1_boolean(boolean):
    # BOOLEAN encoder has been implemented for you
    if boolean:
        boolean = b'\xff'
    else:
        boolean = b'\x00'

    return bytes([0x01]) + asn1_len(boolean) + boolean

def asn1_null():
    # returns DER encoding of NULL
    return bytes([0x05])+bytes([0x00])

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

def getBitstrToInt(bitstr):
    i = 0
    for bit in bitstr:
        i<<=1
        if bit=='1':
            i|= 1
    return i

#i really dont know any other way
def getEmptyBytes(bitstr):
    emptyBytes = 0
    temp = 0
    for i in bitstr:
        if i == '0':
            temp += 1
        else:
            break
        if temp == 8:
            emptyBytes+=1
            temp = 0
        
    return emptyBytes
        

def asn1_bitstring(bitstr):
    # bitstr - string containing bitstring (e.g., "10101")
    # returns DER encoding of BITSTRING
    leadingBytes = getEmptyBytes(bitstr)
    tag = bytes([0x03])
    padding = 0 if (len(bitstr) % 8 == 0) else abs((len(bitstr) % 8)-8)
    num = getBitstrToInt(bitstr) if leadingBytes != len(bitstr) else 0

    actualInt = ib(num << padding)

    #account for the fact that we get no actual int, only leading bytes
    if num == 0 and padding == 0:
        leadingBytes -= 1

    length = asn1_len(actualInt, True, leadingBytes+1)
    if len(bitstr) == 0:
        return tag+bytes([0x01])+bytes([0x00])

    return tag+length+bytes([padding])+bytes([0x00]*leadingBytes)+actualInt

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

def asn1_set(der):
    # der - DER bytes to encapsulate into set
    # returns DER encoding of SET
    tag = bytes([0x31])
    ln = asn1_len(der)
    return tag+ln+der

def asn1_utf8string(utf8bytes):
    # utf8bytes - bytes containing UTF-8 encoded unicode characters (e.g., b"F\xc5\x8d\xc5\x8d")
    # returns DER encoding of UTF8String
    tag = bytes([0x0c])
    ln = asn1_len(utf8bytes)
    return tag+ln+utf8bytes

def asn1_utctime(time):
    # time - bytes containing timestamp in UTCTime format (e.g., b"121229010100Z")
    # returns DER encoding of UTCTime
    tag = bytes([0x17])
    ln = asn1_len(time)
    return tag+ln+time

def asn1_tag_explicit(der, tag):
    # der - DER encoded bytestring
    # tag - tag value to specify in the type octet
    # returns DER encoding of original DER that is encapsulated in tag type
    tag |= 160
    ln = asn1_len(der)
    return bytes([tag])+ln+der

# figure out what to put in '...' by looking on ASN.1 structure required (see slides)
asn1 = asn1_tag_explicit(
    asn1_sequence(
        asn1_set(
            asn1_integer(5)
            +asn1_tag_explicit(asn1_integer(200), 2)
            +asn1_tag_explicit(asn1_integer(65407), 11)
        )
        +asn1_boolean(True)
        +asn1_bitstring("011")
        +asn1_octetstring(b"\x00\x01"+b"\x02"*49)
        +asn1_null()
        +asn1_objectidentifier([1,2,840,113549,1])
        +asn1_utf8string(b"hello.")
        +asn1_utctime(b"250223010900Z")
    )
, 0)
open(sys.argv[1], 'wb').write(asn1)