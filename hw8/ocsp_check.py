#!/usr/bin/env python3

import codecs, datetime, hashlib, re, sys, socket # do not use any other imports/libraries
from urllib.parse import urlparse
from pyasn1.codec.der import decoder, encoder
from pyasn1.type import namedtype, univ

# sudo apt install python3-pyasn1-modules
from pyasn1_modules import rfc2560, rfc5280

# took x.y hours (please specify here how much time your solution required)

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
# put your DER encoder functions here
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
#==== ASN1 encoder end ====


def pem_to_der(content):
    # converts PEM-encoded X.509 certificate (if it is in PEM) to DER
    if content[:2] == b'--':
        content = content.replace(b"-----BEGIN CERTIFICATE-----", b"")
        content = content.replace(b"-----END CERTIFICATE-----", b"")
        content = codecs.decode(content, 'base64')
    return content

def get_name(cert):
    # gets subject DN from certificate
    return decoder.decode(cert)[0][0][3][-1][0][1]

def get_key(cert):
     # gets subjectPublicKey from certificate
    return decoder.decode(cert)[0][0][6][1]

def get_serial(cert):
    # gets serial from certificate
    return decoder.decode(cert)[0][0][1]

def produce_request(cert, issuer_cert):
    # makes OCSP request in ASN.1 DER form
    # construct CertID (use SHA1)
    issuer_name = str(get_name(issuer_cert))
    name_sha1 = hashlib.sha1(issuer_name.encode()).digest()
    issuer_key = get_key(issuer_cert).asOctets()
    key_sha1 = hashlib.sha1(issuer_key).digest()
    serial = int(get_serial(cert))

    req = asn1_sequence(
        asn1_sequence(
            asn1_sequence(
                asn1_sequence(
                    asn1_sequence(
                        asn1_sequence(asn1_objectidentifier([1,3,14,3,2,26])+asn1_null())+
                        asn1_octetstring(name_sha1)+
                        asn1_octetstring(key_sha1)+
                        asn1_integer(serial)
                    )
                )
            )
        )
    )

    print("[+] OCSP request for serial:", serial)

    # construct entire OCSP request
    url = get_ocsp_url(pem_to_der(cert))
    url = urlparse(url)
    request="POST / HTTP/1.1\r\nHost: "+url.netloc+"\r\nContent-Length: "+str(len(req))+"\r\nConnection: close\r\n\r\n"+str(req)
    return request

def send_req(ocsp_req, ocsp_url):
    # sends OCSP request to OCSP responder

    # parse OCSP responder's url
    url = urlparse(ocsp_url)

    print("[+] Connecting to %s..." % (url.netloc))
    # connect to host
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((url.netloc, 80))
    # send HTTP POST request
    s.send(bytes(ocsp_req, 'utf-8'))
    # read HTTP response header
    # get HTTP response length
    # read HTTP response body
    h=b''
    b=b''
    while True:
        if h[-4:] == b"\r\n\r\n":
            num = re.search('content-length: \s*(\d+)\s', h.decode(), re.S+re.I).group(1)
            b+=s.recv(int(num))
            break
        else:
            d=s.recv(1)
            h+=d
    print(b)
    return b

def get_ocsp_url(cert):
    # gets the OCSP responder's url from the certificate's AIA extension

    # pyasn1 syntax description to decode AIA extension
    class AccessDescription(univ.Sequence):
      componentType = namedtype.NamedTypes(
        namedtype.NamedType('accessMethod', univ.ObjectIdentifier()),
        namedtype.NamedType('accessLocation', rfc5280.GeneralName()))

    class AuthorityInfoAccessSyntax(univ.SequenceOf):
      componentType = AccessDescription()

    # looping over certificate extensions
    for seq in decoder.decode(cert)[0][0][7]:
        if str(seq[0])=='1.3.6.1.5.5.7.1.1': # look for AIA extension
            ext_value = bytes(seq[1])
            for aia in decoder.decode(ext_value, asn1Spec=AuthorityInfoAccessSyntax())[0]:
                if str(aia[0])=='1.3.6.1.5.5.7.48.1': # ocsp url
                    return str(aia[1].getComponentByName('uniformResourceIdentifier'))

    print("[-] OCSP url not found in the certificate!")
    exit(1)

def get_issuer_cert_url(cert):
    class AccessDescription(univ.Sequence):
      componentType = namedtype.NamedTypes(
        namedtype.NamedType('accessMethod', univ.ObjectIdentifier()),
        namedtype.NamedType('accessLocation', rfc5280.GeneralName()))

    class AuthorityInfoAccessSyntax(univ.SequenceOf):
      componentType = AccessDescription()

    # gets the CA's certificate URL from the certificate's AIA extension (hint: see get_ocsp_url())
    for seq in decoder.decode(cert)[0][0][7]:
        if str(seq[0])=='1.3.6.1.5.5.7.1.1': # look for AIA extension
            ext_value = bytes(seq[1])
            for aia in decoder.decode(ext_value, asn1Spec=AuthorityInfoAccessSyntax())[0]:
                if str(aia[0])=='1.3.6.1.5.5.7.48.2':
                    return str(aia[1].getComponentByName('uniformResourceIdentifier'))
    
    print("[-] Issuer url not found in the certificate!")
    exit(1)

def download_issuer_cert(issuer_cert_url):
    # downloads issuer certificate
    print("[+] Downloading issuer certificate from:", issuer_cert_url)

    # parse issuer certificate url
    url = urlparse(issuer_cert_url)

    # connect to host
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((url.netloc, 80))
    # send HTTP GET request
    s.send(b'GET '+bytes(url.path, 'utf-8')+b' HTTP/1.1\r\nHost: '+bytes(url.netloc, 'utf-8')+b"\r\nConnection: close\r\n\r\n")
    # read HTTP response header
    h=b''
    b=b''
    while True:
        if h[-4:] == b"\r\n\r\n":
            num = re.search('content-length: \s*(\d+)\s', h.decode(), re.S+re.I).group(1)
            b+=s.recv(int(num))
            break
        else:
            d=s.recv(1)
            h+=d
    # get HTTP response length

    # read HTTP response body

    return b

def parse_ocsp_resp(ocsp_resp):
    # parses OCSP response
    ocspResponse, _ = decoder.decode(ocsp_resp, asn1Spec=rfc2560.OCSPResponse())
    responseStatus = ocspResponse.getComponentByName('responseStatus')
    assert responseStatus == rfc2560.OCSPResponseStatus('successful'), responseStatus.prettyPrint()
    responseBytes = ocspResponse.getComponentByName('responseBytes')
    responseType = responseBytes.getComponentByName('responseType')
    assert responseType == rfc2560.id_pkix_ocsp_basic, responseType.prettyPrint()

    response = responseBytes.getComponentByName('response')

    basicOCSPResponse, _ = decoder.decode(
        response, asn1Spec=rfc2560.BasicOCSPResponse()
    )

    tbsResponseData = basicOCSPResponse.getComponentByName('tbsResponseData')

    response0 = tbsResponseData.getComponentByName('responses').getComponentByPosition(0)

    producedAt = datetime.datetime.strptime(str(tbsResponseData.getComponentByName('producedAt')), '%Y%m%d%H%M%SZ')
    certID = response0.getComponentByName('certID')
    certStatus = response0.getComponentByName('certStatus').getName()
    thisUpdate = datetime.datetime.strptime(str(response0.getComponentByName('thisUpdate')), '%Y%m%d%H%M%SZ')
    nextUpdate = datetime.datetime.strptime(str(response0.getComponentByName('nextUpdate')), '%Y%m%d%H%M%SZ')

    # let's assume that the certID in the response matches the certID sent in the request

    # let's assume that the response is signed by a trusted responder

    print("[+] OCSP producedAt: %s +00:00" % producedAt)
    print("[+] OCSP thisUpdate: %s +00:00" % thisUpdate)
    print("[+] OCSP nextUpdate: %s +00:00" % nextUpdate)
    print("[+] OCSP status:", certStatus)

cert = pem_to_der(open(sys.argv[1], 'rb').read())

ocsp_url = get_ocsp_url(cert)
print("[+] URL of OCSP responder:", ocsp_url)

issuer_cert_url = get_issuer_cert_url(cert)
issuer_cert = download_issuer_cert(issuer_cert_url)

ocsp_req = produce_request(cert, issuer_cert)
ocsp_resp = send_req(ocsp_req, ocsp_url)
parse_ocsp_resp(ocsp_resp)
