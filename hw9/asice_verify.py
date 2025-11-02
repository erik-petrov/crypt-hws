#!/usr/bin/env python3

# do not use any other imports/libraries
import codecs
import datetime
import hashlib
import io
import sys
import zipfile

# apt-get install python3-bs4 python3-pyasn1-modules python3-m2crypto python3-lxml
from M2Crypto import X509, EC
import lxml.etree
from bs4 import BeautifulSoup
from pyasn1.codec.der import decoder, encoder
from pyasn1_modules import rfc2560

# took x.y hours (please specify here how much time your solution required)

def verify_ecdsa(cert, signature_value, signed_hash):
    # verifies ECDSA signature given the hash value
    x509 = X509.load_cert_der_string(cert)
    EC_pubkey = EC.pub_key_from_der(x509.get_pubkey().as_der())

    # constructing r and s to satisfy M2Crypto
    l = len(signature_value)//2
    r = signature_value[:l]
    s = signature_value[l:]
    if r[0]>>7:
        r = b'\x00' + r
    if s[0]>>7:
        s = b'\x00' + s
    r = b'\x00\x00\x00' + bytes([len(r)]) + r
    s = b'\x00\x00\x00' + bytes([len(s)]) + s
    return EC_pubkey.verify_dsa(signed_hash, r, s)

def parse_tsa_response(timestamp_resp):
    # extracts from a TSA response the timestamp and timestamped DigestInfo
    timestamp = decoder.decode(timestamp_resp)
    tsinfo = decoder.decode(timestamp[0][1][2][1])[0]
    ts_digestinfo = encoder.encode(tsinfo[2])
    ts = datetime.datetime.strptime(str(tsinfo[4]), '%Y%m%d%H%M%SZ')
    # let's assume that the timestamp has been issued by a trusted TSA
    return ts, ts_digestinfo

def parse_ocsp_response(ocsp_resp):
    # extracts from an OCSP response certID_serial, certStatus and thisUpdate
    ocspResponse, _ = decoder.decode(ocsp_resp, asn1Spec=rfc2560.OCSPResponse())
    responseStatus = ocspResponse.getComponentByName('responseStatus')
    assert responseStatus == rfc2560.OCSPResponseStatus('successful'), responseStatus.prettyPrint()
    responseBytes = ocspResponse.getComponentByName('responseBytes')
    responseType = responseBytes.getComponentByName('responseType')
    assert responseType == rfc2560.id_pkix_ocsp_basic, responseType.prettyPrint()
    response = responseBytes.getComponentByName('response')
    basicOCSPResponse, _ = decoder.decode(response, asn1Spec=rfc2560.BasicOCSPResponse())
    tbsResponseData = basicOCSPResponse.getComponentByName('tbsResponseData')
    response0 = tbsResponseData.getComponentByName('responses').getComponentByPosition(0)
    # let's assume that the OCSP response has been signed by a trusted OCSP responder
    certID = response0.getComponentByName('certID')
    # let's assume that the issuer name and key hashes in certID are correct
    certID_serial = certID[3]
    certStatus = response0.getComponentByName('certStatus').getName()
    thisUpdate = datetime.datetime.strptime(str(response0.getComponentByName('thisUpdate')), '%Y%m%d%H%M%SZ')

    return certID_serial, certStatus, thisUpdate

def canonicalize(full_xml, tagname):
    # returns XML canonicalization of an element with the specified tagname
    if type(full_xml)!=bytes:
        print("[-] canonicalize(): input is not a bytes object containing XML:", type(full_xml))
        exit(1)
    input = io.BytesIO(full_xml)
    et = lxml.etree.parse(input)
    output = io.BytesIO()
    lxml.etree.ElementTree(et.find('.//{*}'+tagname)).write_c14n(output)
    return output.getvalue()

def canonicalize_by_id(full_xml_bytes, element_id):
    # returns XML canonicalization of an element with the specified Id
    parser = lxml.etree.XMLParser(dtd_validation=False)
    et = lxml.etree.XML(full_xml_bytes, parser)
    element_to_c14n = et.xpath(f"//*[@Id='{element_id[1:]}']")

    output = io.BytesIO()
    lxml.etree.ElementTree(element_to_c14n[0]).write_c14n(output)
    return output.getvalue()

def get_subject_cn(cert_der):
    # returns CommonName value from the certificate's Subject Distinguished Name field
    # looping over Distinguished Name entries until CN found
    for rdn in decoder.decode(cert_der)[0][0][5]:
        if str(rdn[0][0]) == '2.5.4.3': # CommonName
            return str(rdn[0][1])
    return ''

filename = sys.argv[1]

# get and decode XML
zip = zipfile.ZipFile(filename, 'r')
xmldoc_bytes = zip.read('META-INF/signatures0.xml')
xmldoc = BeautifulSoup(xmldoc_bytes, 'xml')

# let's trust this certificate
signers_cert_der = codecs.decode(xmldoc.XAdESSignatures.KeyInfo.X509Data.X509Certificate.encode_contents(), 'base64')
print("[+] Signatory:", get_subject_cn(signers_cert_der))

signed_info = xmldoc.find('SignedInfo')
references = signed_info.find_all('Reference')

for ref in references:
    uri = ref['URI']
    ref_digest_expected = codecs.decode(ref.find('DigestValue').string.encode('utf-8'), 'base64')
    
    if uri.startswith('#'):
        c14n_signed_props = canonicalize_by_id(xmldoc_bytes, uri)
        ref_digest_calculated = hashlib.sha256(c14n_signed_props).digest()
        
        if ref_digest_calculated != ref_digest_expected:
            print(f"[-] SignedProperties digest mismatch")
            sys.exit(1)
    else:
        file_bytes = zip.read(uri)
        
        ref_digest_calculated = hashlib.sha256(file_bytes).digest()
        
        if ref_digest_calculated != ref_digest_expected:
            print(f"[-] Signed file '{uri}' has been modified")
            sys.exit(1)
        
        print(f"[+] Signed file: {uri}")

# perform all kinds of checks
tsa_b64 = xmldoc.find('EncapsulatedTimeStamp').string
tsa_resp = codecs.decode(tsa_b64.encode('utf-8'), 'base64')
ts, ts_digestinfo = parse_tsa_response(tsa_resp)
print("[+] Timestamped: %s +00:00" % (ts))

ocsp_b64 = xmldoc.find('EncapsulatedOCSPValue').string
ocsp_resp = codecs.decode(ocsp_b64.encode('utf-8'), 'base64')
certID_serial, certStatus, thisUpdate = parse_ocsp_response(ocsp_resp)

if ts > thisUpdate:
    print("[-] timestamp is bigger than thisUpdate in OCSP response")
    sys.exit(1)

if certStatus != 'good':
    print(f"[-] certificate status is '{certStatus}', not 'good'")
    sys.exit(1)

sig_val_b64 = xmldoc.find('SignatureValue').string
signature_value = codecs.decode("".join(sig_val_b64.split()).encode('utf-8'), 'base64')

signed_info_str = canonicalize(xmldoc_bytes, 'SignedInfo')

# finally verify signatory's signature
if verify_ecdsa(signers_cert_der, signature_value, hashlib.sha384(signed_info_str).digest()):
    print("[+] Signature verification successful!")
else:
    print("[-] Signature verification failure!")
