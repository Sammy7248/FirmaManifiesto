from suds.client import Client
import logging
import base64
from pdb import set_trace
import hashlib
from datetime import datetime
from M2Crypto import RSA
from M2Crypto import X509
import Crypto.PublicKey.RSA
import os.path as path

SnName = "Samael"
rfc = "TCM970625MB1"
SnAdress = "Morelia #1"
username = "jesuslive1970@gmail.com"
password = "Molj_7248"
SNID = ""

cer = '''-----BEGIN CERTIFICATE-----
MIIGQTCCBCmgAwIBAgIUMjAwMDEwMDAwMDAzMDAwMjI4NDQwDQYJKoZIhvcNAQEL
BQAwggFmMSAwHgYDVQQDDBdBLkMuIDIgZGUgcHJ1ZWJhcyg0MDk2KTEvMC0GA1UE
CgwmU2VydmljaW8gZGUgQWRtaW5pc3RyYWNpw7NuIFRyaWJ1dGFyaWExODA2BgNV
BAsML0FkbWluaXN0cmFjacOzbiBkZSBTZWd1cmlkYWQgZGUgbGEgSW5mb3JtYWNp
w7NuMSkwJwYJKoZIhvcNAQkBFhphc2lzbmV0QHBydWViYXMuc2F0LmdvYi5teDEm
MCQGA1UECQwdQXYuIEhpZGFsZ28gNzcsIENvbC4gR3VlcnJlcm8xDjAMBgNVBBEM
BTA2MzAwMQswCQYDVQQGEwJNWDEZMBcGA1UECAwQRGlzdHJpdG8gRmVkZXJhbDES
MBAGA1UEBwwJQ295b2Fjw6FuMRUwEwYDVQQtEwxTQVQ5NzA3MDFOTjMxITAfBgkq
hkiG9w0BCQIMElJlc3BvbnNhYmxlOiBBQ0RNQTAeFw0xNjExMTUwMDM3MzZaFw0y
MDExMTQwMDM3MzZaMIH7MSgwJgYDVQQDEx9FSklETyBST0RSSUdVRVogUFVFQkxB
IFNBIERFIENWMSgwJgYDVQQpEx9FSklETyBST0RSSUdVRVogUFVFQkxBIFNBIERF
IENWMSgwJgYDVQQKEx9FSklETyBST0RSSUdVRVogUFVFQkxBIFNBIERFIENWMQsw
CQYDVQQGEwJNWDEnMCUGCSqGSIb3DQEJARYYZXJpa2EubWVuZG96YUBzYXQuZ29i
Lm14MSUwIwYDVQQtExxUQ005NzA2MjVNQjEgLyBGVUFCNzcwMTE3QlhBMR4wHAYD
VQQFExUgLyBGVUFCNzcwMTE3TURGUk5OMDkwggEiMA0GCSqGSIb3DQEBAQUAA4IB
DwAwggEKAoIBAQCkEncMarv1+Ov3+UhQyMcOi6wot1X88hExyL/vGlK95E68HKEJ
AvMpybaaASNzU6Nun5bNH5kafl8z+L7XcA2MKMDRdQRqv5LUVnaTEOj8/zvo5q42
EFa0mzYt/97Faz/bMrw3b7H53a4vS6sYrz2OjvzwacczG71Ku8k3lteYF9Nr5/Ki
hDE7mWe9kHr+xyBSF7G7gvxwszlda7/dywd2zQPSrBJKQ+zZ20hUMuU6f1/R3nvl
frA0Hg8yYnMrUKuQUQqoXIJdswPcsPkPZ2oJbMoOcBSZI+8cqybck0Kz45sfj/Aa
GSEnUKn1AJzBNIVA0YVpPzCvNqKY1g3i/EctAgMBAAGjTzBNMAwGA1UdEwEB/wQC
MAAwCwYDVR0PBAQDAgPYMBEGCWCGSAGG+EIBAQQEAwIFoDAdBgNVHSUEFjAUBggr
BgEFBQcDBAYIKwYBBQUHAwIwDQYJKoZIhvcNAQELBQADggIBAAqlByHUDqgodrXn
GaIgKpv8baDtX2TAM2F10qiMhb4O8b4kSoQOn+ziNSedmnBkFi1TEF4BtKLsBnZU
Sa49jrZ2XUtRd+lxDl0b309IeL/9oPzmOQ8Y7fC2xk7in6AtDaiJCU/NlH7GU/P1
a9nC46jr8SM/8gGX1GSy2/nBjFx+dfQPLv3MGd7tnWa4p9Pa6hipGmA7aXAPlbKc
eY4l1lsTL2XAfB2yjbpWBhJbgHpxbNUSXGAYT9wXe3rS6ckyRJsf0QlqWIsib76h
4FpzYc8Qx6BKAkgqT/E0/TtuHDdyqqemVnpfv/hZYoKUGqoDdV0bX0WYd933O6um
6GQnzdSmf8fTZUIQfNH7ervaTEgJRviJQ/YdKSlLa3PUo/Ca2/kTEcAx8obcHkeV
nIA96B2+aJQx+rAi4uQZFXtD2sq9pJAE4e5PMk+vXLifCdsHaxySs2TCkm+FodSx
e1obb1uBiY9hp3XBWg84m/2w6Eqzik2kGR6bhu4tnsaR9GNyTSIEb9YApkkZR01Z
VLowQKMTUS73rv4962E9pGfwIBLUE2vz2rNMri867VgG7iB5uPShGmEicES25Ik8
WICSxEPYH3TowJ/i0+98d7aGjLuc+yYOCmHzc0eD/0VD38ttU5VtT29zk1vcRRHZ
l5ivHWlWcOGPVKnooa0NA9k1rOoT
-----END CERTIFICATE-----'''

key = '''-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCkEncMarv1+Ov3
+UhQyMcOi6wot1X88hExyL/vGlK95E68HKEJAvMpybaaASNzU6Nun5bNH5kafl8z
+L7XcA2MKMDRdQRqv5LUVnaTEOj8/zvo5q42EFa0mzYt/97Faz/bMrw3b7H53a4v
S6sYrz2OjvzwacczG71Ku8k3lteYF9Nr5/KihDE7mWe9kHr+xyBSF7G7gvxwszld
a7/dywd2zQPSrBJKQ+zZ20hUMuU6f1/R3nvlfrA0Hg8yYnMrUKuQUQqoXIJdswPc
sPkPZ2oJbMoOcBSZI+8cqybck0Kz45sfj/AaGSEnUKn1AJzBNIVA0YVpPzCvNqKY
1g3i/EctAgMBAAECggEAVjxWUjJvZJNXA1kEx2EgLub+r8/c5DwfCXmoV/YP8zri
n0C061WflSEuVreueFlHl0dOLbYj9KbjRx/Avt9oX3i0D+NfVPQoKm7fl+DVdNR6
GqnUexoPWJIT4g2Qe1cpkv6RqtmMQ/ZeLQGqhijlQ96n13zhdF1qGrOkyREBdDCG
mPc1dP0jk6N157ByIcoLYONHMgCOrt7cX89KbKbCM65exn7IZt+dRVCebxejopnG
TQg2ZwRK1Ww/CQyq0Nw/En5ERkgnzHvkRa0+DtbbvHmmCYIvJXkttnEH0qdeBCMu
FUOlW+fYkdVrWk8KWOPESzLpcH9d+/R+nJzI1Z7XSQKBgQD2VQGbJBi+6JvuTS4R
tSqlTHCo2OLS4+wEqYwoGMvqnI+V9v7TkWhzZQRNp6wqZofQQUesHkvKG2uatFZH
BpdPC6I4S8+PM6IUYmU/QEg+ZgShkZ694bbJLODyudZfIb8W8p4IaI/k9WuN+OXj
CFLtUvYwNPbDYHi3uFeE5pb6uwKBgQCqgvYb8qK8Yot8p+nDRYHs0BA9idDlUHL+
MSIuXtQa8lhI4qLkoogd7sxl45TYVLjX8hti75f1jpbODWG+nYO/fbtFnJh/m6hv
3/QH9mo6hZ/RxzWqMcSsLMVL71/Z5e+k25yrz3aAzwzrtYNY4n/H0//kpQyFqNuY
q/Cxi90rNwKBgCUQc1ZpnwOSsmuv1z+417rZfpYZVD/RJaEp9bnOyVf6yKwS5xLk
bSf3yib5FLGojcTrHaKrSFIXwCAeBGFZf4jYQkdgONHePgP9LijPPk+NQCMjaxQ9
EyjABPTgu33C8SK9zMONICGeP9mz2rtHdFrbQcnNHlgVevSB20FXBN6jAoGAQRfr
0nGHdLl+HKGRmS1g00H+4S9KozBaJfYl4WPsPzlDQNfcbcIqiprORxthiFCXnEDd
+aAT9/duVM1BAl7pm+Ho60ND6HtJCySI6b1Fgn/eqlwNfaKwPTZ+P2XrxqiEGwCH
yANUbwocGaPat8UIGQYyy1vC8weqhZcmNPF7BnMCgYBPD2mVfKpYiiEG8XaBydj5
tVPFrKJeEYic3V1Ac4E0YmMr7wMA8H3SEh8V4c/z8rtDxAqqrJHhu7p0w5LuVF+g
2H1EiJpi63yZKl1Gg27W3z/fDctErT+Vc1PUXCCNfIkwjXpduxqaQ2jsA9BuC7X7
MwtsL4G6atSJ956FcwGxeQ==
-----END PRIVATE KEY-----
'''

class Manifiesto():

    def __init__(self):
        self.SnName = SnName
        self.rfc = rfc
        self.SnAdress = SnAdress
        self.username = username
        self.password = password
        self.cer = cer
        self.key = key
        self.url = "https://manifiesto.cfdiquadrum.com.mx:8008/servicios/soap/firmar.wsdl"
        self.SNID = SNID

    def get_contracts(self):
        client = Client(self.url, cache=None)
        request = client.service.get_contracts(self.SnName, self.rfc, self.SnAdress, self.username)
        try:
            with open('Contracts/contract.txt','w') as contract:
                contract.write(base64.decodestring(request.contract))

            with open('Contracts/privacy.txt', 'w') as privacy:
                privacy.write(base64.decodestring(request.privacy))
        except Exception as ex:
            print "Get contracts Exception =>" + str(ex)
        finally:
            contract.close()
            privacy.close()

        
    
    def get_contracts_xml_signature(self, documento):
        self.get_contracts()
        fiel_pass = "12345678a"
        if str(documento).upper() == 'C':
            document = open('Contracts/contract.txt')
        elif documento.upper() == 'P':
            document = open('Contracts/privacy.txt')
        aviso_tmpl = '''<?xml version="1.0" encoding="UTF-8"?>
        <documento><contrato rfc="%s" fecha="%s">%s</contrato><ds:Signature 
        xmlns:ds="http://www.w3.org/2000/09/xmldsig#">''' 
        aviso = aviso_tmpl % (self.rfc, datetime.now().replace(microsecond=0).isoformat('T'),document.read())

        digest_value = base64.encodestring(hashlib.sha1(aviso).digest())
        
        signed_info_digest_tmpl = '''<ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/><ds:Reference URI=""><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>%s</ds:DigestValue></ds:Reference></ds:SignedInfo>'''
        signed_info_digest = signed_info_digest_tmpl % (digest_value)

        signed_info_digest_value = hashlib.sha1(signed_info_digest).digest().strip()
        
        try:
            pri_key = RSA.load_key_string(self.key)
        except Exception as e:
            print "Error en key =>" + str(e)
        
        try:
            pri_cer = X509.load_cert_string(self.cer, X509.FORMAT_PEM)
        except Exception as e:
            print "Error en cer =>" + str(e)

        signature_value = pri_key.sign(signed_info_digest_value)
       
        cert = self.cer.replace('-----BEGIN CERTIFICATE-----', '')
        cert = cert.replace('-----END CERTIFICATE-----', '').strip()

        signature_template_tmpl = '''%s<ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/><ds:Reference URI=""><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>+%s</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>%s</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>%s</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature></documento>'''
        signature_template = signature_template_tmpl % (aviso, digest_value, base64.encodestring(signature_value).strip(), cert)

        with open('Contracts/sign_template_{}.xml'.format(documento.upper()), 'w') as sign_template:
            sign_template.write(signature_template)
            sign_template.close()
        print signature_template
    
    def sign_contract(self):
        client = Client(self.url ,cache=None)
        
        contract_xml = open('Contracts/sign_template_C.xml', 'r')
        privacy_xml = open('Contracts/sign_template_P.xml', 'r')

        if not path.exists('Contracts/sign_template_C.xml'):
            self.get_contracts_xml_signature('c')
        elif not path.exists('Contracts/sign_template_P.xml'):
            self.get_contracts_xml_signature('p')

        request = client.service.sign_contract(self.SNID, base64.encodestring(contract_xml.read()), base64.encodestring(contract_xml.read()))

        if request.success:
            print request.message
        else:
            print "Error in response => " + request.message
manif = Manifiesto()
# manif.get_contracts_xml_signature("c")
manif.sign_contract()