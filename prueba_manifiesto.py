from suds.client import Client
import logging
import base64
from pdb import set_trace
import hashlib
from datetime import datetime
from M2Crypto.RSA import *

SNName = "Samael"
RFC = "MOLJ961222TF5"
SNAdress = "Morelia #1"
username = "jesuslive1970@gmail.com"
password = "Molj_7248"
contracts_path = ["/home/jmora/Documentos/privacy.txt", 
        "/home/jmora/Documentos/contract.txt",
        "/home/jmora/Descargas/fiel_demo/FIEL_DEMO/FIEL_Pruebas_{}".format(RFC),
        "/home/jmora/Descargas/fiel_demo/FIEL_DEMO/FIEL_Pruebas_{}".format(RFC)
        ]

class Manifiesto():

    def __init__(self):
        self.SNName = SNName
        self.RFC = RFC
        self.SNAdress = SNAdress
        self.username = username
        self.password = password
        self.contracts_path = contracts_path

    def get_contracts(self):
        url = "https://manifiesto.cfdiquadrum.com.mx:8008/servicios/soap/firmar.wsdl"
        client = Client(url, cache=None)
        request = client.service.get_contracts(self.SNName, self.RFC, self.SNAdress, self.username)
        try:
            with open(contracts_path[0],'w') as contract:
                contract.write(base64.decodestring(request.contract))

            with open(contracts_path[1], 'w') as privacy:
                privacy.write(base64.decodestring(request.privacy))
        except Exception as ex:
            print "Get contracts Exception =>" + str(ex)
        finally:
            contract.close()
            privacy.close()

        
    
    def sign_contract(self):
        self.get_contracts()
        fiel_pass = "12345678a"
        privacy = open(self.contracts_path[0])
        contract = open(self.contracts_path[1])
        aviso = '''<?xml version="1.0" encoding="UTF-8"?>
        <documento><contrato rfc="{}" fecha="{}">{}</contrato><ds:Signature 
        xmlns:ds="http://www.w3.org/2000/09/xmldsig#">'''.format(self.RFC, datetime.now().replace(microsecond=0).isoformat('T'),contract.read())
        #Es mejor utilizar el metodo read() para leer texto codificado a utf-8
        #PASOS PARA OBTENER EL DIGEST VALUE
        # Digest Value
        digest_value = base64.encodestring(hashlib.sha1(aviso).digest())
        signed_info = '''<ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
        <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
        <ds:Reference URI=""><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
        </ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>{}</ds:DigestValue></ds:Reference></ds:SignedInfo>'''.format(digest_value)
        try:
            print signed_info
        except Exception as e:
            print ""

        


manif = Manifiesto()
manif.sign_contract()