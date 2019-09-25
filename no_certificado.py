# -*- coding: utf-8 -*-

import os
from pdb import set_trace

def get_no_cer(cer_path):
    openssl = os.system('openssl x509 -inform DER -in {} -noout -serial > "numero.txt"'.format(cer_path))
    try:
        with open('numero.txt', 'r') as numero:
            no_cer = str(numero.read()).strip()[8::2]
            numero.close()
    except Exception as ex:
        print "Exception => " + str(ex)
        
    return no_cer
no_cer = get_no_cer('/home/jmora/Documentos/php_ws/EKU9003173C9.cer')
print no_cer