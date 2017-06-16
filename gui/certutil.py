from OpenSSL import crypto
import os
import random

class CertGen:
  def __init__(self):
    self.cakey = crypto.load_privatekey(crypto.FILETYPE_PEM,open("keys/cacert.key").read(),"cert")
    self.cacert = crypto.load_certificate(crypto.FILETYPE_PEM,open("keys/cacert.crt").read())

  def get_key(self, certhost):
    pemfile="keys/%s.pem" % certhost

    if os.path.isfile(pemfile) and os.path.isfile(pemfile):
      print "Key exists!"
    else:
      print "No key for %s - creating new one"%certhost
      k = crypto.PKey()
      k.generate_key(crypto.TYPE_RSA, 1024)
      fd = open(pemfile, "wt")
      fd.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k))

      newcert = crypto.X509()
      newcert.set_version(3)
      newcert.get_subject().C = "FI"
      newcert.get_subject().CN = certhost
      newcert.set_serial_number(random.randint(0,10000000))
      newcert.gmtime_adj_notBefore(-10000)
      newcert.gmtime_adj_notAfter(10*365*24*60*60)
      newcert.set_issuer(self.cacert.get_subject())
      newcert.set_pubkey(k)
      newcert.sign(self.cakey, 'sha1')

      fd.write(crypto.dump_certificate(crypto.FILETYPE_PEM, newcert))
      fd.close()
    return pemfile

