# Copyright (c) 2017 Yubico AB

import unittest
import os
import struct
import datetime
import uuid

import PyKCS11
from PyKCS11 import PyKCS11Error

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding, utils
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography import x509
from cryptography.x509.oid import NameOID

SHA1_DI = "\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14"
SHA256_DI = "\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20"
SHA384_DI = "\x30\x41\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02\x05\x00\x04\x30"
SHA512_DI = "\x30\x51\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03\x05\x00\x04\x40"

P256_PARAMS = "\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07"
P384_PARAMS = "\x06\x05\x2b\x81\x04\x00\x22"
P521_PARAMS = "\x06\x05\x2b\x81\x04\x00\x23"

YUBICO_BASE_VENDOR = 0x59554200

CKK_YUBICO_AES128_CCM_WRAP = PyKCS11.CKK_VENDOR_DEFINED | YUBICO_BASE_VENDOR | 29
CKK_YUBICO_AES192_CCM_WRAP = PyKCS11.CKK_VENDOR_DEFINED | YUBICO_BASE_VENDOR | 41
CKK_YUBICO_AES256_CCM_WRAP = PyKCS11.CKK_VENDOR_DEFINED | YUBICO_BASE_VENDOR | 42
CKM_YUBICO_AES_CCM_WRAP = PyKCS11.CKM_VENDOR_DEFINED | YUBICO_BASE_VENDOR | 0x04

class RSAPssMech(object):
  def __init__(self, hash, mgf, saltlen, m = None):
    # zeroes here for struct padding
    pssparam = struct.pack("LLLLLL", hash, mgf, saltlen, 0, 0, 0)

    self._pssmech = PyKCS11.LowLevel.CK_MECHANISM()
    if(m != None):
      self._pssmech.mechanism = m
    elif(hash == PyKCS11.CKM_SHA_1):
      self._pssmech.mechanism = PyKCS11.CKM_SHA1_RSA_PKCS_PSS
    elif(hash == PyKCS11.CKM_SHA256):
      self._pssmech.mechanism = PyKCS11.CKM_SHA256_RSA_PKCS_PSS
    elif(hash == PyKCS11.CKM_SHA384):
      self._pssmech.mechanism = PyKCS11.CKM_SHA384_RSA_PKCS_PSS
    elif(hash == PyKCS11.CKM_SHA512):
      self._pssmech.mechanism = PyKCS11.CKM_SHA512_RSA_PKCS_PSS
    self._pssmech.pParameter = pssparam
    self._pssmech.ulParameterLen = 24

  def to_native(self):
    return self._pssmech

def decode_int(num):
  # remove 0x at the start
  dec = hex(num)[2:]
  # if num is long hex() will add L at the end
  dec = dec.replace("L", "", 1)
  if len(dec) % 2 == 1:
    dec = '0' + dec
  return dec.decode('hex')

def decode_ec_sig(signature):
  signature = ''.join(map(chr, signature))
  r = int(signature[:len(signature) / 2].encode('hex'), 16)
  s = int(signature[len(signature) / 2:].encode('hex'), 16)
  return utils.encode_dss_signature(r = r, s = s)


class Pkcs11Tester(unittest.TestCase):

  def setUp(self):
    self.pkcs11 = PyKCS11.PyKCS11Lib()
    if os.environ.has_key("YUBIHSM_PKCS11_MODULE"):
      self.pkcs11.load(os.environ.get("YUBIHSM_PKCS11_MODULE"))
    else:
      raise Exception("YUBIHSM_PKCS11_MODULE must be set to the location of the pkcs11 module")
    slots = self.pkcs11.getSlotList()
    for slot in slots:
      info = self.pkcs11.getSlotInfo(slot)
      if(info.flags & PyKCS11.CKF_TOKEN_PRESENT):
        self.slot = slot
    self.mechs = self.pkcs11.getMechanismList(self.slot)
    self.pkcs11.getTokenInfo(self.slot)

  def tearDown(self):
    self.pkcs11.closeAllSessions(self.slot)

  def login(self, password):
    session = self.pkcs11.openSession(self.slot, PyKCS11.CKF_RW_SESSION)
    session.login(password)
    return session

  def pubobjToKey(self, pubkey, session):
    t = session.getAttributeValue(pubkey, [PyKCS11.CKA_KEY_TYPE])[0]
    if(t == PyKCS11.CKK_RSA):
      (modulus,pubexp) = session.getAttributeValue(pubkey, [PyKCS11.CKA_MODULUS, PyKCS11.CKA_PUBLIC_EXPONENT])
      n = ''.join(map(chr, modulus))
      e = ''.join(map(chr, pubexp))
      key = rsa.RSAPublicNumbers(e=int(e.encode('hex'), 16), n=int(n.encode('hex'), 16))
    elif(t == PyKCS11.CKK_EC):
      (param,point) = session.getAttributeValue(pubkey, [PyKCS11.CKA_EC_PARAMS, PyKCS11.CKA_EC_POINT])
      param = ''.join(map(chr, param))
      point = point[1:]
      if(point[0] == 0x81):
        point = point[1:]
      self.assertEqual(point[0] + 1, len(point))
      point = point[1:] # length byte
      point = ''.join(map(chr, point))
      if(param == P256_PARAMS):
        curve = ec.SECP256R1()
        clen = 32
      elif(param == P384_PARAMS):
        curve = ec.SECP384R1()
        clen = 48
      elif(param == P521_PARAMS):
        curve = ec.SECP521R1()
        clen = 66
      else:
        print "no curve.. %d - %d" % (len(param), len(P256_PARAMS))
        return
      x = point[1: 1 + len(point)/2]
      y = point[1 + len(point) / 2:]
      key = ec.EllipticCurvePublicNumbers(curve = curve, x = int(x.encode('hex'), 16), y = int(y.encode('hex'), 16))

    return key.public_key(backend=default_backend())

  def testLogin(self):
    error = PyKCS11.CKR_OK
    try:
      self.login("0001wrongpass")
    except PyKCS11Error as e:
      error = e.value
    self.assertEqual(error, PyKCS11.CKR_PIN_INCORRECT)

    try:
      self.login("password")
    except PyKCS11Error as e:
      error = e.value
    self.assertEqual(error, PyKCS11.CKR_ARGUMENTS_BAD)

    session = self.login("0001password")
    self.assertNotEqual(session.getSessionInfo(), "")
    session.logout()

  def rsaPkcsSigs(self, session, pubkey, privkey):
    mechs = [
        {"name":"CKM_SHA1_RSA_PKCS", "h":hashes.SHA1(), "m":PyKCS11.CKM_SHA1_RSA_PKCS, "di":SHA1_DI},
        {"name":"CKM_SHA256_RSA_PKCS", "h":hashes.SHA256(), "m":PyKCS11.CKM_SHA256_RSA_PKCS, "di":SHA256_DI},
        {"name":"CKM_SHA384_RSA_PKCS", "h":hashes.SHA384(), "m":PyKCS11.CKM_SHA384_RSA_PKCS, "di":SHA384_DI},
        {"name":"CKM_SHA512_RSA_PKCS", "h":hashes.SHA512(), "m":PyKCS11.CKM_SHA512_RSA_PKCS, "di":SHA512_DI}
        ]
    for mech in (mechs):
      self.assertIn(mech["name"], self.mechs)
      info = self.pkcs11.getMechanismInfo(self.slot, mech["name"])
      self.assertGreaterEqual(2048, info.ulMinKeySize)
      self.assertLessEqual(2048, info.ulMaxKeySize)

      tosign = os.urandom(2000)
      digest = hashes.Hash(mech["h"], backend = default_backend())
      hashed = mech["di"]
      digest.update(tosign)
      hashed += digest.finalize()

      signature = session.sign(privkey, tosign, PyKCS11.Mechanism(mech["m"], None))

      res = session.verify(pubkey, tosign, signature, PyKCS11.Mechanism(mech["m"], None))
      self.assertTrue(res)

      key = self.pubobjToKey(pubkey, session)
      key2 = serialization.load_der_public_key(''.join(map(chr, session.getAttributeValue(pubkey, [PyKCS11.CKA_VALUE])[0])), default_backend())
      self.assertEquals(key.public_numbers(), key2.public_numbers())

      key.verify(''.join(map(chr, signature)), tosign, padding.PKCS1v15(), mech["h"])

      signature = session.sign(privkey, hashed, PyKCS11.Mechanism(PyKCS11.CKM_RSA_PKCS, None))

      res = session.verify(pubkey, hashed, signature, PyKCS11.Mechanism(PyKCS11.CKM_RSA_PKCS, None))
      self.assertTrue(res)

      key.verify(''.join(map(chr, signature)), tosign, padding.PKCS1v15(), mech["h"])

  def rsaPssSigs(self, session, pubkey, privkey, saltlen = 0):
    mechs = [
        {"name":"CKM_SHA1_RSA_PKCS_PSS", "m_hash":PyKCS11.CKM_SHA_1, "mgf1":PyKCS11.CKG_MGF1_SHA1, "hash":hashes.SHA1()},
        {"name":"CKM_SHA256_RSA_PKCS_PSS", "m_hash":PyKCS11.CKM_SHA256, "mgf1":PyKCS11.CKG_MGF1_SHA256, "hash":hashes.SHA256()},
        {"name":"CKM_SHA384_RSA_PKCS_PSS", "m_hash":PyKCS11.CKM_SHA384, "mgf1":PyKCS11.CKG_MGF1_SHA384, "hash":hashes.SHA384()},
        {"name":"CKM_SHA512_RSA_PKCS_PSS", "m_hash":PyKCS11.CKM_SHA512, "mgf1":PyKCS11.CKG_MGF1_SHA512, "hash":hashes.SHA512()}
        ]

    for mech in (mechs):
      self.assertIn(mech["name"], self.mechs)
      info = self.pkcs11.getMechanismInfo(self.slot, mech["name"])

      tosign = os.urandom(1500)

      sig = session.sign(privkey, tosign, RSAPssMech(mech["m_hash"], mech["mgf1"], saltlen))

      res = session.verify(pubkey, tosign, sig, RSAPssMech(mech["m_hash"], mech["mgf1"], saltlen))
      self.assertTrue(res)

      key = self.pubobjToKey(pubkey, session)
      key2 = serialization.load_der_public_key(''.join(map(chr, session.getAttributeValue(pubkey, [PyKCS11.CKA_VALUE])[0])), default_backend())
      self.assertEquals(key.public_numbers(), key2.public_numbers())

      key.verify(''.join(map(chr, sig)), tosign, padding.PSS(padding.MGF1(mech["hash"]), saltlen), mech["hash"])

      digest = hashes.Hash(mech["hash"], backend = default_backend())
      digest.update(tosign)
      hashed = digest.finalize()

      sig = session.sign(privkey, hashed, RSAPssMech(mech["m_hash"], mech["mgf1"], saltlen, m = PyKCS11.CKM_RSA_PKCS_PSS))
      res = session.verify(pubkey, hashed, sig, RSAPssMech(mech["m_hash"], mech["mgf1"], saltlen, m = PyKCS11.CKM_RSA_PKCS_PSS))
      self.assertTrue(res)

  def testGenerateSignRSA2048(self):
    public_template = [
        (PyKCS11.CKA_CLASS, PyKCS11.CKO_PUBLIC_KEY),
        (PyKCS11.CKA_VERIFY, PyKCS11.CK_TRUE),
        (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_RSA),
        (PyKCS11.CKA_MODULUS_BITS, 2048),
        ]

    private_template = [
        (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
        (PyKCS11.CKA_TOKEN, PyKCS11.CK_TRUE),
        (PyKCS11.CKA_SIGN, PyKCS11.CK_TRUE),
        ]

    session = self.login("0001password")

    (pubkey,privkey) = session.generateKeyPair(public_template, private_template)
    self.rsaPkcsSigs(session, pubkey, privkey)
    self.rsaPssSigs(session, pubkey, privkey, saltlen = 32)

    session.destroyObject(privkey)

    session.logout()

  def generateSignEC(self, params, session):
    public_template = [
        (PyKCS11.CKA_CLASS, PyKCS11.CKO_PUBLIC_KEY),
        (PyKCS11.CKA_VERIFY, PyKCS11.CK_TRUE),
        (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_EC),
        (PyKCS11.CKA_EC_PARAMS, params),
        ]

    private_template = [
        (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
        (PyKCS11.CKA_SIGN, PyKCS11.CK_TRUE),
        ]

    if(params == P256_PARAMS):
      keysize = 256
      mech = PyKCS11.CKM_ECDSA_SHA256
      h = hashes.SHA256()
    elif(params == P384_PARAMS):
      keysize = 384
      mech = PyKCS11.CKM_ECDSA_SHA384
      h = hashes.SHA384()
    elif(params == P521_PARAMS):
      keysize = 521
      mech = PyKCS11.CKM_ECDSA_SHA512
      h = hashes.SHA512()

    self.assertIn(PyKCS11.CKM[mech], self.mechs)
    info = self.pkcs11.getMechanismInfo(self.slot, PyKCS11.CKM[mech])
    self.assertGreaterEqual(keysize, info.ulMinKeySize)
    self.assertLessEqual(keysize, info.ulMaxKeySize)

    (pubkey,privkey) = session.generateKeyPair(public_template, private_template, mecha=PyKCS11.MechanismECGENERATEKEYPAIR)

    tosign = os.urandom(2000)
    digest = hashes.Hash(h, backend = default_backend())
    digest.update(tosign)
    hashed = digest.finalize()

    signature = session.sign(privkey, tosign, PyKCS11.Mechanism(mech, None))

    res = session.verify(pubkey, tosign, signature, PyKCS11.Mechanism(mech, None))
    self.assertTrue(res)

    key = self.pubobjToKey(pubkey, session)
    key2 = serialization.load_der_public_key(''.join(map(chr, session.getAttributeValue(pubkey, [PyKCS11.CKA_VALUE])[0])), default_backend())
    self.assertEquals(key.public_numbers(), key2.public_numbers())

    signature = decode_ec_sig(signature)
    key.verify(signature, tosign, ec.ECDSA(h))

    signature = session.sign(privkey, hashed, PyKCS11.Mechanism(PyKCS11.CKM_ECDSA, None))

    res = session.verify(pubkey, hashed, signature, PyKCS11.Mechanism(PyKCS11.CKM_ECDSA, None))
    self.assertTrue(res)

    key = self.pubobjToKey(pubkey, session)
    signature = decode_ec_sig(signature)
    key.verify(signature, tosign, ec.ECDSA(h))

    session.destroyObject(privkey)

  def testGenerateSignEC(self):
    session = self.login("0001password")
    for curve in (P256_PARAMS, P384_PARAMS, P521_PARAMS):
        self.generateSignEC(curve, session)
    session.logout()

  def importRSA(self, session, length, decrypt=False, sign=False):
    key = rsa.generate_private_key(
        public_exponent=0x10001,
        key_size=length,
        backend=default_backend())

    self.assertIn("CKM_RSA_PKCS", self.mechs)
    info = self.pkcs11.getMechanismInfo(self.slot, "CKM_RSA_PKCS")
    self.assertGreaterEqual(length, info.ulMinKeySize)
    self.assertLessEqual(length, info.ulMaxKeySize)

    p = decode_int(key.private_numbers().p)
    q = decode_int(key.private_numbers().q)
    e = decode_int(key.public_key().public_numbers().e)

    template = [
        (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
        (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_RSA),
        (PyKCS11.CKA_DECRYPT, PyKCS11.CK_TRUE if decrypt else PyKCS11.CK_FALSE),
        (PyKCS11.CKA_SIGN, PyKCS11.CK_TRUE if sign else PyKCS11.CK_FALSE),
        (PyKCS11.CKA_PRIME_1, p),
        (PyKCS11.CKA_PRIME_2, q),
        (PyKCS11.CKA_PUBLIC_EXPONENT, e),
        ]

    keyobj = session.createObject(template)

    pubkey = session.findObjects([(PyKCS11.CKA_ID, session.getAttributeValue(keyobj, [PyKCS11.CKA_ID])[0]), (PyKCS11.CKA_CLASS, PyKCS11.CKO_PUBLIC_KEY)])[0]

    return key,keyobj,pubkey

  def testImportDecryptRSA3072(self):
    session = self.login("0001password")

    key, keyobj, pubkey = self.importRSA(session, 3072, decrypt=True)

    data = os.urandom(64)

    ciphertext = key.public_key().encrypt(
        data,
        padding.PKCS1v15())

    decrypted = session.decrypt(keyobj, ciphertext, PyKCS11.Mechanism(PyKCS11.CKM_RSA_PKCS, None))
    decrypted = ''.join(map(chr, decrypted))
    self.assertEquals(data, decrypted)

    self.assertIn("CKM_RSA_PKCS_OAEP", self.mechs)
    info = self.pkcs11.getMechanismInfo(self.slot, "CKM_RSA_PKCS_OAEP")
    self.assertGreaterEqual(3072, info.ulMinKeySize)
    self.assertLessEqual(3072, info.ulMaxKeySize)

    ciphertext = key.public_key().encrypt(
        data,
	padding.OAEP(
	  mgf=padding.MGF1(algorithm=hashes.SHA384()),
	  algorithm=hashes.SHA384(),
	  label=None))

    decrypted = session.decrypt(keyobj, ciphertext, PyKCS11.RSAOAEPMechanism(PyKCS11.CKM_SHA384, PyKCS11.CKG_MGF1_SHA384))
    decrypted = ''.join(map(chr, decrypted))
    self.assertEqual(data, decrypted)

    session.destroyObject(keyobj)

    session.logout()

  def testImportSignRSA4096(self):
    session = self.login("0001password")

    key,privkey,pubkey = self.importRSA(session, 4096, sign=True)
    self.rsaPssSigs(session, pubkey, privkey)

    session.destroyObject(privkey)
    session.logout()

  def testGenerateHmacSignVerify(self):
    session = self.login("0001password")
    for h in (PyKCS11.CKM_SHA_1_HMAC, PyKCS11.CKM_SHA256_HMAC, PyKCS11.CKM_SHA384_HMAC, PyKCS11.CKM_SHA512_HMAC):
      if(h == PyKCS11.CKM_SHA_1_HMAC):
        t = PyKCS11.CKK_SHA_1_HMAC
      elif(h == PyKCS11.CKM_SHA256_HMAC):
        t = PyKCS11.CKK_SHA256_HMAC
      elif(h == PyKCS11.CKM_SHA384_HMAC):
        t = PyKCS11.CKK_SHA384_HMAC
      elif(h == PyKCS11.CKM_SHA512_HMAC):
        t = PyKCS11.CKK_SHA512_HMAC

      self.assertIn(PyKCS11.CKM[h], self.mechs)
      info = self.pkcs11.getMechanismInfo(self.slot, PyKCS11.CKM[h])

      template = [
          (PyKCS11.CKA_CLASS, PyKCS11.CKO_SECRET_KEY),
          (PyKCS11.CKA_KEY_TYPE, t),
          (PyKCS11.CKA_SIGN, PyKCS11.CK_TRUE),
          (PyKCS11.CKA_VERIFY, PyKCS11.CK_TRUE),
          ]
      keyobj = session.generateKey(template, PyKCS11.Mechanism(PyKCS11.CKM_GENERIC_SECRET_KEY_GEN, None))

      data = os.urandom(64)
      signature = session.sign(keyobj, data, PyKCS11.Mechanism(h, None))
      res = session.verify(keyobj, data, signature, PyKCS11.Mechanism(h, None))
      self.assertTrue(res)

      session.destroyObject(keyobj)

    session.logout()

  def testGetRandom(self):
    session = self.login("0001password")
    rnd = session.generateRandom(128)
    rnd2 = session.generateRandom(128)
    self.assertNotEqual(rnd, rnd2)
    self.assertEqual(128, len(rnd))
    self.assertEqual(len(rnd), len(rnd2))
    session.logout()

  def testGeneratedWrap(self):
    session = self.login("0001password")
    wrapTemplate = [
        (PyKCS11.CKA_CLASS, PyKCS11.CKO_SECRET_KEY),
        (PyKCS11.CKA_KEY_TYPE, CKK_YUBICO_AES128_CCM_WRAP),
        (PyKCS11.CKA_WRAP, PyKCS11.CK_TRUE),
        (PyKCS11.CKA_UNWRAP, PyKCS11.CK_TRUE),
        ]

    wrapobj = session.generateKey(wrapTemplate, PyKCS11.Mechanism(PyKCS11.CKM_GENERIC_SECRET_KEY_GEN, None))

    eckey = ec.generate_private_key(ec.SECP256R1(), backend=default_backend())

    s = decode_int(eckey.private_numbers().private_value)
    ecTemplate = [
        (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
        (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_EC),
        (PyKCS11.CKA_SIGN, PyKCS11.CK_TRUE),
        (PyKCS11.CKA_EXTRACTABLE, PyKCS11.CK_TRUE),
        (PyKCS11.CKA_EC_PARAMS, P256_PARAMS),
        (PyKCS11.CKA_VALUE, s),
        ]

    keyobj = session.createObject(ecTemplate)

    tosign = os.urandom(2000)
    signature = session.sign(keyobj, tosign, PyKCS11.Mechanism(PyKCS11.CKM_ECDSA_SHA256, None))
    signature = decode_ec_sig(signature)
    eckey.public_key().verify(signature, tosign, ec.ECDSA(hashes.SHA256()))

    wrap = session.wrapKey(wrapobj, keyobj, mecha=PyKCS11.Mechanism(CKM_YUBICO_AES_CCM_WRAP, None))

    session.destroyObject(keyobj)

    keyobj = session.unwrapKey(wrapobj, wrap, [], mecha=PyKCS11.Mechanism(CKM_YUBICO_AES_CCM_WRAP, None))

    signature = session.sign(keyobj, tosign, PyKCS11.Mechanism(PyKCS11.CKM_ECDSA_SHA256, None))
    signature = decode_ec_sig(signature)
    eckey.public_key().verify(signature, tosign, ec.ECDSA(hashes.SHA256()))

    session.destroyObject(keyobj)
    session.destroyObject(wrapobj)

    session.logout()

  def testEncryptDecryptWrap(self):
    session = self.login("0001password")
    key = os.urandom(32)
    encTemplate = [
        (PyKCS11.CKA_CLASS, PyKCS11.CKO_SECRET_KEY),
        (PyKCS11.CKA_KEY_TYPE, CKK_YUBICO_AES256_CCM_WRAP),
        (PyKCS11.CKA_ENCRYPT, PyKCS11.CK_TRUE),
        (PyKCS11.CKA_DECRYPT, PyKCS11.CK_FALSE),
        (PyKCS11.CKA_VALUE, key),
        ]
    decTemplate = [
        (PyKCS11.CKA_CLASS, PyKCS11.CKO_SECRET_KEY),
        (PyKCS11.CKA_KEY_TYPE, CKK_YUBICO_AES256_CCM_WRAP),
        (PyKCS11.CKA_ENCRYPT, PyKCS11.CK_FALSE),
        (PyKCS11.CKA_DECRYPT, PyKCS11.CK_TRUE),
        (PyKCS11.CKA_VALUE, key),
        ]

    encobj = session.createObject(encTemplate)
    decobj = session.createObject(decTemplate)

    for length in (1, 16, 128, 1024, 1989):
      data = os.urandom(length)
      cipher = session.encrypt(encobj, data, PyKCS11.Mechanism(CKM_YUBICO_AES_CCM_WRAP, None))
      plain = session.decrypt(decobj, cipher, PyKCS11.Mechanism(CKM_YUBICO_AES_CCM_WRAP, None))
      plain = ''.join(map(chr, plain))
      self.assertEquals(data, plain)

    session.destroyObject(encobj)
    session.destroyObject(decobj)

    session.logout()

  def testImportCertFind(self):
    session = self.login("0001password")

    label = uuid.uuid4().hex

    private_key = rsa.generate_private_key(
        public_exponent=0x10001, key_size=4096, backend=default_backend())
    builder = x509.CertificateBuilder()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"pkcs11 test cert")])
    builder = builder.subject_name(name)
    builder = builder.issuer_name(name)
    one_day = datetime.timedelta(1, 0, 0)
    builder = builder.not_valid_before(datetime.datetime.today() - one_day)
    builder = builder.not_valid_after(datetime.datetime.today() + one_day)
    builder = builder.serial_number(int(uuid.uuid4()))
    builder = builder.public_key(private_key.public_key())
    certificate = builder.sign(private_key=private_key, algorithm=hashes.SHA256(),
                                   backend=default_backend())

    p = decode_int(private_key.private_numbers().p)
    q = decode_int(private_key.private_numbers().q)
    e = decode_int(private_key.public_key().public_numbers().e)

    keyTemplate = [
        (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
        (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_RSA),
        (PyKCS11.CKA_DECRYPT, PyKCS11.CK_TRUE),
        (PyKCS11.CKA_PRIME_1, p),
        (PyKCS11.CKA_PRIME_2, q),
        (PyKCS11.CKA_PUBLIC_EXPONENT, e),
        (PyKCS11.CKA_LABEL, label),
        ]

    keyobj = session.createObject(keyTemplate)

    certTemplate = [
        (PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE),
        (PyKCS11.CKA_CERTIFICATE_TYPE, PyKCS11.CKC_X_509),
        (PyKCS11.CKA_VALUE, certificate.public_bytes(Encoding.DER)),
        (PyKCS11.CKA_LABEL, label),
        ]

    certobj = session.createObject(certTemplate)

    self.assertEqual(label, session.getAttributeValue(certobj, [PyKCS11.CKA_LABEL])[0])
    certval = ''.join(map(chr, session.getAttributeValue(certobj, [PyKCS11.CKA_VALUE])[0]))
    self.assertEqual(certval, certificate.public_bytes(Encoding.DER))

    objs = session.findObjects([(PyKCS11.CKA_LABEL, label)])
    self.assertEqual(len(objs), 3) # this is returned as 3 objects, privkey, pubkey & cert
    for obj in (objs):
      cka_class = session.getAttributeValue(obj, [PyKCS11.CKA_CLASS])[0]
      if(cka_class == PyKCS11.CKO_PRIVATE_KEY or cka_class == PyKCS11.CKO_PUBLIC_KEY):
        cka_modulus = ''.join(map(chr, session.getAttributeValue(obj, [PyKCS11.CKA_MODULUS])[0]))
        n = decode_int(private_key.public_key().public_numbers().n)
        self.assertEqual(n, cka_modulus)
      elif(cka_class == PyKCS11.CKO_CERTIFICATE):
        val = ''.join(map(chr, session.getAttributeValue(certobj, [PyKCS11.CKA_VALUE])[0]))
        self.assertEqual(val, certificate.public_bytes(Encoding.DER))

        # TODO: extract subject and stuff here and compare.
      else:
        raise ValueError

    session.destroyObject(keyobj)
    session.destroyObject(certobj)

    session.logout()

  def testHmacVectors(self):
    vectors = [
        {"key": b"\x0b" * 20, "chal": b"Hi There", "exp_sha1": b"\xb6\x17\x31\x86\x55\x05\x72\x64\xe2\x8b\xc0\xb6\xfb\x37\x8c\x8e\xf1\x46\xbe\x00", "exp_sha256": b"\xb0\x34\x4c\x61\xd8\xdb\x38\x53\x5c\xa8\xaf\xce\xaf\x0b\xf1\x2b\x88\x1d\xc2\x00\xc9\x83\x3d\xa7\x26\xe9\x37\x6c\x2e\x32\xcf\xf7", "exp_sha512": b"\x87\xaa\x7c\xde\xa5\xef\x61\x9d\x4f\xf0\xb4\x24\x1a\x1d\x6c\xb0\x23\x79\xf4\xe2\xce\x4e\xc2\x78\x7a\xd0\xb3\x05\x45\xe1\x7c\xde\xda\xa8\x33\xb7\xd6\xb8\xa7\x02\x03\x8b\x27\x4e\xae\xa3\xf4\xe4\xbe\x9d\x91\x4e\xeb\x61\xf1\x70\x2e\x69\x6c\x20\x3a\x12\x68\x54", "exp_sha384": b"\xaf\xd0\x39\x44\xd8\x48\x95\x62\x6b\x08\x25\xf4\xab\x46\x90\x7f\x15\xf9\xda\xdb\xe4\x10\x1e\xc6\x82\xaa\x03\x4c\x7c\xeb\xc5\x9c\xfa\xea\x9e\xa9\x07\x6e\xde\x7f\x4a\xf1\x52\xe8\xb2\xfa\x9c\xb6"},
        {"key": b"Jefe", "chal": b"what do ya want for nothing?", "exp_sha1": b"\xef\xfc\xdf\x6a\xe5\xeb\x2f\xa2\xd2\x74\x16\xd5\xf1\x84\xdf\x9c\x25\x9a\x7c\x79", "exp_sha256": b"\x5b\xdc\xc1\x46\xbf\x60\x75\x4e\x6a\x04\x24\x26\x08\x95\x75\xc7\x5a\x00\x3f\x08\x9d\x27\x39\x83\x9d\xec\x58\xb9\x64\xec\x38\x43", "exp_sha512": b"\x16\x4b\x7a\x7b\xfc\xf8\x19\xe2\xe3\x95\xfb\xe7\x3b\x56\xe0\xa3\x87\xbd\x64\x22\x2e\x83\x1f\xd6\x10\x27\x0c\xd7\xea\x25\x05\x54\x97\x58\xbf\x75\xc0\x5a\x99\x4a\x6d\x03\x4f\x65\xf8\xf0\xe6\xfd\xca\xea\xb1\xa3\x4d\x4a\x6b\x4b\x63\x6e\x07\x0a\x38\xbc\xe7\x37", "exp_sha384": b"\xaf\x45\xd2\xe3\x76\x48\x40\x31\x61\x7f\x78\xd2\xb5\x8a\x6b\x1b\x9c\x7e\xf4\x64\xf5\xa0\x1b\x47\xe4\x2e\xc3\x73\x63\x22\x44\x5e\x8e\x22\x40\xca\x5e\x69\xe2\xc7\x8b\x32\x39\xec\xfa\xb2\x16\x49"},
        {"key": b"\xaa" * 20, "chal": b"\xdd" * 50, "exp_sha1": b"\x12\x5d\x73\x42\xb9\xac\x11\xcd\x91\xa3\x9a\xf4\x8a\xa1\x7b\x4f\x63\xf1\x75\xd3", "exp_sha256": b"\x77\x3e\xa9\x1e\x36\x80\x0e\x46\x85\x4d\xb8\xeb\xd0\x91\x81\xa7\x29\x59\x09\x8b\x3e\xf8\xc1\x22\xd9\x63\x55\x14\xce\xd5\x65\xfe", "exp_sha512": b"\xfa\x73\xb0\x08\x9d\x56\xa2\x84\xef\xb0\xf0\x75\x6c\x89\x0b\xe9\xb1\xb5\xdb\xdd\x8e\xe8\x1a\x36\x55\xf8\x3e\x33\xb2\x27\x9d\x39\xbf\x3e\x84\x82\x79\xa7\x22\xc8\x06\xb4\x85\xa4\x7e\x67\xc8\x07\xb9\x46\xa3\x37\xbe\xe8\x94\x26\x74\x27\x88\x59\xe1\x32\x92\xfb", "exp_sha384": b"\x88\x06\x26\x08\xd3\xe6\xad\x8a\x0a\xa2\xac\xe0\x14\xc8\xa8\x6f\x0a\xa6\x35\xd9\x47\xac\x9f\xeb\xe8\x3e\xf4\xe5\x59\x66\x14\x4b\x2a\x5a\xb3\x9d\xc1\x38\x14\xb9\x4e\x3a\xb6\xe1\x01\xa3\x4f\x27"},
            {"key": b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19", "chal": b"\xcd" * 50, "exp_sha1": b"\x4c\x90\x07\xf4\x02\x62\x50\xc6\xbc\x84\x14\xf9\xbf\x50\xc8\x6c\x2d\x72\x35\xda", "exp_sha256": b"\x82\x55\x8a\x38\x9a\x44\x3c\x0e\xa4\xcc\x81\x98\x99\xf2\x08\x3a\x85\xf0\xfa\xa3\xe5\x78\xf8\x07\x7a\x2e\x3f\xf4\x67\x29\x66\x5b", "exp_sha512": b"\xb0\xba\x46\x56\x37\x45\x8c\x69\x90\xe5\xa8\xc5\xf6\x1d\x4a\xf7\xe5\x76\xd9\x7f\xf9\x4b\x87\x2d\xe7\x6f\x80\x50\x36\x1e\xe3\xdb\xa9\x1c\xa5\xc1\x1a\xa2\x5e\xb4\xd6\x79\x27\x5c\xc5\x78\x80\x63\xa5\xf1\x97\x41\x12\x0c\x4f\x2d\xe2\xad\xeb\xeb\x10\xa2\x98\xdd", "exp_sha384": b"\x3e\x8a\x69\xb7\x78\x3c\x25\x85\x19\x33\xab\x62\x90\xaf\x6c\xa7\x7a\x99\x81\x48\x08\x50\x00\x9c\xc5\x57\x7c\x6e\x1f\x57\x3b\x4e\x68\x01\xdd\x23\xc4\xa7\xd6\x79\xcc\xf8\xa3\x86\xc6\x74\xcf\xfb"},
        ]
    session = self.login("0001password")
    for v in vectors:
        for h in ("sha1", "sha256", "sha384", "sha512"):
          if(h == "sha1"):
            mechanism = PyKCS11.CKM_SHA_1_HMAC
            t = PyKCS11.CKK_SHA_1_HMAC
            exp = v["exp_sha1"]
          elif(h == "sha256"):
            mechanism = PyKCS11.CKM_SHA256_HMAC
            t = PyKCS11.CKK_SHA256_HMAC
            exp = v["exp_sha256"]
          elif(h == "sha384"):
            mechanism = PyKCS11.CKM_SHA384_HMAC
            t = PyKCS11.CKK_SHA384_HMAC
            exp = v["exp_sha384"]
          elif(h == "sha512"):
            mechanism = PyKCS11.CKM_SHA512_HMAC
            t = PyKCS11.CKK_SHA512_HMAC
            exp = v["exp_sha512"]

          self.assertIn(PyKCS11.CKM[mechanism], self.mechs)
          info = self.pkcs11.getMechanismInfo(self.slot, PyKCS11.CKM[mechanism])
          self.assertGreaterEqual(len(v["key"]), info.ulMinKeySize)
          self.assertLessEqual(len(v["key"]), info.ulMaxKeySize)

          template = [
              (PyKCS11.CKA_CLASS, PyKCS11.CKO_SECRET_KEY),
              (PyKCS11.CKA_KEY_TYPE, t),
              (PyKCS11.CKA_SIGN, PyKCS11.CK_TRUE),
              (PyKCS11.CKA_VERIFY, PyKCS11.CK_TRUE),
              (PyKCS11.CKA_VALUE, v['key'])
              ]

          key = session.createObject(template)
          response = session.sign(key, v["chal"], PyKCS11.Mechanism(mechanism, None))
          response = ''.join(map(chr, response))
          self.assertEquals(response, exp)

          session.destroyObject(key)
    session.logout()

  def testDigest(self):
    vectors = [
        {"msg": "abc", PyKCS11.CKM_SHA_1: b"\xa9\x99\x3e\x36\x47\x06\x81\x6a\xba\x3e\x25\x71\x78\x50\xc2\x6c\x9c\xd0\xd8\x9d", PyKCS11.CKM_SHA256: b"\xba\x78\x16\xbf\x8f\x01\xcf\xea\x41\x41\x40\xde\x5d\xae\x22\x23\xb0\x03\x61\xa3\x96\x17\x7a\x9c\xb4\x10\xff\x61\xf2\x00\x15\xad", PyKCS11.CKM_SHA384: b"\xcb\x00\x75\x3f\x45\xa3\x5e\x8b\xb5\xa0\x3d\x69\x9a\xc6\x50\x07\x27\x2c\x32\xab\x0e\xde\xd1\x63\x1a\x8b\x60\x5a\x43\xff\x5b\xed\x80\x86\x07\x2b\xa1\xe7\xcc\x23\x58\xba\xec\xa1\x34\xc8\x25\xa7", PyKCS11.CKM_SHA512: b"\xdd\xaf\x35\xa1\x93\x61\x7a\xba\xcc\x41\x73\x49\xae\x20\x41\x31\x12\xe6\xfa\x4e\x89\xa9\x7e\xa2\x0a\x9e\xee\xe6\x4b\x55\xd3\x9a\x21\x92\x99\x2a\x27\x4f\xc1\xa8\x36\xba\x3c\x23\xa3\xfe\xeb\xbd\x45\x4d\x44\x23\x64\x3c\xe8\x0e\x2a\x9a\xc9\x4f\xa5\x4c\xa4\x9f"},
        {"msg": "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", PyKCS11.CKM_SHA_1: b"\x84\x98\x3e\x44\x1c\x3b\xd2\x6e\xba\xae\x4a\xa1\xf9\x51\x29\xe5\xe5\x46\x70\xf1", PyKCS11.CKM_SHA256: b"\x24\x8d\x6a\x61\xd2\x06\x38\xb8\xe5\xc0\x26\x93\x0c\x3e\x60\x39\xa3\x3c\xe4\x59\x64\xff\x21\x67\xf6\xec\xed\xd4\x19\xdb\x06\xc1", PyKCS11.CKM_SHA384: b"\x33\x91\xfd\xdd\xfc\x8d\xc7\x39\x37\x07\xa6\x5b\x1b\x47\x09\x39\x7c\xf8\xb1\xd1\x62\xaf\x05\xab\xfe\x8f\x45\x0d\xe5\xf3\x6b\xc6\xb0\x45\x5a\x85\x20\xbc\x4e\x6f\x5f\xe9\x5b\x1f\xe3\xc8\x45\x2b", PyKCS11.CKM_SHA512: b"\x20\x4a\x8f\xc6\xdd\xa8\x2f\x0a\x0c\xed\x7b\xeb\x8e\x08\xa4\x16\x57\xc1\x6e\xf4\x68\xb2\x28\xa8\x27\x9b\xe3\x31\xa7\x03\xc3\x35\x96\xfd\x15\xc1\x3b\x1b\x07\xf9\xaa\x1d\x3b\xea\x57\x78\x9c\xa0\x31\xad\x85\xc7\xa7\x1d\xd7\x03\x54\xec\x63\x12\x38\xca\x34\x45"},
        {"msg": "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", PyKCS11.CKM_SHA_1: b"\xa4\x9b\x24\x46\xa0\x2c\x64\x5b\xf4\x19\xf9\x95\xb6\x70\x91\x25\x3a\x04\xa2\x59", PyKCS11.CKM_SHA256: b"\xcf\x5b\x16\xa7\x78\xaf\x83\x80\x03\x6c\xe5\x9e\x7b\x04\x92\x37\x0b\x24\x9b\x11\xe8\xf0\x7a\x51\xaf\xac\x45\x03\x7a\xfe\xe9\xd1", PyKCS11.CKM_SHA384: b"\x09\x33\x0c\x33\xf7\x11\x47\xe8\x3d\x19\x2f\xc7\x82\xcd\x1b\x47\x53\x11\x1b\x17\x3b\x3b\x05\xd2\x2f\xa0\x80\x86\xe3\xb0\xf7\x12\xfc\xc7\xc7\x1a\x55\x7e\x2d\xb9\x66\xc3\xe9\xfa\x91\x74\x60\x39", PyKCS11.CKM_SHA512: b"\x8e\x95\x9b\x75\xda\xe3\x13\xda\x8c\xf4\xf7\x28\x14\xfc\x14\x3f\x8f\x77\x79\xc6\xeb\x9f\x7f\xa1\x72\x99\xae\xad\xb6\x88\x90\x18\x50\x1d\x28\x9e\x49\x00\xf7\xe4\x33\x1b\x99\xde\xc4\xb5\x43\x3a\xc7\xd3\x29\xee\xb6\xdd\x26\x54\x5e\x96\xe5\x5b\x87\x4b\xe9\x09"},
        ]

    session = self.login("0001password")

    for v in vectors:
      for m in (PyKCS11.CKM_SHA_1, PyKCS11.CKM_SHA256, PyKCS11.CKM_SHA384, PyKCS11.CKM_SHA512):
        resp = session.digest(v["msg"], PyKCS11.Mechanism(m, None))
        resp = ''.join(map(chr, resp))
        self.assertEquals(resp, v[m])

    session.logout()

  def testListSecretKeys(self):
    session = self.login("0001password")
    wrap_template = [
        (PyKCS11.CKA_CLASS, PyKCS11.CKO_SECRET_KEY),
        (PyKCS11.CKA_KEY_TYPE, CKK_YUBICO_AES192_CCM_WRAP),
        (PyKCS11.CKA_WRAP, PyKCS11.CK_TRUE),
        (PyKCS11.CKA_UNWRAP, PyKCS11.CK_TRUE),
        ]

    wrapobj = session.generateKey(wrap_template, PyKCS11.Mechanism(PyKCS11.CKM_GENERIC_SECRET_KEY_GEN, None))

    hmac_template = [
          (PyKCS11.CKA_CLASS, PyKCS11.CKO_SECRET_KEY),
          (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_SHA_1_HMAC),
          (PyKCS11.CKA_SIGN, PyKCS11.CK_TRUE),
          (PyKCS11.CKA_VERIFY, PyKCS11.CK_TRUE),
          ]
    hmacobj = session.generateKey(hmac_template, PyKCS11.Mechanism(PyKCS11.CKM_GENERIC_SECRET_KEY_GEN, None))

    public_template = [
        (PyKCS11.CKA_CLASS, PyKCS11.CKO_PUBLIC_KEY),
        (PyKCS11.CKA_VERIFY, PyKCS11.CK_TRUE),
        (PyKCS11.CKA_KEY_TYPE, PyKCS11.CKK_EC),
        (PyKCS11.CKA_EC_PARAMS, P256_PARAMS),
        ]

    private_template = [
        (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
        (PyKCS11.CKA_SIGN, PyKCS11.CK_TRUE),
        ]

    (pubkey, privkey) = session.generateKeyPair(public_template, private_template, mecha=PyKCS11.MechanismECGENERATEKEYPAIR)

    objects = session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_SECRET_KEY)])

    handles = [i.value() for i in objects]

    self.assertTrue(wrapobj.value() in handles)
    self.assertTrue(hmacobj.value() in handles)
    self.assertFalse(pubkey.value() in handles)
    self.assertFalse(privkey.value() in handles)

    session.destroyObject(wrapobj)
    session.destroyObject(hmacobj)
    #session.destroyObject(pubkey)
    session.destroyObject(privkey)

if __name__ == '__main__':
  unittest.main()
