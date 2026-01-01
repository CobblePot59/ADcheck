import io
from winacl.dtyp.wcee.rsaprivkey import RSAPrivateKeyBlob


# https://github.com/openssl/openssl/blob/9dddcd90a1350fa63486cbf3226c3eee79f9aff5/crypto/pem/pvkfmt.c
class PVKFile:
	def __init__(self):
		self.magic:int = 0xb0b5f11e
		self.reserved:int = 0
		self.keytype:bytes = None
		self.isencrypted:int = None
		self.saltlength:int = None
		self.keylength:int = None
		self.saltblob:bytes = None
		self.keyblob:bytes = None

	@staticmethod
	def construct_unencrypted(keytype, keydata):
		if isinstance(keytype, str):
			keytype = keytype.encode()
		pvk = PVKFile()
		pvk.keytype = keytype
		pvk.isencrypted = 0
		pvk.saltlength = 0
		pvk.keylength = len(keydata)
		pvk.saltblob = b''
		pvk.keyblob = keydata
		return pvk

	@staticmethod
	def from_file(filepath):
		with open(filepath, 'rb') as f:
			return PVKFile.from_buffer(f)
	
	
	@staticmethod
	def from_bytes(data):
		return PVKFile.from_buffer(io.BytesIO(data))

	@staticmethod
	def from_buffer(buff):
		pvk = PVKFile()
		pvk.magic = int.from_bytes(buff.read(4), byteorder='little', signed=False)
		assert 0xb0b5f11e == pvk.magic
		pvk.reserved = int.from_bytes(buff.read(4), byteorder='little', signed=False)
		pvk.keytype = buff.read(4)
		pvk.isencrypted = int.from_bytes(buff.read(4), byteorder='little', signed=False)
		pvk.saltlength = int.from_bytes(buff.read(4), byteorder='little', signed=False)
		pvk.keylength = int.from_bytes(buff.read(4), byteorder='little', signed=False)
		pvk.saltblob = buff.read(pvk.saltlength)
		pvk.keyblob = buff.read(pvk.keylength)
		return pvk

	def to_bytes(self):
		data = b''
		data += self.magic.to_bytes(4, byteorder='little', signed=False)
		data += self.reserved.to_bytes(4, byteorder='little', signed=False)
		data += self.keytype
		data += self.isencrypted.to_bytes(4, byteorder='little', signed=False)
		if self.saltblob is None:
			self.saltblob = b''
		if self.keyblob is None:
			self.keyblob = b''
		data += len(self.saltblob).to_bytes(4, byteorder='little', signed=False)
		data += len(self.keyblob).to_bytes(4, byteorder='little', signed=False)
		data += self.saltblob
		data += self.keyblob
		return data

	def get_key(self):
		if self.keyblob[8:].startswith(b'RSA2'):
			return RSAPrivateKeyBlob.from_bytes(self.keyblob).get_key()

	def __str__(self):
		t = ''
		for k in self.__dict__:
			t += '%s: %s\r\n' % (k, self.__dict__[k])
		return t