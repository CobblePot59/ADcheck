import io

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

class ECDHPrivateKeyBlob:
	def __init__(self):
		self.magic = None
		self.length = None
		self.x = None
		self.y = None
		self.privateexp = None

	@staticmethod
	def from_bytes(data):
		return ECDHPrivateKeyBlob.from_buffer(io.BytesIO(data))
	
	@staticmethod
	def from_buffer(buff):
		pk = ECDHPrivateKeyBlob()
		pk.magic = int.from_bytes(buff.read(4), byteorder='little', signed=False)
		pk.length = int.from_bytes(buff.read(4), byteorder='little', signed=False)
		pk.x = int.from_bytes(buff.read(pk.length), byteorder='little', signed=False)
		pk.y = int.from_bytes(buff.read(pk.length), byteorder='little', signed=False)
		pk.privateexp = int.from_bytes(buff.read(pk.length), byteorder='little', signed=False)
		return pk
	
	def get_curve(self):
		if self.magic in [0x314B4345, 0x324B4345, 0x31534345, 0x32534345]:
			return ec.SECP256R1()
		elif self.magic in [0x334B4345, 0x344B4345, 0x33534345, 0x34534345]:
			return ec.SECP384R1()
		elif self.magic in [0x354B4345, 0x364B4345, 0x35534345, 0x36534345]:
			return ec.SECP521R1()
		else:
			raise Exception('Unknown curve type for %s' % self.magic.to_bytes(4, byteorder='little', signed=False).hex())
	
	def get_key(self):
		curve = self.get_curve()
		
		private_numbers = ec.EllipticCurvePrivateNumbers(
			private_value=self.privateexp,
			public_numbers=ec.EllipticCurvePublicNumbers(
				x=self.x,
				y=self.y,
				curve=curve
			)
		)
		private_key = private_numbers.private_key(default_backend())
		return private_key
	
	def get_pubkey(self):
		curve = self.get_curve()
		
		public_numbers = ec.EllipticCurvePublicNumbers(
			x=self.x,
			y=self.y,
			curve=curve
		)
		public_key = public_numbers.public_key(default_backend())
		return public_key


	def __str__(self):
		t = ''
		for k in self.__dict__:
			t += '%s: %s\r\n' % (k, self.__dict__[k])
		return t