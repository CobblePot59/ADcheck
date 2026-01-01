import io
from winacl.dtyp.wcee import keyblobselector

class CryptoAPIKeyProperty:
	def __init__(self):
		self.length = None
		self.type = None
		self.unknown1 = None
		self.name_len = None
		self.name = None
		self.value_len = None
		self.value = None
	
	@staticmethod
	def from_bytes(data:bytes):
		return CryptoAPIKeyProperty.from_buffer(io.BytesIO(data))
	
	@staticmethod
	def from_buffer(buff:io.BytesIO):
		prop = CryptoAPIKeyProperty()
		prop.length = int.from_bytes(buff.read(4), byteorder='little', signed=False)
		prop.type = int.from_bytes(buff.read(4), byteorder='little', signed=False)
		prop.unknown1 = buff.read(4)
		prop.name_len = int.from_bytes(buff.read(4), byteorder='little', signed=False)
		prop.value_len = int.from_bytes(buff.read(4), byteorder='little', signed=False)
		prop.name = buff.read(prop.name_len).decode('utf-16-le')
		prop.value = buff.read(prop.value_len)
		if prop.name == 'NgcSoftwareKeyPbkdf2Round':
			prop.value = int.from_bytes(prop.value, byteorder='little', signed=False)
		return prop
	
	def __str__(self):
		t = '= CryptoAPIKeyProperty =\n'
		t += 'Length: %s\n' % self.length
		t += 'Type: %s\n' % self.type
		t += 'Unknown1: %s\n' % self.unknown1
		t += 'Name Length: %s\n' % self.name_len
		t += 'Name: %s\n' % self.name
		t += 'Value Length: %s\n' % self.value_len
		t += 'Value: %s\n' % self.value
		return t

class CryptoAPIKeyProperties:
	# after DPAPI decryption, the properties are stored in a list of CryptoAPIKeyProperty objects
	def __init__(self):
		self.properties = {}
	
	@staticmethod
	def from_bytes(data:bytes):
		return CryptoAPIKeyProperties.from_buffer(io.BytesIO(data))
	
	@staticmethod
	def from_buffer(buff:io.BytesIO):
		prop = CryptoAPIKeyProperties()
		while True:
			p = CryptoAPIKeyProperty.from_buffer(buff)
			prop.properties[p.name] = p
			if buff.tell() == len(buff.getbuffer()):
				return prop.properties


class CryptoAPIPublicKey:
	def __init__(self):
		self.header_size = None
		self.unknown1 = None
		self.unknown2 = None
		self.header1_size = None
		self.header2_size = None
		self.header1 = None
		self.header2 = None
		self.keyblob = None
	
	@staticmethod
	def from_bytes(data:bytes):
		return CryptoAPIPublicKey.from_buffer(io.BytesIO(data))
	
	@staticmethod
	def from_buffer(buff:io.BytesIO):
		start = buff.tell()
		key = CryptoAPIPublicKey()
		key.header_size = int.from_bytes(buff.read(4), byteorder='little', signed=False)
		key.unknown1 = buff.read(4)
		key.unknown2 = buff.read(4)
		key.header1_size = int.from_bytes(buff.read(4), byteorder='little', signed=False)
		key.header2_size = int.from_bytes(buff.read(4), byteorder='little', signed=False)
		key.header1 = buff.read(key.header1_size).decode('utf-16-le')
		key.header2 = buff.read(key.header2_size)
		buff.read(20)

		# this point it's a public key.
		keystruct = keyblobselector(buff)
		key.keyblob = keystruct.from_buffer(buff)
		return key

	def __str__(self):
		t = '== CryptoAPIPublicKey ==\n'
		t += 'Header Size: %s\n' % self.header_size
		t += 'Unknown1: %s\n' % self.unknown1
		t += 'Unknown2: %s\n' % self.unknown2
		t += 'Header1 Size: %s\n' % self.header1_size
		t += 'Header2 Size: %s\n' % self.header2_size
		t += 'Header1: %s\n' % self.header1
		t += 'Header2: %s\n' % self.header2

		t += 'Key: %s\n' % self.keyblob
		return t


class CryptoAPIKeyFile:
	def __init__(self):
		self.type = None
		self.unknown1 = None
		self.description_len = None
		self.unknown2 = None
		self.field_cnt = None
		self.filed_lengths = []
		self.description = None
		self.fields = []
	
	def from_bytes(data:bytes):
		return CryptoAPIKeyFile.from_buffer(io.BytesIO(data))

	def from_buffer(buff:io.BytesIO):
		key = CryptoAPIKeyFile()
		key.type = buff.read(4)
		key.unknown1 = buff.read(4)
		key.description_len = int.from_bytes(buff.read(4), byteorder='little', signed=False)
		key.unknown2 = buff.read(2)
		key.field_cnt = int.from_bytes(buff.read(2), byteorder='little', signed=False)
		for _ in range(0,key.field_cnt):
			key.filed_lengths.append(int.from_bytes(buff.read(4), byteorder='little', signed=False))
		buff.seek(44,0)
		key.description = buff.read(key.description_len).decode('utf-16-le')
		for i, size in enumerate(key.filed_lengths):
			field = buff.read(size)
			if i == 0:
				field = CryptoAPIPublicKey.from_bytes(field) # other fields are -hopefully- DPAPI blobs
			key.fields.append(field)
		return key
	
	def __str__(self):
		t = '== CryptoAPIKeyDescriptor ==\n'
		t += 'Type: %s\n' % self.type
		t += 'Unknown1: %s\n' % self.unknown1
		t += 'Description Length: %s\n' % self.description_len
		t += 'Unknown2: %s\n' % self.unknown2
		t += 'Field Count: %s\n' % self.field_cnt
		t += 'Description: %s\n' % self.description
		for i in range(self.field_cnt):
			t += 'Field %d: %s\n' % (i, self.fields[i])
		return t


def main():
	with open('/home/webdev/Desktop/winhellotest/winhello_test/cryptokeys/5b64a9701545a917d7778d1d19fd2d78_50962b6d-f3c6-40f5-b6ab-81e1beb9be3a', 'rb') as f:
		data = f.read()
	
	key = CryptoAPIKeyFile.from_bytes(data)
	print(str(key))

if __name__ == '__main__':
	main()
