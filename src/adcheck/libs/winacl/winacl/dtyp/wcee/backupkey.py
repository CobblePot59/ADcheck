import io

class PREFERRED_BACKUP_KEY:
	def __init__(self):
		self.version = None
		self.keylength = None
		self.certificatelength = None
		self.keydata = None
		self.certdata = None

	@staticmethod
	def from_bytes(data):
		return PREFERRED_BACKUP_KEY.from_buffer(io.BytesIO(data))

	@staticmethod
	def from_buffer(buff):
		pbk = PREFERRED_BACKUP_KEY()
		pbk.version = int.from_bytes(buff.read(4), byteorder='little', signed = False)
		pbk.keylength = int.from_bytes(buff.read(4), byteorder='little', signed = False)
		pbk.certificatelength = int.from_bytes(buff.read(4), byteorder='little', signed = False)
		pbk.keydata = buff.read(pbk.keylength)
		pbk.certdata = buff.read(pbk.certificatelength)
		return pbk