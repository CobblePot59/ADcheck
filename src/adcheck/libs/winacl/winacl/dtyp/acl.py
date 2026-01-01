from winacl.dtyp.ace import ACE
import io
import enum
import hashlib
from typing import List

class ACL_REVISION(enum.Enum):
	NO_DS = 0x02 # When set to 0x02, only AceTypes 0x00, 0x01, 0x02, 0x03, 0x11, 0x12, and 0x13 can be present in the ACL. An AceType of 0x11 is used for SACLs but not for DACLs. For more information about ACE types, see section 2.4.4.1.
	DS = 0x04 #When set to 0x04, AceTypes 0x05, 0x06, 0x07, 0x08, and 0x11 are allowed. ACLs of revision 0x04 are applicable only to directory service objects. An AceType of 0x11 is used for SACLs but not for DACLs.

ACL_REV_NODS_ALLOWED_TYPES = [0x00, 0x01, 0x02, 0x03, 0x11, 0x12, 0x13]
ACL_REV_DS_ALLOWED_TYPES   = [0x05, 0x06, 0x07, 0x08, 0x11]

class ACL:
	def __init__(self, sd_object_type = None):
		self.AclRevision:int = None
		self.Sbz1:int = 0
		self.AclSize:int = None
		self.AceCount:int = None
		self.Sbz2:int = 0
		
		self.aces:List[ACE] = []
		self.sd_object_type = sd_object_type
		
	@staticmethod
	def from_buffer(buff, sd_object_type = None):
		acl = ACL(sd_object_type)
		acl.AclRevision = int.from_bytes(buff.read(1), 'little', signed = False)
		acl.Sbz1 = int.from_bytes(buff.read(1), 'little', signed = False)
		acl.AclSize = int.from_bytes(buff.read(2), 'little', signed = False)
		acl.AceCount = int.from_bytes(buff.read(2), 'little', signed = False)
		acl.Sbz2 = int.from_bytes(buff.read(2), 'little', signed = False)
		for _ in range(acl.AceCount):
			acl.aces.append(ACE.from_buffer(buff, sd_object_type))
		return acl

	def to_bytes(self):
		buff = io.BytesIO()
		self.to_buffer(buff)
		buff.seek(0)
		return buff.read()

	def to_buffer(self, buff):
		data_buff = io.BytesIO()

		self.AceCount = len(self.aces)
		for ace in self.aces:
			ace.to_buffer(data_buff)

		self.AclSize = 8 + data_buff.tell()

		buff.write(self.AclRevision.to_bytes(1, 'little', signed = False))
		buff.write(self.Sbz1.to_bytes(1, 'little', signed = False))
		buff.write(self.AclSize.to_bytes(2, 'little', signed = False))
		buff.write(self.AceCount.to_bytes(2, 'little', signed = False))
		buff.write(self.Sbz2.to_bytes(2, 'little', signed = False))
		data_buff.seek(0)
		buff.write(data_buff.read())
		
	def __str__(self):
		t = '=== ACL ===\r\n'
		for ace in self.aces:
			t += '%s\r\n' % str(ace)
		return t

	def to_sddl(self, object_type = None):
		t = ''
		for ace in self.aces:
			t += ace.to_sddl(object_type)
		return t

	@staticmethod
	def from_sddl(sddl_str, object_type = None, domain_sid = None):
		acl = ACL()
		acl.AclRevision = 2
		acl.AceCount = 0
		
		for ace_sddl in sddl_str.split(')('):
			ace = ACE.from_sddl(ace_sddl, object_type = object_type, domain_sid = domain_sid)
			acl.aces.append(ace)
			acl.AceCount += 1
			if acl.AclRevision == 2:
				if ace.AceType.value in ACL_REV_DS_ALLOWED_TYPES:
					acl.AclRevision = ACL_REVISION.DS.value

		return acl

	def __eq__(self, acl):
		if not isinstance(acl, ACL):
			return False

		if self.AclRevision != acl.AclRevision:
			return False
		if self.Sbz1 != acl.Sbz1:
			return False
		if self.Sbz2 != acl.Sbz2:
			return False
		this_aces = {}
		that_aces = {}
		for ace in self.aces:
			buff = io.BytesIO()
			ace.to_buffer(buff)
			pos = buff.tell()
			buff.seek(0,0)
			this_aces[hashlib.sha1(buff.read(pos)).digest()] = 1
		
		for ace in acl.aces:
			buff = io.BytesIO()
			ace.to_buffer(buff)
			pos = buff.tell()
			buff.seek(0,0)
			that_aces[hashlib.sha1(buff.read(pos)).digest()] = 1

		for ha in this_aces:
			if ha not in that_aces:
				return False
		
		for ha in that_aces:
			if ha not in this_aces:
				return False

		for hthis, hthat in zip(this_aces.keys(), that_aces.keys()):
			if hthis != hthat:
				return False

		return True

	def diff(self, acl):
		diff_res = {}
		if self.AclRevision != acl.AclRevision:
			diff_res['revision'] = [self.AclRevision, acl.AclRevision]
		if self.Sbz1 != acl.Sbz1:
			diff_res['Sbz1'] = [self.Sbz1, acl.Sbz1]
		if self.Sbz2 != acl.Sbz2:
			diff_res['Sbz2'] = [self.Sbz2, acl.Sbz2]
		this_aces = {}
		that_aces = {}
		for ace in self.aces:
			buff = io.BytesIO()
			ace.to_buffer(buff)
			pos = buff.tell()
			buff.seek(0,0)
			data = buff.read(pos)
			this_aces[hashlib.sha1(data).digest()] = data
		
		for ace in acl.aces:
			buff = io.BytesIO()
			ace.to_buffer(buff)
			pos = buff.tell()
			buff.seek(0,0)
			data = buff.read(pos)
			that_aces[hashlib.sha1(data).digest()] = data

		for ha in this_aces:
			if ha not in that_aces:
				diff_res['deleted'] = this_aces[ha]
		
		for ha in that_aces:
			if ha not in this_aces:
				diff_res['added'] = that_aces[ha]

		#TODO: diff the ordering changes of ACEs
		#for hthis, hthat in zip(this_aces.keys(), that_aces.keys()):
		#	if hthis != hthat:
		#		return False

		return diff_res