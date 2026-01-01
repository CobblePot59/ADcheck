from winacl.dtyp.acl import ACL
from winacl.dtyp.sid import SID
import enum
import io

class SE_SACL(enum.IntFlag):
	SE_DACL_AUTO_INHERIT_REQ = 0x0100 	#Indicates a required security descriptor in which the discretionary access control list (DACL) is set up to support automatic propagation of inheritable access control entries (ACEs) to existing child objects.
										#For access control lists (ACLs) that support auto inheritance, this bit is always set. Protected servers can call the ConvertToAutoInheritPrivateObjectSecurity function to convert a security descriptor and set this flag.
	SE_DACL_AUTO_INHERITED = 0x0400     #Indicates a security descriptor in which the discretionary access control list (DACL) is set up to support automatic propagation of inheritable access control entries (ACEs) to existing child objects.
										#For access control lists (ACLs) that support auto inheritance, this bit is always set. Protected servers can call the ConvertToAutoInheritPrivateObjectSecurity function to convert a security descriptor and set this flag.
	SE_DACL_DEFAULTED = 0x0008			#Indicates a security descriptor with a default DACL. For example, if the creator an object does not specify a DACL, the object receives the default DACL from the access token of the creator. This flag can affect how the system treats the DACL with respect to ACE inheritance. The system ignores this flag if the SE_DACL_PRESENT flag is not set.
										#This flag is used to determine how the final DACL on the object is to be computed and is not stored physically in the security descriptor control of the securable object.
										#To set this flag, use the SetSecurityDescriptorDacl function.
	SE_DACL_PRESENT = 0x0004			#Indicates a security descriptor that has a DACL. If this flag is not set, or if this flag is set and the DACL is NULL, the security descriptor allows full access to everyone.
										#This flag is used to hold the security information specified by a caller until the security descriptor is associated with a securable object. After the security descriptor is associated with a securable object, the SE_DACL_PRESENT flag is always set in the security descriptor control.
										#To set this flag, use the SetSecurityDescriptorDacl function.
	SE_DACL_PROTECTED = 0x1000			#Prevents the DACL of the security descriptor from being modified by inheritable ACEs. To set this flag, use the SetSecurityDescriptorControl function.
	SE_GROUP_DEFAULTED = 0x0002			#Indicates that the security identifier (SID) of the security descriptor group was provided by a default mechanism. This flag can be used by a resource manager to identify objects whose security descriptor group was set by a default mechanism. To set this flag, use the SetSecurityDescriptorGroup function.
	SE_OWNER_DEFAULTED = 0x0001			#Indicates that the SID of the owner of the security descriptor was provided by a default mechanism. This flag can be used by a resource manager to identify objects whose owner was set by a default mechanism. To set this flag, use the SetSecurityDescriptorOwner function.
	SE_RM_CONTROL_VALID = 0x4000		#Indicates that the resource manager control is valid.
	SE_SACL_AUTO_INHERIT_REQ = 0x0200	#Indicates a required security descriptor in which the system access control list (SACL) is set up to support automatic propagation of inheritable ACEs to existing child objects.
										#The system sets this bit when it performs the automatic inheritance algorithm for the object and its existing child objects. To convert a security descriptor and set this flag, protected servers can call the ConvertToAutoInheritPrivateObjectSecurity function.
	SE_SACL_AUTO_INHERITED = 0x0800		#Indicates a security descriptor in which the system access control list (SACL) is set up to support automatic propagation of inheritable ACEs to existing child objects.
										#The system sets this bit when it performs the automatic inheritance algorithm for the object and its existing child objects. To convert a security descriptor and set this flag, protected servers can call the ConvertToAutoInheritPrivateObjectSecurity function.
	SE_SACL_DEFAULTED = 0x0008			#A default mechanism, rather than the original provider of the security descriptor, provided the SACL. This flag can affect how the system treats the SACL, with respect to ACE inheritance. The system ignores this flag if the SE_SACL_PRESENT flag is not set. To set this flag, use the SetSecurityDescriptorSacl function.
	SE_SACL_PRESENT   = 0x0010			#Indicates a security descriptor that has a SACL. To set this flag, use the SetSecurityDescriptorSacl function.
	SE_SACL_PROTECTED = 0x2000			#Prevents the SACL of the security descriptor from being modified by inheritable ACEs. To set this flag, use the SetSecurityDescriptorControl function.
	SE_SELF_RELATIVE  = 0x8000			#Indicates a self-relative security descriptor. If this flag is not set, the security descriptor is in absolute format. For more information, see Absolute and Self-Relative Security Descriptors.

sddl_acl_control_flags = {
	"P"  : SE_SACL.SE_DACL_PROTECTED,
	"AR" : SE_SACL.SE_DACL_AUTO_INHERIT_REQ,
	"AI" : SE_SACL.SE_DACL_AUTO_INHERITED,
	"SR" : SE_SACL.SE_SELF_RELATIVE,
	#"NO_ACCESS_CONTROL" : 0
}
sddl_acl_control_flags_inv = {v: k for k, v in sddl_acl_control_flags.items()}

def sddl_acl_control(flags):
	t = ''
	for x in sddl_acl_control_flags_inv:
		if x == SE_SACL.SE_SELF_RELATIVE:
			continue #this flag is always set implicitly
		if x in flags:
			t += sddl_acl_control_flags_inv[x]
	return t

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7d4dac05-9cef-4563-a058-f108abecce1d
class SECURITY_DESCRIPTOR:
	def __init__(self, object_type = None):
		self.Revision:int = 1
		self.Sbz1:int = 0 #default value but SDDL doesnt store this info and in some cases this field is nonzero
		self.Control:SE_SACL = None
		self.Owner:SID = None
		self.Group:SID = None
		self.Sacl:ACL = None
		self.Dacl:ACL = None

		self.object_type = object_type #high level info, not part of the struct
	
	@staticmethod
	def from_bytes(data, object_type = None):
		return SECURITY_DESCRIPTOR.from_buffer(io.BytesIO(data), object_type)
	
	def to_bytes(self):
		buff = io.BytesIO()
		self.to_buffer(buff)
		buff.seek(0)
		return buff.read()

	def to_buffer(self, buff):
		start = buff.tell()
		buff_data = io.BytesIO()
		OffsetOwner = 0
		OffsetGroup = 0
		OffsetSacl = 0
		OffsetDacl = 0

		if self.Owner is not None:
			buff_data.write(self.Owner.to_bytes())
			OffsetOwner = start + 20
		
		if self.Group is not None:
			OffsetGroup = start + 20 + buff_data.tell()
			buff_data.write(self.Group.to_bytes())
			
		
		if self.Sacl is not None:
			OffsetSacl = start + 20 + buff_data.tell()
			buff_data.write(self.Sacl.to_bytes())
			
		
		if self.Dacl is not None:
			OffsetDacl = start + 20 + buff_data.tell()
			buff_data.write(self.Dacl.to_bytes())
			

		
		buff.write(self.Revision.to_bytes(1, 'little', signed = False))
		buff.write(self.Sbz1.to_bytes(1, 'little', signed = False))
		buff.write(self.Control.to_bytes(2, 'little', signed = False))
		buff.write(OffsetOwner.to_bytes(4, 'little', signed = False))
		buff.write(OffsetGroup.to_bytes(4, 'little', signed = False))
		buff.write(OffsetSacl.to_bytes(4, 'little', signed = False))
		buff.write(OffsetDacl.to_bytes(4, 'little', signed = False))
		buff_data.seek(0)
		buff.write(buff_data.read())


	@staticmethod
	def from_buffer(buff, object_type = None):
		sd = SECURITY_DESCRIPTOR(object_type)
		sd.Revision = int.from_bytes(buff.read(1), 'little', signed = False)
		sd.Sbz1 =  int.from_bytes(buff.read(1), 'little', signed = False)
		sd.Control = SE_SACL(int.from_bytes(buff.read(2), 'little', signed = False))
		OffsetOwner  = int.from_bytes(buff.read(4), 'little', signed = False)
		OffsetGroup  = int.from_bytes(buff.read(4), 'little', signed = False)
		OffsetSacl  = int.from_bytes(buff.read(4), 'little', signed = False)
		OffsetDacl  = int.from_bytes(buff.read(4), 'little', signed = False)

		if OffsetOwner > 0:
			buff.seek(OffsetOwner)
			sd.Owner = SID.from_buffer(buff)
		
		if OffsetGroup > 0:
			buff.seek(OffsetGroup)
			sd.Group = SID.from_buffer(buff)
			
		if OffsetSacl > 0:
			buff.seek(OffsetSacl)
			sd.Sacl = ACL.from_buffer(buff, object_type)
		
		if OffsetDacl > 0:
			buff.seek(OffsetDacl)
			sd.Dacl = ACL.from_buffer(buff, object_type)
			
		return sd
	
	def to_sddl(self, object_type = None):
		t=''
		if self.Owner is not None:
			t +=  'O:' + self.Owner.to_sddl()
		if self.Group is not None:
			t += 'G:' + self.Group.to_sddl()
		if self.Sacl is not None:
			t+= 'S:' + sddl_acl_control(self.Control) + self.Sacl.to_sddl(object_type)
		if self.Dacl is not None:
			t+= 'D:' + sddl_acl_control(self.Control) + self.Dacl.to_sddl(object_type)
		return t

	@staticmethod
	def from_sddl(sddl:str, object_type = None, domain_sid = None):
		sd = SECURITY_DESCRIPTOR(object_type = object_type)
		params = sddl.split(':')
		np = [params[0]]
		i = 1
		while i < len(params):
			np.append(params[i][:-1])
			np.append(params[i][-1])
			i += 1
		params = {}
		i = 0 
		while i < len(np):
			if np[i] == ')':
				break
			params[np[i]] = np[i+1]
			i += 2
		
		
		sd.Control = SE_SACL.SE_SELF_RELATIVE
		fk = None
		if 'D' in params:
			fk = 'D'
		elif 'S' in params:
			fk = 'S'
		
		if fk is not None:
			if '(' in params[fk]:
				flags, acl = params[fk].split('(', 1)
			else:
				flags = params[fk]
			if flags.upper().find('P') != -1:
				sd.Control |= SE_SACL.SE_DACL_PROTECTED
				sd.Control |= SE_SACL.SE_SACL_PROTECTED
				flags = flags.replace('P', '')
			for _ in range(len(flags)):
				x = flags[:2]
				cf = sddl_acl_control_flags[x]
				if cf == SE_SACL.SE_DACL_AUTO_INHERIT_REQ:
					sd.Control |= SE_SACL.SE_DACL_AUTO_INHERIT_REQ
					sd.Control |= SE_SACL.SE_SACL_AUTO_INHERIT_REQ
				elif cf == SE_SACL.SE_DACL_AUTO_INHERITED:
					sd.Control |= SE_SACL.SE_DACL_AUTO_INHERITED
					sd.Control |= SE_SACL.SE_SACL_AUTO_INHERITED
				else:
					sd.Control |= cf
				
				flags = flags[2:]
				if flags == '':
					break

		
		if 'O' in params:
			sd.Owner = SID.from_sddl(params['O'], domain_sid = domain_sid)
		if 'G' in params:
			sd.Group = SID.from_sddl(params['G'], domain_sid = domain_sid)
		if 'D' in params:
			sd.Control |= SE_SACL.SE_DACL_PRESENT
			acl = params['D']
			m = acl.find('(')
			if m != -1:
				sd.Dacl = ACL.from_sddl(acl[m:], object_type=object_type, domain_sid = domain_sid)
		if 'S' in params:
			sd.Control |= SE_SACL.SE_SACL_PRESENT
			acl = params['S']
			m = acl.find('(')
			if m != -1:
				sd.Sacl = ACL.from_sddl(acl[m:], object_type=object_type, domain_sid = domain_sid)
			
		return sd
			
	def __str__(self):
		t = '=== SECURITY_DESCRIPTOR ==\r\n'
		t+= 'Revision : %s\r\n' % self.Revision
		t+= 'Control : %s\r\n' % self.Control
		t+= 'Owner : %s\r\n' % self.Owner
		t+= 'Group : %s\r\n' % self.Group
		t+= 'Sacl : %s\r\n' % self.Sacl
		t+= 'Dacl : %s\r\n' % self.Dacl
		return t

	def __eq__(self, sd):
		if not isinstance(sd, SECURITY_DESCRIPTOR):
			return False
		if sd.Revision != self.Revision:
			return False
		if sd.Sbz1 != self.Sbz1:
			return False
		if self.Control != self.Control:
			return False
		if self.Owner != self.Owner:
			return False
		if self.Group != self.Group:
			return False
		if sd.Sacl is not None and self.Sacl is None:
			return False
		if sd.Dacl is not None and self.Dacl is None:
			return False
		if sd.Sacl is None and self.Sacl is not None:
			return False
		if sd.Dacl is None and self.Dacl is not None:
			return False
		
		if self.Sacl is not None:
			if self.Sacl != sd.Sacl:
				return False
		if self.Dacl is not None:
			if self.Dacl != sd.Dacl:
				return False

		return True
	
	def diff(self, sd):
		diff_res = {}
		if sd.Revision != self.Revision:
			diff_res['revision'] = [self.Revision, sd.Revision]
		if sd.Sbz1 != self.Sbz1:
			diff_res['Sbz1'] = [self.Sbz1, sd.Sbz1]
		if self.Control != self.Control:
			diff_res['Control'] = [self.Control, sd.Control]
		if self.Owner != self.Owner:
			diff_res['Owner'] = [self.Owner, sd.Owner]
		if self.Group != self.Group:
			diff_res['Group'] = [self.Group, sd.Group]
		if sd.Sacl is not None and self.Sacl is None:
			diff_res['Sacl_added'] = None
		if sd.Dacl is not None and self.Dacl is None:
			diff_res['Dacl_added'] = None
		if sd.Sacl is None and self.Sacl is not None:
			diff_res['Sacl_deleted'] = None
		if sd.Dacl is None and self.Dacl is not None:
			diff_res['Dacl_deleted'] = None
		
		if self.Sacl is not None and sd.Sacl is not None:
			sacl_diff = self.Sacl.diff(sd.Sacl)
			if len(sacl_diff) > 0:
				diff_res['Sacl'] = sacl_diff
		if self.Dacl is not None:
			dacl_diff = self.Dacl.diff(sd.Dacl)
			if len(dacl_diff) > 0:
				diff_res['Dacl'] = dacl_diff

		return diff_res
	
if __name__ == '__main__':
	ds = 'S-1-5-21-3448413973-1765323015-1500960949'
	x = 'O:BAG:DUD:AI(A;OICI;FA;;;DA)(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)(A;OICIID;0x1200a9;;;BU)(A;CIID;0x100004;;;BU)(A;CIID;0x100002;;;BU)(A;OICIIOID;FA;;;CO)(A;OICIID;FA;;;DA)'
	a = SECURITY_DESCRIPTOR.from_sddl(x, domain_sid = ds)
	print(x)
	print(a.to_sddl())
	print(x == a.to_sddl())

	print(a)
