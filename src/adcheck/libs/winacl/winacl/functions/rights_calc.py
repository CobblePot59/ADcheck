from winacl.dtyp.ace import ACEType, AceFlags
from winacl.dtyp.sid import SID
from typing import List

SYNCHRONIZE = 0x00100000
WRITE_OWNER = 0x00080000
WRITE_DACL = 0x00040000
READ_CONTROL = 0x00020000
DELETE = 0x00010000
MAXIMUM_ALLOWED = 0x02000000

def group_lookup(sid, sid_groups):
	for csid in sid_groups:
		if sid == csid:
			return True
	return False

def sid_in_dacl(sid, dacl):
	for ace in dacl.aces:
		if ace.Sid == sid:
			return True
	return False

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/4f1bbcbb-814a-4c70-a11e-2a5b8779a6f9
def EvaluateSidAgainstDescriptor(sd, sid:str or SID, req_access:int, sid_groups:List[str] = []):
	# sid_groups is a list of SIDs where the user's SID is member of
	dacl = sd.Dacl
	sacl = sd.Sacl
	remainging_access = req_access
	allowed_access = 0
	denied_access = 0
	max_allowed_mode = False
	granted_access = 0

	#IF RemainingAccess contains ACCESS_SYSTEM_SECURITY access bit THEN
	#     IF Token.Privileges contains SeSecurityPrivilege THEN
	#         Remove ACCESS_SYSTEM_SECURITY access bit from RemainingAccess
	#         Set GrantedAccess to GrantedAccess or ACCESS_SYSTEM_SECURITY
	#
	#         IF RemainingAccess to 0 THEN
	#             Return success
	#         Else
	#
	#     ELSE
	#         Set GrantedAccess to 0
	#         Return access_denied
	#
	#     END IF
	# END IF

	#IF RemainingAccess contains WRITE_OWNER access bit and Token.Privileges is not NULL THEN
	#     IF  Token.Privileges contains SeTakeOwnershipPrivilege THEN
	#       Remove WRITE_OWNER access bit from RemainingAccess
	#       Set GrantedAccess to GrantedAccess or WRITE_OWNER
	#    END IF
	# END IF

	#if WRITE_OWNER in remainging_access:
	#    remainging_access = WRITE_OWNER
	#    granted_access |= WRITE_OWNER

	#-- the owner of an object is always granted READ_CONTROL and WRITE_DAC.
	# CALL SidInToken(Token, SecurityDescriptor.Owner, PrincipalSelfSubst)
	# IF SidInToken returns True THEN
	#     IF DACL does not contain ACEs from object owner THEN
	#         Remove READ_CONTROL and WRITE_DAC from RemainingAccess
	#         Set GrantedAccess to GrantedAccess or READ_CONTROL or WRITE_OWNER
	#     END IF
	# END IF

	if group_lookup(sd.Owner, sid_groups) is True:
		if sid_in_dacl(sd.Owner, dacl) is False:
			remainging_access &= ~READ_CONTROL
			remainging_access &= ~WRITE_DACL
			granted_access |= WRITE_OWNER 
			granted_access |= READ_CONTROL
	
	if bool(remainging_access & MAXIMUM_ALLOWED) is True :
		max_allowed_mode = True

	for ace in dacl.aces:
		if bool(AceFlags.INHERIT_ONLY_ACE & ace.AceFlags) is True:
			continue

		if ace.AceType == ACEType.ACCESS_ALLOWED_ACE_TYPE:
			if group_lookup(ace.Sid, sid_groups) is True:
				if max_allowed_mode is True:
					allowed_access |= ace.Mask
					granted_access |= ace.Mask
				else:
					remainging_access &= ~ace.Mask
					granted_access |= (remainging_access & ace.Mask)

		elif ace.AceType == ACEType.ACCESS_DENIED_ACE_TYPE:
			#print('AM %s '% ace.Mask)
			if ace.Mask == 0:
				break
			if group_lookup(ace.Sid, sid_groups) is True:
				#print('here')
				if max_allowed_mode is True:
					denied_access |= ace.Mask
				else:
					#print(bin(remainging_access))
					#print(bin(ace.Mask))
					if (remainging_access & ace.Mask) != 0:
						granted_access = 0
						return (False, granted_access)
		
	
	if max_allowed_mode is True:
		granted_access = allowed_access & ~denied_access
		if granted_access != 0:
			return True, granted_access
		return False, granted_access
	
	granted_access = 0
	if remainging_access == 0:
		return True, granted_access
	return False, granted_access
