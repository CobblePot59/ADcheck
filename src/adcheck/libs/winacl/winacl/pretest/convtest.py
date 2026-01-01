import base64
from winacl.dtyp.security_descriptor import SECURITY_DESCRIPTOR, sddl_acl_control

# '/home/devel/Desktop/projects/aiosmb/filesd'
with open('/mnt/hgfs/!SHARED/ad2.txt','r') as f:
	for line in f:
		line = line.strip()
		if line == '':
			continue
		#sd_data = bytes.fromhex(line)
		sd_data = base64.b64decode(line)
		#print(sd_data)
		sd = SECURITY_DESCRIPTOR.from_bytes(sd_data)
		#print(sd)
		x = sd.to_sddl()
		#print(x)
		sd2 = SECURITY_DESCRIPTOR.from_sddl(x)

		#if sd2.to_sddl() != x:
		#	print(x)
		#	print(sd2.to_sddl())
		#	print('ERR!')
		#
		
		if sd == None:
			print('???')
		if sd.to_bytes() != sd2.to_bytes():
			if sd != sd2:
				#print('diffing!')
				diff_res = sd.diff(sd2)
				if len(diff_res) == 1 and 'Sacl_deleted' in diff_res:
					continue
				if len(diff_res) > 0:
					print(diff_res)
					input('ERR2!')

