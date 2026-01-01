
# list services current user has write access to
# list services given user has write access to
# list sd of services
# list services
# get sd of given service

from winacl.functions.highlevel import *
from winacl.dtyp.ace import SERVICE_ACCESS_MASK

def main():
	import argparse
	parser = argparse.ArgumentParser(description='Pure Python implementation of Mimikatz --and more--')
	parser.add_argument('-v', '--verbose', action='count', default=0)

	subparsers = parser.add_subparsers(help = 'commands')
	subparsers.required = True
	subparsers.dest = 'cmdtype'

	services_group = subparsers.add_parser('srv', help='Service related commands')
	services_group_sub = services_group.add_subparsers()
	services_group_sub.required = True
	services_group_sub.dest = 'command'

	srv_ls = services_group_sub.add_parser('ls', help='listing services')
	srv_ls.add_argument('--user', help = 'user to use in eff mode. If omitted, the current user will be used. Format: "domain\\username" for domain users or "username" for local users ')
	srv_ls.add_argument('--sid', help = 'SID of the user to use in eff mode.')
	srv_ls.add_argument('--sddl', action = 'store_true', help = 'Security Descriptors will be listed in SDDL format')
	srv_ls.add_argument('--eff', action = 'store_true', help = 'Effective permissions will be printed insted of Security Descriptors')

	srv_name = services_group_sub.add_parser('name', help='operate on specific service')
	srv_name.add_argument('service_name', help = 'Name of the service to operate on (short)')
	srv_name.add_argument('--user', help = 'user to use in eff mode. If omitted, the current user will be used. Format: "domain\\username" for domain users or "username" for local users ')
	srv_name.add_argument('--sid', help = 'SID of the user to use in eff mode.')
	srv_name.add_argument('--sddl', action = 'store_true', help = 'Security Descriptors will be listed in SDDL format')
	srv_name.add_argument('--eff', action = 'store_true', help = 'Effective permissions will be printed insted of Security Descriptors')


	args = parser.parse_args()
	print(args)

	if args.cmdtype == 'srv':
		if args.command == 'ls':
			for srv_name, srv_sd in enumerate_all_service_sd():
				output = 'Name: %s ' % srv_name
				
				if isinstance(srv_sd, str):
					output += 'Error getting SD!'
					print(output)
					continue
			
				if args.sddl is True:
					output += 'SDDL: %s' % srv_sd.to_sddl()
				elif args.eff is True:
					if args.user is not None:
						max_perm = get_maximum_permissions_for_user(srv_sd, args.user)
					elif args.sid is not None:
						max_perm = GetEffectiveRightsFromAclW(srv_sd.Dacl, SID.from_string(args.sid))
					else:
						raise NotImplementedError()
					output += 'max_perm : %s value: %s' % (SERVICE_ACCESS_MASK(max_perm) , hex(max_perm))
				else:
					output += 'SD: %s' % str(srv_sd)
		
				print(output)
		elif args.command == 'name':
			srv_sd = get_service_sd(args.service_name)
			output = ''
			if args.sddl is True:
				print('SDDL: %s' % srv_sd.to_sddl())
			
			elif args.eff is True:
				if args.user is not None:
					max_perm = get_maximum_permissions_for_user(srv_sd, args.user)
				elif args.sid is not None:
					max_perm = GetEffectiveRightsFromAclW(srv_sd.Dacl, SID.from_string(args.sid))
				else:
					raise NotImplementedError()
				output += 'max_perm : %s value: %s' % (SERVICE_ACCESS_MASK(max_perm) , hex(max_perm))
			else:
				output += 'SD: %s' % str(srv_sd)
			
			print(output)
			

if __name__ == '__main__':
	main()