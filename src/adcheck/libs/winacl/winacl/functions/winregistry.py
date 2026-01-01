import winreg


def get_nameserver_candidates():
	"""
	Returns a list of IP addresses which potentially an active DNS server used by the current machine.
	Please be aware that it's not at all precise!
	"""
	keynames = ['NameServer', 'DhcpNameServer']
	def get_ips(iface, keyname):
		try:
			result = {}
			res, _ = winreg.QueryValueEx(iface,keyname)
			if len(res) > 0:
				if res.find(',') != -1:
					for x in res.split(','):
						result[x] = 0
				else:
					result[res] = 0
		except Exception as e:
			pass #print(e)
		finally:
			return list(result.keys())

	ips = {}
	hklm = winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE)
	key = 'System\CurrentControlSet\Services\Tcpip\Parameters\Interfaces'
	aKey = winreg.OpenKey(hklm, key)
	for i in range(1024):
		try:
			asubkey_name=winreg.EnumKey(aKey,i)
			iface = winreg.OpenKey(aKey, asubkey_name)
			for keyname in keynames:
				for res in get_ips(iface, keyname):
					ips[res] = 0
		
		except OSError as e:
			if e.args[0] == 22:
				break
			elif e.args[0] == 259:
				continue
			else:
				raise
		except Exception as e:
			print(e)
	
	return list(ips.keys())

if __name__ == '__main__':
	x = get_nameserver_candidates()
	print(x)