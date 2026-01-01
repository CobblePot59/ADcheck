import enum

class SE_OBJECT_TYPE(enum.Enum):
	SE_UNKNOWN_OBJECT_TYPE = 0 #Unknown object type.
	SE_FILE_OBJECT = 1 #Indicates a file or directory.
	SE_SERVICE = 2 #Indicates a Windows service
	SE_PRINTER = 3 #Indicates a printer.
	SE_REGISTRY_KEY = 4 #Indicates a registry key.
	SE_LMSHARE = 5 #Indicates a network share.
	SE_KERNEL_OBJECT = 6 #Indicates a local 
	SE_WINDOW_OBJECT = 7 #Indicates a window station or desktop object on the local computer
	SE_DS_OBJECT = 8 #Indicates a directory service object or a property set or property of a directory service object. 
	SE_DS_OBJECT_ALL = 9 #Indicates a directory service object and all of its property sets and properties.
	SE_PROVIDER_DEFINED_OBJECT = 10 #Indicates a provider-defined object.
	SE_WMIGUID_OBJECT = 11 #Indicates a WMI object.
	SE_REGISTRY_WOW64_32KEY = 12 #Indicates an object for a registry entry under WOW64.
	SE_REGISTRY_WOW64_64KEY = 13 #Indicates an object for a registry entry under WOW64.