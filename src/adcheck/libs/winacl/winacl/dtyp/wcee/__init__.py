from winacl.dtyp.wcee.rsaprivkey import RSAPrivateKeyBlob, BCRYPTRSAKeyBlob
from winacl.dtyp.wcee.ecdhprivkey import ECDHPrivateKeyBlob

# https://learn.microsoft.com/en-us/windows/win32/seccng/key-storage-and-retrieval
# ECDH and ECDSA structures are basically the same, so we can use the same class for both

def keyblobselector(buff):
    magic = buff.read(4)
    buff.seek(-4, 1)
    magic_int = int.from_bytes(magic, byteorder='little', signed=False)
    magic_int_big = int.from_bytes(magic, byteorder='big', signed=False)
    magic_str = None
    try:
        magic_str = magic.decode('ascii')
        magic_str_rev = magic[::-1].decode('ascii')
    except:
        pass
    
    if magic == b'\x07\x02\x00\x00':
        return RSAPrivateKeyBlob
    if magic_str in magic_obj_map:
        return magic_obj_map[magic_str]
    elif magic_str_rev in magic_obj_map:
        return magic_obj_map[magic_str_rev]
    else:
        raise Exception('Unknown key type ASCII: "%s" ASCII_REV: "%s" HEX_LITTLE: %s, HEX_BIG: %s' % (magic_str, magic_str_rev, magic.hex(), magic[::-1].hex()))


# https://github.com/tpn/winsdk-10/blob/master/Include/10.0.14393.0/shared/bcrypt.h
# ints are kept so ppl can find it easier
magics = {
    'ECK1': 0x314B4345, # The key is a 256-bit ECDH public key. BCRYPT_ECDH_PUBLIC_P256_MAGIC
    'ECK2': 0x324B4345, # The key is a 256-bit ECDH private key. BCRYPT_ECDH_PRIVATE_P256_MAGIC
    'ECK3': 0x334B4345, # The key is a 384-bit ECDH public key. BCRYPT_ECDH_PUBLIC_P384_MAGIC
    'ECK4': 0x344B4345, # The key is a 384-bit ECDH private key. BCRYPT_ECDH_PRIVATE_P384_MAGIC
    'ECK5': 0x354B4345, # The key is a 521-bit ECDH public key. BCRYPT_ECDH_PUBLIC_P521_MAGIC
    'ECK6': 0x364B4345, # The key is a 521-bit ECDH private key. BCRYPT_ECDH_PRIVATE_P521_MAGIC
    'ECKP': 0x504B4345, # BCRYPT_ECDH_PUBLIC_GENERIC_MAGIC
    'ECKV': 0x564B4345, # BCRYPT_ECDH_PRIVATE_GENERIC_MAGIC
    'ECS1': 0x31534345, # The key is an ECDSA public key. BCRYPT_ECDSA_PUBLIC_P256_MAGIC
    'ECS2': 0x32534345, # The key is an ECDSA private key. BCRYPT_ECDSA_PRIVATE_P256_MAGIC
    'ECS3': 0x33534345, # The key is an ECDSA public key. BCRYPT_ECDSA_PUBLIC_P384_MAGIC
    'ECS4': 0x34534345, # The key is an ECDSA private key. BCRYPT_ECDSA_PRIVATE_P384_MAGIC
    'ECS5': 0x35534345, # The key is an ECDSA public key. BCRYPT_ECDSA_PUBLIC_P521_MAGIC
    'ECS6': 0x36534345, # The key is an ECDSA private key. BCRYPT_ECDSA_PRIVATE_P521_MAGIC
    'ECDP': 0x50444345, # BCRYPT_ECDSA_PUBLIC_GENERIC_MAGIC
    'ECDV': 0x56444345, # BCRYPT_ECDSA_PRIVATE_GENERIC_MAGIC
    'RSA1': 0x31415352, # The key is an RSA public key. BCRYPT_RSAPUBLIC_MAGIC
    'RSA2': 0x32415352, # The key is an RSA private key. BCRYPT_RSAPRIVATE_MAGIC
    'RSA3': 0x33415352, # The key is an RSA key pair with parameters. BCRYPT_RSAFULLPRIVATE_MAGIC
}

magic_obj_map = {
    'ECK1': ECDHPrivateKeyBlob, # The key is a 256-bit ECDH public key. BCRYPT_ECDH_PUBLIC_P256_MAGIC
    'ECK2': ECDHPrivateKeyBlob,
    'ECK3': ECDHPrivateKeyBlob,
    'ECK4': ECDHPrivateKeyBlob,
    'ECK5': ECDHPrivateKeyBlob,
    'ECK6': ECDHPrivateKeyBlob,
    'ECKP': ECDHPrivateKeyBlob,
    'ECKV': ECDHPrivateKeyBlob,
    'ECS1': ECDHPrivateKeyBlob,
    'ECS2': ECDHPrivateKeyBlob,
    'ECS3': ECDHPrivateKeyBlob,
    'ECS4': ECDHPrivateKeyBlob,
    'ECS5': ECDHPrivateKeyBlob,
    'ECS6': ECDHPrivateKeyBlob,
    'ECDP': ECDHPrivateKeyBlob,
    'ECDV': ECDHPrivateKeyBlob,
    'RSA1': BCRYPTRSAKeyBlob,
    'RSA2': BCRYPTRSAKeyBlob,
    'RSA3': BCRYPTRSAKeyBlob,
}