from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization



# Generate a private key for use in the exchange.
#private_key = X25519PrivateKey.generate()
private_key_bytes = bytes.fromhex('802485554bee3688f8e33567b304080857cabd313e6412fdf610d56037359148')
private_key = X25519PrivateKey.from_private_bytes(
    data = private_key_bytes
)
private_bytes = private_key.private_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PrivateFormat.Raw,
    encryption_algorithm=serialization.NoEncryption()
)

#chave = ", 0x".join("{:02x}".format(ord(c)) for c in private_bytes)
chave = private_bytes.hex()
print("Chave Privada a")
print(chave)

public_key = private_key.public_key()
public_bytes = public_key.public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw
)

#chave = ", 0x".join("{:02x}".format(ord(c)) for c in public_bytes)
chave = public_bytes.hex()
print("Chave Publica a")
print(chave)

##Chave Bob

private_keyb = X25519PrivateKey.generate()

private_bytes = private_keyb.private_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PrivateFormat.Raw,
    encryption_algorithm=serialization.NoEncryption()
)

#chave = ", 0x".join("{:02x}".format(ord(c)) for c in private_bytes)
chave = private_bytes.hex()
print("Chave Privada b")
print(chave)

public_keyb = private_keyb.public_key()
public_bytes = public_keyb.public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw
)

#chave = ", 0x".join("{:02x}".format(ord(c)) for c in public_bytes)
chave = public_bytes.hex()
print("Chave Publica b")
print(chave)

#chave compartilhada A
shared_key = private_key.exchange(public_keyb)

#chave = ", 0x".join("{:02x}".format(ord(c)) for c in shared_key)
chave = shared_key.hex()
print("Chave compartilhada a")
print(chave)

#chave compartilhada b
shared_key = private_keyb.exchange(public_key)

#chave = ", 0x".join("{:02x}".format(ord(c)) for c in shared_key)
chave = shared_key.hex()
print("Chave compartilhada a")
print(chave)

