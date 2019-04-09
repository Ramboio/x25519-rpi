from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization

#Message received via UDP from Arduino, the Public Key
msg = '802485554bee3688f8e33567b304080857cabd313e6412fdf610d56037359148'

# Generate a private key for use in the exchange.
private_key = X25519PrivateKey.generate()
#private_key_bytes = bytes.fromhex('802485554bee3688f8e33567b304080857cabd313e6412fdf610d56037359148')
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
arduino_public_key_bytes = bytes.fromhex(msg)
arduino_public_key = X25519PublicKey.from_public_bytes(arduino_public_key_bytes)


#chave compartilhada A
shared_key = private_key.exchange(arduino_public_key)

#chave = ", 0x".join("{:02x}".format(ord(c)) for c in shared_key)
chave = shared_key.hex()
print("Chave compartilhada a")
print(chave)
