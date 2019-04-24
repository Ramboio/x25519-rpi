from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
import socket

localPort   = 40001

bufferSize  = 1024

# Create a datagram socket

UDPServerSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)

 

# Bind to address and ip

UDPServerSocket.bind(("", localPort))


# Generate a private key for use in the exchange.
private_key = X25519PrivateKey.generate()
#private_key_bytes = bytes.fromhex('802485554bee3688f8e33567b304080857cabd313e6412fdf610d56037359148')
#private_key = X25519PrivateKey.from_private_bytes(
#    data = private_key_bytes
#)
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
public_key_send = str.encode("PK" + chave)
print("Chave Publica a")
print(chave)

#chave compartilhada A
#shared_key = private_key.exchange(public_keyb)

#chave = ", 0x".join("{:02x}".format(ord(c)) for c in shared_key)
#chave = shared_key.hex()
#print("Chave compartilhada a")
#print(chave)
print("UDP server up and listening")



# Listen for incoming datagrams

while(True):

    bytesAddressPair = UDPServerSocket.recvfrom(bufferSize)

    message = bytesAddressPair[0]

    address = bytesAddressPair[1]

    clientMsg = "Message from Client:{}".format(message)
    clientIP  = "Client IP Address:{}".format(address)
    
    print(clientMsg)
    print(clientIP)

    if (message.decode() == "Join"):
        UDPServerSocket.sendto(public_key_send, address)
    elif (len(message.decode()) == 64):
        arduino_public_bytes = bytes.fromhex(message.decode())
        arduino_public_key = X25519PublicKey.from_public_bytes( data = arduino_public_bytes)
        shared_key = private_key.exchange(arduino_public_key)
        print(shared_key.hex())
