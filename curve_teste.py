from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
import datetime
#sudo pip3 install cryptography
print("Teste")
#dh1
time_start = datetime.datetime.now()
private_key = X25519PrivateKey.generate()
public_key = private_key.public_key()
time_end = datetime.datetime.now()
print("Decrypt: " + str(time_end.microsecond - time_start.microsecond))


#dh2

arduino_private = X25519PrivateKey.generate()
arduino_public = arduino_private.public_key()
time_start = datetime.datetime.now()
private_key.exchange(arduino_public)
time_end = datetime.datetime.now()
print("Decrypt: " + str(time_end.microsecond - time_start.microsecond))