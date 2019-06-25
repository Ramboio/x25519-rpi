from Crypto.Cipher import AES
import datetime

# #AES128
# print("AES128")
# chave = bytes.fromhex("647b5efef3b62452423a4349ebc39d28")
# aes128 = AES.new(chave, AES.MODE_ECB)

# time_start = datetime.datetime.now()
# aes128.encrypt("1234567890123456")
# time_end = datetime.datetime.now()
# print("Decrypt: " + str(time_end.microsecond - time_start.microsecond))
# time_start = datetime.datetime.now()
# aes128.decrypt(bytes.fromhex("cda3baaf66eeb38fdf642ac9df885fcd"))
# time_end = datetime.datetime.now()
# print("Decrypt: " + str(time_end.microsecond - time_start.microsecond))


# #AES192
# print("AES192")
# chave = bytes.fromhex("647b5efef3b62452423a4349ebc39d2854fa12f1ac3feb93")
# aes192 = AES.new(chave, AES.MODE_ECB)

# time_start = datetime.datetime.now()
# aes192.encrypt("1234567890123456")
# time_end = datetime.datetime.now()
# print("Encrypt: " + str(time_end.microsecond - time_start.microsecond))
# time_start = datetime.datetime.now()
# aes192.decrypt(bytes.fromhex("cda3baaf66eeb38fdf642ac9df885fcd"))
# time_end = datetime.datetime.now()
# print("Decrypt: " + str(time_end.microsecond - time_start.microsecond))



#AES256
print("AES256")
chave = bytes.fromhex("647b5efef3b62452423a4349ebc39d2854fa12f1ac3feb93da7ee4096f43dc02")
aes256 = AES.new(chave, AES.MODE_ECB)

time_start = datetime.datetime.now()
aes256.encrypt("1234567890123456")
time_end = datetime.datetime.now()
print("Encrypt: " + str(time_end.microsecond - time_start.microsecond))
time_start = datetime.datetime.now()
aes256.decrypt(bytes.fromhex("cda3baaf66eeb38fdf642ac9df885fcd"))
time_end = datetime.datetime.now()
print("Decrypt: " + str(time_end.microsecond - time_start.microsecond))




##RSA
#time openssl genrsa -des3 -out private.pem 2048
#gedit arquivo.txt
#time openssl enc -aes-256-cbc -salt -in arquivo.txt -out arquivo.txt.enc -pass file:private.pem
#time openssl rsautl -decrypt -inkey private.pem -in arquivo.txt.enc -out teste.txt
#time openssl dgst -sha256 arquivo.txt
#time openssl dgst -sha512 arquivo.txt
#time openssl dgst -sha3-256 arquivo.txt
#time openssl dgst -sha3-512 arquivo.txt