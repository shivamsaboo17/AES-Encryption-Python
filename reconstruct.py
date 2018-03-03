import base64
from Crypto import Random
from Crypto.Cipher import AES
import hashlib
import pickle
import getpass

"""
This is a demo for reconstructing original data from the anonymized text.
The method uses AES encryption to first encrypt all the identified sensitive data 
which may lead to re-identification of the author.
The encryption requires user to enter a password which in turn becomes the cipher
key for encryption.
Now for reconstructing data to original format this key is needed without which
AES itself cannot decrypt the data.
The code demonstrates a simple example:
Suppose original text has data : John Cambridge
We apply some anonymization technique to get output as : Ron Stanford
To encrypt these mappings we take a cipher key in form of password from the user
To restore and fetch the original data this key is again needed.
Hence we can successfully implement restoration feature without letting privacy hindered.   
"""


class AESCipher(object):

    def __init__(self, key, filename):
        self.bs = 32
        self.key = hashlib.sha256(key.encode()).digest()
        self.filename = filename

    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw))

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    def dump_file(self, data):
        with open(self.filename, 'wb') as dict:
            pickle.dump(data, dict)


class Restore(object):

    def __init__(self, filename, key):
        self.bs = 32
        self.key = key
        self.filename = filename

    def load_file(self):
        with open(self.filename, 'rb') as dict:
            encoded_dict = pickle.loads(dict.read())
            return encoded_dict

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf8')

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s) - 1:])]


def encrypt():
    print("Enter a password to encrypt your personal data")
    pass_key = getpass.getpass('Password: ')
    Encrypter = AESCipher(pass_key, "encoded_dictionary")
    encoded_data = {"Ron": [Encrypter.encrypt("John"), 1], "Stanford": [Encrypter.encrypt("Cambridge"), 2]}
    Encrypter.dump_file(encoded_data)
    print("Your personal data has been securely encrypted!")


def decrypt():
    print("To reconstruct your original file enter your password")
    pass_key = getpass.getpass()
    pass_key = hashlib.sha256(pass_key.encode()).digest()
    Restorer = Restore("encoded_dictionary", pass_key)
    encrypted_data = Restorer.load_file()
    correct = True
    for entity in encrypted_data:
        decrypted_data = Restorer.decrypt(encrypted_data[entity][0])
        if decrypted_data != '':
            encrypted_data[entity][0] = decrypted_data
        else:
            print("Original file cannot be constructed as the password is incorrect!")
            print("Try again")
            correct = False
            break
    if correct:
        print(encrypted_data)


if __name__ == '__main__':
    encrypt()
    decrypt()