#! /usr/bin/python3
import base64
from Crypto import Random
from Crypto.Cipher import AES


class Encrypter:
    def encrypt1(self, payload, key):
        # Encryption Routine
        BS = 16
        pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
        paddedKey =self.padKey(key)
        cipher = AESCipher(paddedKey)
        encrypted = str(cipher.encrypt(payload, pad))
        encrypted = encrypted[2:-1] #Dumb hack to remove the byte string formatting (b'XXX') that Python puts in
        return encrypted

    def padKey(self, s):  # Pad key to 32 bytes for AES256
        return (s * (32 // len(s) + 1))[:32]

class AESCipher:
    def __init__(self, key):
        self.key = key

    def encrypt(self, raw, pad):
        raw = pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw))
