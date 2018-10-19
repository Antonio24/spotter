#! /usr/bin/python
from random import choice,randint
import string

class Obfuscator:
    def obfVar(self):
        newVar = "".join(choice(string.ascii_letters) for x in range(randint(3, 8)))
        return (newVar)

    def varobfs(self):
        varKey = self.obfVar()
        varCtr = self.obfVar()
        varBytes = self.obfVar()
        varAesManaged = self.obfVar()
        varencryptedStringWithIV = self.obfVar()
        varUnencryptedData = self.obfVar()
        varDecryptor = self.obfVar()
        varLauncher = self.obfVar()
        funcCreateAesManagedObject = self.obfVar()
        funcDecryptString = self.obfVar()
        a = self.obfVar()
        b = self.obfVar()
        c = self.obfVar()
        d = self.obfVar()
        return varKey, varCtr, varBytes, varAesManaged, varencryptedStringWithIV, varUnencryptedData, varDecryptor, varLauncher, funcCreateAesManagedObject, funcDecryptString, a, b, c, d
