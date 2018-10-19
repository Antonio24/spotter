#! /usr/bin/python3
import base64

class csInjectorTemplate:
    def csiPayload(self, payload_file):
        f = open(payload_file, "rb")
        content = f.read()
        encoded = base64.b64encode(content)
        encoded = encoded.decode("utf-8")
        return encoded

