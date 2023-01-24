import os
from Crypto.Util.strxor import strxor
from Crypto.Util.number import long_to_bytes, bytes_to_long
import random
class Trivium:
    def __init__(self):
        self.state = [0]*288

    def setup(self):
        key  = self.key
        iv  = self.iv
        t = [0]*3
        self.state[:92] = [*key, *[0]*12]
        self.state[93:176] = [*iv, *[0]*3]
        self.state[177:287] = [*[0]*107, 1, 1, 1]
        
        for _ in range(4*288):
            t[0] = self.state[65] ^ self.state[90] & self.state[91] ^ self.state[92] ^ self.state[170]
            t[1] = self.state[161] ^ self.state[174] & self.state[175] ^ self.state[176] ^ self.state[263]
            t[2] = self.state[242] ^ self.state[285] & self.state[286] ^ self.state[287] ^ self.state[68]

            self.state[0:92] = [t[2], *self.state[0:91]]
            self.state[93:176] = [t[0], *self.state[93:175]]
            self.state[177:287] = [t[1], *self.state[177:286]]
    
    def generate_key(self):
        self.key = [random.randint(0,1) for _ in range(80)]
        self.iv = [random.randint(0,1) for _ in range(80)]

    def algorithm(self,plaintext):
        N = len(plaintext[2:])*4
        z, t = [], [0]*3
        
        self.setup()

        for _ in range(N):
            t[0] = self.state[65] ^ self.state[92]
            t[1] = self.state[161] ^ self.state[176]
            t[2] = self.state[242] ^ self.state[287]
            
            z.append(t[0] ^ t[1] ^ t[2])
            
            t[0] = t[0] ^ self.state[90] & self.state[91] ^ self.state[170]
            t[1] = t[1] ^ self.state[174] & self.state[175] ^ self.state[263]
            t[2] = t[2] ^ self.state[285] & self.state[286] ^ self.state[68]
            
            self.state[0:92] = [t[2], *self.state[0:91]]
            self.state[93:176] = [t[0], *self.state[93:175]]
            self.state[177:287] = [t[1], *self.state[177:286]]
            
        plaintext = bin(int(plaintext[2:],16))[2:].zfill(N)
        print('z:',hex(int(''.join([str(x) for x in z]),2)))
        cipher = [a^int(b) for a,b in zip(z, plaintext)]
        cipher = ''.join([str(x) for x in cipher]).encode()
        cipher = hex(int(cipher,2))
        return cipher, self.key, self.iv 

    def encrypt(self, plaintext):
        self.generate_key()
        return self.algorithm(plaintext)

    def decrypt(self, ciphertext):
        return self.algorithm(ciphertext)
        
if __name__ == "__main__":
    triv = Trivium()
    plaintext = "Hello"
    plaintext = hex(int(plaintext.encode().hex(),16))
    print('plaintext:',plaintext)
    n, key, iv = triv.encrypt(plaintext)
    print('ciphertext',n)
    print('key:',hex(int(''.join([str(x) for x in key]),2)))
    print('iv:',hex(int(''.join([str(x) for x in iv]),2)))
    n, key, iv = triv.decrypt(n)
    print('decrypted:',n)