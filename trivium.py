from Crypto.Random.random import randint

class Trivium:
    ''' Class description '''
    
    def __init__(self):
        self.state = [0]*288

    def setup(self):
        ''' Function description '''        
        key  = self.key
        iv  = self.iv
        t = [0, 0, 0]
        
        # Add comment
        self.state[:93] = [*key, *[0]*13]
        self.state[93:177] = [*iv, *[0]*4]
        self.state[177:288] = [*[0]*108, 1, 1, 1]
        
        for _ in range(4*288):
            t[0] = self.state[65] ^ self.state[90] & self.state[91] ^ self.state[92] ^ self.state[170]
            t[1] = self.state[161] ^ self.state[174] & self.state[175] ^ self.state[176] ^ self.state[263]
            t[2] = self.state[242] ^ self.state[285] & self.state[286] ^ self.state[287] ^ self.state[68]

            # Register 1 shift
            self.state[1:93] = self.state[0:92]
            self.state[0] = t[2]

            # Register 2 shift
            self.state[94:177] = self.state[93:176]
            self.state[93] = t[0]

            # Register 3 shift
            self.state[178:288] = self.state[177:287]
            self.state[177] = t[1]
    
    def generate_keys(self):
        ''' Add function description '''
        self.key = [randint(0,1) for _ in range(80)]
        self.iv = [randint(0,1) for _ in range(80)]

    def algorithm(self, plaintext):
        ''' Add function description'''
        N = len(plaintext[2:])*4
        t = [0, 0, 0]
        key_stream = []
        
        self.setup()

        for _ in range(N):
            t[0] = self.state[65] ^ self.state[92]
            t[1] = self.state[161] ^ self.state[176]
            t[2] = self.state[242] ^ self.state[287]
            
            key_stream.append(t[0] ^ t[1] ^ t[2])
            
            t[0] = t[0] ^ self.state[90] & self.state[91] ^ self.state[170]
            t[1] = t[1] ^ self.state[174] & self.state[175] ^ self.state[263]
            t[2] = t[2] ^ self.state[285] & self.state[286] ^ self.state[68]
            
            # Register 1 shift
            self.state[1:93] = self.state[0:92]
            self.state[0] = t[2]

            # Register 2 shift
            self.state[94:177] = self.state[93:176]
            self.state[93] = t[0]

            # Register 3 shift
            self.state[178:288] = self.state[177:287]
            self.state[177] = t[1]
        
        plaintext = bin(int(plaintext[2:], 16))[2:].zfill(N)
        cipher = [a^int(b) for a, b in zip(key_stream, plaintext)]
        cipher = ''.join([str(x) for x in cipher]).encode()
        cipher = hex(int(cipher, 2))
        
        return cipher, self.key, self.iv 

    def encrypt(self, plaintext):
        self.generate_keys()
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
    