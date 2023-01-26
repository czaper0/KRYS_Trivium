from Crypto.Random.random import randint
import argparse
class Trivium:
    ''' Class representing Trivium cipher '''
    
    def __init__(self):
        ''' Constructor '''
        self.state = [0]*288
        self.key = [randint(0, 1) for _ in range(80)]
        self.iv = [randint(0, 1) for _ in range(80)]

    def setup(self, key, iv):
        ''' Key and IV setup '''        
        t = [0, 0, 0]
        
        # Loading key and IV into registers
        self.state[:93] = [*key, *[0]*13]
        self.state[93:177] = [*iv, *[0]*4]
        self.state[177:288] = [*[0]*108, 1, 1, 1]
        
        # 4 full Trivium cycles
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

    def get_keystream(self, N : int, key=None, iv=None):
        ''' Generate key stream '''
        t = [0, 0, 0]
        key_stream = []
        
        # Checking if encrypting or decrypting
        if key is None: key = self.key
        if iv is None: iv = self.iv
        
        self.setup(key, iv)

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
        
        return key_stream, key, iv

    def encrypt(self, plaintext : str) -> str:
        ''' Plaintext encryption '''
        plaintext_hex = plaintext.encode().hex()
        N = len(plaintext_hex)*4

        plaintext_bin = bin(int(plaintext_hex, 16))[2:].zfill(N)
        key_stream, key, iv = self.get_keystream(N)
        
        print(f'Plaintext (hex):  0x{plaintext_hex}')
        print(f'Key 80-bit:       {"".join([str(k) for k in key])}')
        print(f'IV 80-bit:        {"".join([str(i) for i in iv])}')
        print(f'Key stream:       {"".join([str(s) for s in key_stream])}')

        cipher = [a^int(b) for a, b in zip(key_stream, plaintext_bin)]
        cipher = ''.join([str(c) for c in cipher])
        
        return hex(int(cipher, 2))

    def decrypt(self, ciphertext, key, iv) -> str:
        ''' Ciphertext decryption '''
        self.key = key
        self.iv = iv
        ciphertext_hex = ciphertext
        print('Ciphertext (hex):', ciphertext_hex,'type:',type(ciphertext_hex))
        N = len(ciphertext_hex)*4

        plaintext_bin = bin(int(ciphertext_hex, 16))[2:].zfill(N)
        key_stream, key, iv = self.get_keystream(N,key,iv)
        print(f'Key stream: {"".join([str(s) for s in key_stream])}')

        plaintext = [a^int(b) for a, b in zip(key_stream, plaintext_bin)]
        plaintext = ''.join([str(p) for p in plaintext])

        return hex(int(plaintext, 2))

if __name__ == "__main__":
    trivium = Trivium()
    argParser = argparse.ArgumentParser()
    argParser.add_argument("-e", "--encrypt", help="message to encrypt (text)")
    argParser.add_argument("-d", "--decrypt", help="message to decrypt (hex)")
    argParser.add_argument("-k", "--key", help="key to decrypt (bin)")
    argParser.add_argument("-i", "--iv", help="iv to decrypt (bin)")
    args = argParser.parse_args()
    if args.encrypt:
        print('Ciphertext (hex):', trivium.encrypt(args.encrypt))
    elif args.decrypt:
        if args.key and args.iv:
            trivium.key = [int(k) for k in args.key]
            trivium.iv = [int(i) for i in args.iv]
            plaintext = trivium.decrypt(args.decrypt, trivium.key, trivium.iv)
            print('Plaintext:', plaintext,'->', bytes.fromhex(plaintext[2:]).decode(errors='ignore'))
        else:
            print('Key and IV are required to decrypt, use -h for help')
    else:
        print('No arguments provided, use -h for help')
    
    # plaintext = "Hello" 
    # print('Plaintext:', plaintext)
    # ciphertext = trivium.encrypt(plaintext)
    # print('Ciphertext:', ciphertext)
