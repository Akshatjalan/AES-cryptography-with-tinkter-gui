import binascii
import re


class AES(object):

    def __init__(self, mode, input_type):
        self.mode = mode
        self.input = input_type
        self.Nb = 0
        self.Nk = 0
        self.Nr = 0

        # Rijndael S-box
        self.sbox = [
            0x36,	 0xc7,	 0x1e,	 0x06,	 0xf2,	 0x26,	 0x2e,	 0x86,	 0x84,	 0xc6,	 0x3e,	 0x43,	 0xea,	 0x92,	 0x6e,	 0x59,
 0xbf,	 0xec,	 0x9e,	 0xf8,	 0xe2,	 0xd0,	 0x5c,	 0x35,	 0x58,	 0xd4,	 0x64,	 0x66,	 0x1a,	 0x7a,	 0x51,	 0xbe,
 0x22,	 0xb1,	 0x8b,	 0x61,	 0xb2,	 0x5a,	 0x81,	 0x6d,	 0x8c,	 0xd9,	 0x45,	 0x97,	 0xd3,	 0xf9,	 0x67,	 0x56,
 0xd1,	 0x71,	 0x47,	 0xe0,	 0x1f,	 0x13,	 0xce,	 0x15,	 0xf0,	 0xc8,	 0x10,	 0xba,	 0x85,	 0x34,	 0xa2,	 0x0b,
 0x3c,	 0xbd,	 0x25,	 0xa6,	 0x38,	 0x23,	 0x9d,	 0xa8,	 0x74,	 0xae,	 0x00,	 0x03,	 0x3d,	 0x2d,	 0x4b,	 0x7b,
 0x6b,	 0x18,	 0x11,	 0xf4,	 0x8f,	 0x1b,	 0xe6,	 0x20,	 0x14,	 0xb7,	 0x01,	 0x69,	 0x4e,	 0xd8,	 0xd6,	 0xb5,
 0xc5,	 0x5f,	 0x95,	 0xb4,	 0x5e,	 0x9b,	 0x5d,	 0x04,	 0x72,	 0x60,	 0xa4,	 0x9a,	 0x4a,	 0x4c,	 0x77,	 0x12,
 0x55,	 0xe9,	 0x99,	 0x65,	 0xf5,	 0x50,	 0xa0,	 0x73,	 0x3f,	 0xc2,	 0xe7,	 0x0c,	 0x7c,	 0xc9,	 0x78,	 0x41,
 0x33,	 0xe4,	 0xf3,	 0xcc,	 0x6f,	 0x3b,	 0x7e,	 0x63,	 0x31,	 0x89,	 0xbc,	 0xfa,	 0xe3,	 0xdf,	 0x79,	 0x68,
 0x17,	 0x80,	 0xaa,	 0x1c,	 0xfd,	 0x07,	 0xac,	 0xa1,	 0xb3,	 0x6a,	 0xbb,	 0xcd,	 0x88,	 0x94,	 0x90,	 0xeb,
 0x98,	 0x39,	 0x21,	 0xee,	 0x75,	 0x48,	 0x57,	 0xa9,	 0x3a,	 0xb8,	 0x70,	 0xdd,	 0x8e,	 0xcb,	 0xed,	 0x32,
 0xf7,	 0xd5,	 0xf6,	 0x16,	 0x7d,	 0x76,	 0x49,	 0x7f,	 0x0a,	 0x83,	 0x91,	 0xfb,	 0x96,	 0x52,	 0x27,	 0x0f,
 0xcf,	 0xab,	 0x82,	 0x4f,	 0x37,	 0xb9,	 0xa7,	 0xa3,	 0x02,	 0xdc,	 0x30,	 0x2a,	 0x53,	 0x4d,	 0xff,	 0xa5,
 0xc4,	 0x0d,	 0x1d,	 0x29,	 0xaf,	 0x42,	 0xb0,	 0xc0,	 0x08,	 0x40,	 0xdb,	 0xde,	 0x46,	 0xda,	 0x24,	 0xef,
 0x87,	 0x28,	 0x09,	 0xca,	 0xe1,	 0x8a,	 0x9f,	 0x6c,	 0xd7,	 0xf1,	 0x05,	 0xb6,	 0xad,	 0xfc,	 0x44,	 0xfe,
 0x62,	 0x93,	 0x9c,	 0x2c,	 0x0e,	 0xe8,	 0x2b,	 0xe5,	 0xc3,	 0x5b,	 0x19,	 0x54,	 0xc1,	 0x2f,	 0x8d,	 0xd2
]

        # Rijndael Inverted S-box
        self.rsbox = [
            0x4a,	 0x5a,	 0xc8,	 0x4b,	 0x67,	 0xea,	 0x03,	 0x95,	 0xd8,	 0xe2,	 0xb8,	 0x3f,	 0x7b,	 0xd1,	 0xf4,	 0xbf,
 0x3a,	 0x52,	 0x6f,	 0x35,	 0x58,	 0x37,	 0xb3,	 0x90,	 0x51,	 0xfa,	 0x1c,	 0x55,	 0x93,	 0xd2,	 0x02,	 0x34,
 0x57,	 0xa2,	 0x20,	 0x45,	 0xde,	 0x42,	 0x05,	 0xbe,	 0xe1,	 0xd3,	 0xcb,	 0xf6,	 0xf3,	 0x4d,	 0x06,	 0xfd,
 0xca,	 0x88,	 0xaf,	 0x80,	 0x3d,	 0x17,	 0x00,	 0xc4,	 0x44,	 0xa1,	 0xa8,	 0x85,	 0x40,	 0x4c,	 0x0a,	 0x78,
 0xd9,	 0x7f,	 0xd5,	 0x0b,	 0xee,	 0x2a,	 0xdc,	 0x32,	 0xa5,	 0xb6,	 0x6c,	 0x4e,	 0x6d,	 0xcd,	 0x5c,	 0xc3,
 0x75,	 0x1e,	 0xbd,	 0xcc,	 0xfb,	 0x70,	 0x2f,	 0xa6,	 0x18,	 0x0f,	 0x25,	 0xf9,	 0x16,	 0x66,	 0x64,	 0x61,
 0x69,	 0x23,	 0xf0,	 0x87,	 0x1a,	 0x73,	 0x1b,	 0x2e,	 0x8f,	 0x5b,	 0x99,	 0x50,	 0xe7,	 0x27,	 0x0e,	 0x84,
 0xaa,	 0x31,	 0x68,	 0x77,	 0x48,	 0xa4,	 0xb5,	 0x6e,	 0x7e,	 0x8e,	 0x1d,	 0x4f,	 0x7c,	 0xb4,	 0x86,	 0xb7,
 0x91,	 0x26,	 0xc2,	 0xb9,	 0x08,	 0x3c,	 0x07,	 0xe0,	 0x9c,	 0x89,	 0xe5,	 0x22,	 0x28,	 0xfe,	 0xac,	 0x54,
 0x9e,	 0xba,	 0x0d,	 0xf1,	 0x9d,	 0x62,	 0xbc,	 0x2b,	 0xa0,	 0x72,	 0x6b,	 0x65,	 0xf2,	 0x46,	 0x12,	 0xe6,
 0x76,	 0x97,	 0x3e,	 0xc7,	 0x6a,	 0xcf,	 0x43,	 0xc6,	 0x47,	 0xa7,	 0x92,	 0xc1,	 0x96,	 0xec,	 0x49,	 0xd4,
 0xd6,	 0x21,	 0x24,	 0x98,	 0x63,	 0x5f,	 0xeb,	 0x59,	 0xa9,	 0xc5,	 0x3b,	 0x9a,	 0x8a,	 0x41,	 0x1f,	 0x10,
 0xd7,	 0xfc,	 0x79,	 0xf8,	 0xd0,	 0x60,	 0x09,	 0x01,	 0x39,	 0x7d,	 0xe3,	 0xad,	 0x83,	 0x9b,	 0x36,	 0xc0,
 0x15,	 0x30,	 0xff,	 0x2c,	 0x19,	 0xb1,	 0x5e,	 0xe8,	 0x5d,	 0x29,	 0xdd,	 0xda,	 0xc9,	 0xab,	 0xdb,	 0x8d,
 0x33,	 0xe4,	 0x14,	 0x8c,	 0x81,	 0xf7,	 0x56,	 0x7a,	 0xf5,	 0x71,	 0x0c,	 0x9f,	 0x11,	 0xae,	 0xa3,	 0xdf,
 0x38,	 0xe9,	 0x04,	 0x82,	 0x53,	 0x74,	 0xb2,	 0xb0,	 0x13,	 0x2d,	 0x8b,	 0xbb,	 0xed,	 0x94,	 0xef,	 0xce
]

        self.rcon = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]

    @staticmethod
    def pad(data, block=16):

        if block < 2 or block > 255:
            raise ValueError("Block Size must be < 2 and > 255")

        if len(data) == block: return data
        pads = block - (len(data) % block)
        return data + binascii.unhexlify(('%02x' % int(pads)).encode()) + b'\x00' * (pads - 1)

    @staticmethod
    def unpad(data):

        p = None
        for x in data[::-1]:
            if x == 0:
                continue
            elif x != 0:
                p = x; break
        data = data[::-1]
        data = data[p:]
        return data[::-1]

    @staticmethod
    def unblock(data, size=16):

        return [data[x:x + size] for x in range(0, len(data), size)]

    @staticmethod
    def RotWord(word):

        return int(word[2:] + word[0:2], 16)

    @staticmethod
    def StateMatrix(state):

        new_state = []
        split = re.findall('.' * 2, state)
        for x in range(4):
            new_state.append(split[0:4][x]); new_state.append(split[4:8][x])
            new_state.append(split[8:12][x]); new_state.append(split[12:16][x])
        return new_state

    @staticmethod
    def RevertStateMatrix(state):

        columns = [state[x:x + 4] for x in range(0, 16, 4)]
        return ''.join(''.join([columns[0][x], columns[1][x], columns[2][x], columns[3][x]]) for x in range(4))

    @staticmethod
    def galois(a, b):

        p = 0
        for counter in range(8):
            if b & 1: p ^= a
            hi_bit_set = a & 0x80
            a <<= 1
            # keep a 8 bit
            a &= 0xFF
            if hi_bit_set:
                a ^= 0x1b
            b >>= 1
        return p

    @staticmethod
    def AddRoundKey(state, key):
 
        return ['%02x' % (int(state[x], 16) ^ int(key[x], 16)) for x in range(16)]

    def ShiftRows(self, state, isInv):

        offset = 0
        if isInv: state = re.findall('.' * 2, self.RevertStateMatrix(state))
        for x in range(0, 16, 4):
            state[x:x + 4] = state[x:x + 4][offset:] + state[x:x + 4][:offset]
            if not isInv:
                offset += 1
            elif isInv:
                offset -= 1
        if isInv: return self.StateMatrix(''.join(state))
        return state

    def SubWord(self, byte):

        return ((self.sbox[(byte >> 24 & 0xff)] << 24) + (self.sbox[(byte >> 16 & 0xff)] << 16) +
                (self.sbox[(byte >> 8 & 0xff)] << 8) + self.sbox[byte & 0xff])

    def SubBytes(self, state, isInv):

        if not isInv: return ['%02x' % self.sbox[int(state[x], 16)] for x in range(16)]
        elif isInv: return ['%02x' % self.rsbox[int(state[x], 16)] for x in range(16)]

    def MixColumns(self, state, isInv):

        if isInv: fixed = [14, 9, 13, 11]; state = self.StateMatrix(''.join(state))
        else: fixed = [2, 1, 1, 3]
        columns = [state[x:x + 4] for x in range(0, 16, 4)]
        row = [0, 3, 2, 1]
        col = 0
        output = []
        for _ in range(4):
            for _ in range(4):
                output.append('%02x' % (
                    self.galois(int(columns[row[0]][col], 16), fixed[0]) ^
                    self.galois(int(columns[row[1]][col], 16), fixed[1]) ^
                    self.galois(int(columns[row[2]][col], 16), fixed[2]) ^
                    self.galois(int(columns[row[3]][col], 16), fixed[3])))
                row = [row[-1]] + row[:-1]
            col += 1
        return output

    def Cipher(self, expandedKey, data):

        state = self.AddRoundKey(self.StateMatrix(data), expandedKey[0])
        for r in range(self.Nr - 1):
            state = self.SubBytes(state, False)
            state = self.ShiftRows(state, False)
            state = self.StateMatrix(''.join(self.MixColumns(state, False)))
            state = self.AddRoundKey(state, expandedKey[r + 1])

        state = self.SubBytes(state, False)
        state = self.ShiftRows(state, False)
        state = self.AddRoundKey(state, expandedKey[self.Nr])
        return self.RevertStateMatrix(state)

    def InvCipher(self, expandedKey, data):
        state = self.AddRoundKey(re.findall('.' * 2, data), expandedKey[self.Nr])

        for r in range(self.Nr - 1):
            state = self.ShiftRows(state, True)
            state = self.SubBytes(state, True)
            state = self.AddRoundKey(state, expandedKey[-(r + 2)])
            state = self.MixColumns(state, True)

        state = self.ShiftRows(state, True)
        state = self.SubBytes(state, True)
        state = self.AddRoundKey(state, expandedKey[0])
        return ''.join(state)

    def ExpandKey(self, key):

        w = ['%08x' % int(x, 16) for x in re.findall('.' * 8, key)]

        i = self.Nk
        while i < self.Nb * (self.Nr + 1):
            temp = w[i - 1]
            if i % self.Nk == 0:
                temp = '%08x' % (self.SubWord(self.RotWord(temp)) ^ (self.rcon[i // self.Nk] << 24))
            elif self.Nk > 6 and i % self.Nk == 4:
                temp = '%08x' % self.SubWord(int(temp, 16))
            w.append('%08x' % (int(w[i - self.Nk], 16) ^ int(temp, 16)))
            i += 1

        return [self.StateMatrix(''.join(w[x:x + 4])) for x in range(0, len(w), self.Nk)]

    def key_handler(self, key, isInv):

        if len(key) == 32:
            self.Nb = 4; self.Nk = 4; self.Nr = 10
        elif len(key) == 48:
            self.Nb = 4; self.Nk = 6; self.Nr = 12
        elif len(key) == 64:
            self.Nb = 4; self.Nk = 8; self.Nr = 14
        else: raise AssertionError("%s Is an invalid Key!\nUse a 128-bit, 192-bit or 256-bit key!" % key)

        if not isInv: return self.ExpandKey(key)
        # Return the inverse expanded key
        if isInv: return [re.findall('.' * 2, self.RevertStateMatrix(x)) for x in self.ExpandKey(key)]

    def aes_main(self, data, key, isInv):

        expanded_key = self.key_handler(key, isInv)
        if self.mode == 'ecb': return self.ecb(data, expanded_key, isInv)
        else: raise AttributeError("\n\n\tSupported AES Modes of Operation are ecb")

    def encryption(self, data, key):

        return self.aes_main(data, key, False)

    def decryption(self, data, key):

        return self.aes_main(data, key, True)

    
    def ecb(self, data, expanded_key, isInv):

        if self.input == 'hex':
            if not isInv: return self.Cipher(expanded_key, data)
            elif isInv: return self.InvCipher(expanded_key, data)
        elif self.input == 'text':
            if not isInv: return self.Cipher(expanded_key, ''.join('%02x' % x for x in self.pad(data.encode())))
            elif isInv: return str(self.unpad(binascii.unhexlify(self.InvCipher(expanded_key, data).encode())))[2:-1]
        elif self.input == 'data':
            if not isInv: return b''.join(binascii.unhexlify(self.Cipher(
                expanded_key, str(binascii.hexlify(x))[2:-1]).encode()) for x in self.unblock(data))
            if isInv: return b''.join(binascii.unhexlify(self.InvCipher(
                expanded_key, str(binascii.hexlify(x))[2:-1]).encode()) for x in self.unblock(data))
        else: raise AttributeError("\n\n\tSupported Input types are ['hex', 'text', 'data']")


