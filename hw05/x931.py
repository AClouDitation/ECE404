#! /usr/bin/env python3
from BitVector import *
from math import ceil
import time
import sys
import copy

AES_modulus = BitVector(bitstring='100011011')
subBytesTable = []                                                  # for encryption
#invSubBytesTable = []                                               # for decryption
MAXROUND = 14

v0=BitVector(textstring="computersecurity")

def genTables():
    # Credit to: Avi Kak (February 15, 2015)
    c = BitVector(bitstring='01100011')
    d = BitVector(bitstring='00000101')
    for i in range(0, 256):
        # For the encryption SBox
        a = BitVector(intVal = i, size=8).gf_MI(AES_modulus, 8) if i != 0 else BitVector(intVal=0)
        # For bit scrambling for the encryption SBox entries:
        a1,a2,a3,a4 = [a.deep_copy() for x in range(4)]
        a ^= (a1 >> 4) ^ (a2 >> 5) ^ (a3 >> 6) ^ (a4 >> 7) ^ c
        subBytesTable.append(int(a))
        """
        # For the decryption Sbox:
        b = BitVector(intVal = i, size=8)
        # For bit scrambling for the decryption SBox entries:
        b1,b2,b3 = [b.deep_copy() for x in range(3)]
        b = (b1 >> 2) ^ (b2 >> 5) ^ (b3 >> 7) ^ d
        check = b.gf_MI(AES_modulus, 8)
        b = check if isinstance(check, BitVector) else 0
        invSubBytesTable.append(int(b))
        """


def gee(keyword, round_constant, byte_sub_table):
    '''
    This is the g() function you see in Figure 4 of Lecture 8.
    '''
    rotated_word = keyword.deep_copy()
    rotated_word << 8
    newword = BitVector(size = 0)
    for i in range(4):
        newword += BitVector(intVal = byte_sub_table[rotated_word[8*i:8*i+8].intValue()], size = 8)
    newword[:8] ^= round_constant
    round_constant = round_constant.gf_multiply_modular(BitVector(intVal = 0x02), AES_modulus, 8)
    return newword, round_constant


def gen_key_schedule_256(key_bv):
    byte_sub_table = subBytesTable
    #  We need 60 keywords (each keyword consists of 32 bits) in the key schedule for
    #  256 bit AES. The 256-bit AES uses the first four keywords to xor the input
    #  block with.  Subsequently, each of the 14 rounds uses 4 keywords from the key
    #  schedule. We will store all 60 keywords in the following list:
    key_words = [None for i in range(60)]
    round_constant = BitVector(intVal = 0x01, size=8)
    for i in range(8):
        key_words[i] = key_bv[i*32 : i*32 + 32]
    for i in range(8,60):
        if i%8 == 0:
            kwd, round_constant = gee(key_words[i-1], round_constant, byte_sub_table)
            key_words[i] = key_words[i-8] ^ kwd
        elif (i - (i//8)*8) < 4:
            key_words[i] = key_words[i-8] ^ key_words[i-1]
        elif (i - (i//8)*8) == 4:
            key_words[i] = BitVector(size = 0)
            for j in range(4):
                key_words[i] += BitVector(intVal = 
                                 byte_sub_table[key_words[i-1][8*j:8*j+8].intValue()], size = 8)
            key_words[i] ^= key_words[i-8] 
        elif ((i - (i//8)*8) > 4) and ((i - (i//8)*8) < 8):
            key_words[i] = key_words[i-8] ^ key_words[i-1]
        else:
            sys.exit("error in key scheduling algo for i = %d" % i)
    return key_words


def get_key_from_user(key_file="key.txt"):
    # only get 256 bits key in this case
    bvFp = BitVector(filename=key_file)
    key_bv = bvFp.read_bits_from_file(256)
    return key_bv


def stateBlock_to_bitvector(state):
    # reform into bitvector
    bv = BitVector(size=0)
    for j in range(4):
        for i in range(4):
           bv += state[i][j] 
    return bv


def bitvector_to_stateBlock(bv):
    return [[bv[j*32+i*8:j*32+i*8+8] for j in range(4)] for i in range(4)]




def AESEncryptOneBlock(bv, key_file):
    
    def oneRoundAESEncrypt(bv, roundkey, lastround=False):
        
        # reform into 4*4 block
        state = bitvector_to_stateBlock(bv)

        # substitution
        for i in range(4):
            for j in range(4):
                state[i][j] = BitVector(intVal=subBytesTable[int(state[i][j])], size=8)

        # shift row
        for i in range(1,4):
            state[i] = state[i][i:] + state[i][:i]

        if not lastround:
            # mix columns
            state_cpy = copy.deepcopy(state)
            factor = [BitVector(hexstring="02"), BitVector(hexstring="03"), BitVector(hexstring="01"), BitVector(hexstring="01")]
            for j in range(4):
                for i in range(4):
                    output = BitVector(size=8)
                    for k in range(4):
                        output ^= state_cpy[k][j].gf_multiply_modular(factor[k-i],AES_modulus,8)
                    state[i][j] = output

        # reform into bitvector
        bv = stateBlock_to_bitvector(state)

        # Add round key
        bv ^= roundkey

        return bv


    key_bv = get_key_from_user(key_file)
    key_bytes = gen_key_schedule_256(key_bv)

    if bv.length() < 128:
        bv.pad_from_right(128-bv.length())

    # add round key
    key = key_bytes[0] + key_bytes[1] + key_bytes[2] + key_bytes[3]
    bv ^= key

    # encrypt 14 rounds
    for i in range(MAXROUND):
        key = key_bytes[(i+1)*4] + key_bytes[(i+1)*4+1] + key_bytes[(i+1)*4+2] + key_bytes[(i+1)*4+3]
        bv = oneRoundAESEncrypt(bv, key, i == MAXROUND-1)
    
    return bv


def x931(v0, dt, totalNum, key_file='key.txt'):

    v_last = v0
    encryptedTime = AESEncryptOneBlock(dt, key_file)
    ranNums = [None for _ in range(totalNum)]
    for i in range(totalNum):
        ranNums[i] = AESEncryptOneBlock(encryptedTime^v_last, key_file)
        v_last = AESEncryptOneBlock(ranNums[i] ^ encryptedTime, key_file)

    return [int(x) for x in ranNums]

if __name__ == "__main__":
    genTables()
    #dt = BitVector(intVal=int(10**6*time.time()))+BitVector(intVal=int(10**6*time.time()))
    dt = BitVector(textstring="0123456789abcdef")
    rans = x931(v0,dt,10)
    print(rans)
    pass