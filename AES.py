##############################################################################
#                                FILE INFORMATION                            #
##############################################################################
# File Name   : your_file_name.py
# Author      : Ben Miller
# Class       : Your Class/Subject
# Date        : 2024-02-05
# Description : 
#   This Python file serves the purpose of provide a detailed description
# Useful Sites:
# https://www.cryptool.org/en/cto/aes-step-by-step
# https://www.rapidtables.com/convert/number/ascii-to-hex.html
##############################################################################
import sys
from BitVector import *

class AES ():
    def __init__ ( self , keyfile:str ) -> None :
        self.key_file = keyfile
        self.sub_bytes_table = []
        self.inv_sub_bytes_table = []
        self.key_schedule = []
        self.AES_modulus = BitVector(bitstring='100011011')

    # Credit: Lecture 8 Code
    def gee(self, keyword, round_constant, byte_sub_table):
        '''
        This is the g() function you see in Figure 4 of Lecture 8.
        '''
        rotated_word = keyword.deep_copy()
        rotated_word << 8
        newword = BitVector(size = 0)
        for i in range(4):
            newword += BitVector(intVal = byte_sub_table[rotated_word[8*i:8*i+8].intValue()], size = 8)
        newword[:8] ^= round_constant
        round_constant = round_constant.gf_multiply_modular(BitVector(intVal = 0x02), self.AES_modulus, 8)
        return newword, round_constant

    # Credit: Lecture 8 Code
    def gen_key_schedule_256(self, key_bv):
        byte_sub_table = self.sub_bytes_table
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
                kwd, round_constant = self.gee(key_words[i-1], round_constant, byte_sub_table)
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

    def create_state_array(self, vector):
        # empty array
        statearray = [[0 for x in range(4)] for x in range(4)]

        # filling array with vectors
        for i in range(4):
            for j in range(4):
                statearray[j][i] = vector[32*i + 8*j:32*i + 8*(j+1)]

        # returning result
        return statearray
    
    def flaten_state_array(self, state_array):
        # for storing result
        bit_out = BitVector(size=0)
        for i in range(4):
            for j in range(4):
                bits = state_array[j][i]
                bit_out.pad_from_right(8)
                bit_out |= bits
        return bit_out
    
    # Credit: Lecture 8 Code
    def gen_tables(self):
        # For Storing Results
        subBytesTable = []                                                  # for encryption
        invSubBytesTable = []    

        #generating Tables
        c = BitVector(bitstring='01100011')
        d = BitVector(bitstring='00000101')
        for i in range(0, 256):
            # For the encryption SBox
            a = BitVector(intVal = i, size=8).gf_MI(self.AES_modulus, 8) if i != 0 else BitVector(intVal=0)
            # For bit scrambling for the encryption SBox entries:
            a1,a2,a3,a4 = [a.deep_copy() for x in range(4)]
            a ^= (a1 >> 4) ^ (a2 >> 5) ^ (a3 >> 6) ^ (a4 >> 7) ^ c
            subBytesTable.append(int(a))
            # For the decryption Sbox:
            b = BitVector(intVal = i, size=8)
            # For bit scrambling for the decryption SBox entries:
            b1,b2,b3 = [b.deep_copy() for x in range(3)]
            b = (b1 >> 2) ^ (b2 >> 5) ^ (b3 >> 7) ^ d
            check = b.gf_MI(self.AES_modulus, 8)
            b = check if isinstance(check, BitVector) else 0
            invSubBytesTable.append(int(b))  
        
        #storing results
        self.sub_bytes_table = subBytesTable
        self.inv_sub_bytes_table = invSubBytesTable

    def extract_keys(self):
        #retreiving text from file
        key_text = ""
        with open (self.key_file, 'r') as file:
            key_text = file.read()
        
        #generating bitvector from text
        key_bv = BitVector(textstring = key_text)
        return key_bv

    def get_words(self,idx):
        # for storing result
        word_bv = BitVector(size = 0)

        # getting 4 words
        for i in range((4 * idx), (4 * idx) + 4):
            word_bv.pad_from_right(32)
            word_bv ^= self.key_schedule[i]

        return word_bv

    def sub_bytes(self, state_array):
        # going item by item and substituting
        for i in range(4):
            for j in range(4):
                state_array[j][i] = BitVector(intVal = self.sub_bytes_table[state_array[j][i].int_val()])

    def shift_rows(self, state_array): 
        # uses fancy python subsitution and concatination
        for i in range(1, 4):
            state_array[i] = state_array[i][i:] + state_array[i][:i]
        return state_array

    def mix_collumns(self, state_array):
        # defining 2 and 3 bitvectors
        two_bv = BitVector(intVal = 2)
        three_bv = BitVector(intVal = 3)
        # creating a temp state array
        temp_array =  [[BitVector(size = 0) for _ in range(4)] for _ in range(4)]
        for col in range(4):  # Iterate over each column
            for row in range(4):  # Iterate over each row in the column
                # Get the bytes in the column, considering it's a circular list
                byte0 = state_array[row][col]
                byte1 = state_array[(row + 1) % 4][col]
                byte2 = state_array[(row + 2) % 4][col]
                byte3 = state_array[(row + 3) % 4][col]
                # Apply the encryption formula
                new_byte = (byte0.gf_multiply_modular(two_bv, self.AES_modulus, 8)) ^ ((byte1.gf_multiply_modular(three_bv, self.AES_modulus, 8)) ^ byte2 ^ byte3)
                # Update the state with the new byte value
                temp_array[row][col] = new_byte
        return temp_array

    def encrypt ( self , plaintext:str , ciphertext:str ) -> None :
        # reading key from file
        key_bv = self.extract_keys()

        # generating words and key scheldule
        self.gen_tables()
        self.key_schedule = self.gen_key_schedule_256(key_bv)

        #creating spot to store encrpyted text
        ciphertext_bv = BitVector(size = 0)

        #extracting text
        plain_text = ""
        with open(plaintext, 'r') as file:
            plain_text = file.read()

        #creating bitvector of whole file
        text_bits = BitVector(textstring = plain_text)

        # going chunk by chunk
        while text_bits.length() > 0:
            #trying to extract full chunk
            if text_bits.length() > 128:
                text_chunk = text_bits[:128]
                #updating by removing used bits
                text_bits = text_bits[128:]
            #if not full section
            else:
                #padding from right
                text_chunk = text_bits
                text_chunk.pad_from_right(128 - text_chunk.length())
                #updating by removing used bits
                text_bits = BitVector(size = 0)

            # xoring with words 0-3
            # creating state array
            state_array = self.create_state_array(text_chunk)

            # getting words for round
            words = self.get_words(0)

            # xoring words with textchunk
            text_chunk = self.flaten_state_array(state_array)
            text_chunk ^= words
            state_array = self.create_state_array(text_chunk)

            for round in range(1, 15):
                # performing subytes
                self.sub_bytes(state_array)
                text_chunk = self.flaten_state_array(state_array)

                # performing shift rows
                state_array = self.shift_rows(state_array)
                text_chunk = self.flaten_state_array(state_array)

                # ignoring mix columns if last round
                if (round != 14):
                    # performing mix collumns
                    state_array = self.mix_collumns(state_array)
                    text_chunk = self.flaten_state_array(state_array)

                # getting words for round
                words = self.get_words(round)

                # xoring words with textchunk
                text_chunk ^= words
                state_array = self.create_state_array(text_chunk)

            # appending to cipher text
            ciphertext_bv.pad_from_right(128)
            ciphertext_bv ^= text_chunk

        # writing output file
        with open (ciphertext, "w") as file:
            file.write(ciphertext_bv.get_bitvector_in_hex())

    def inv_shift_rows(self, state_array):
        for i in range(4):
            state_array[i] = state_array[i][-i:] + state_array[i][:-i]
        return state_array
    
    def inv_sub_bytes(self, state_array):
        # going item by item and substituting
        for i in range(4):
            for j in range(4):
                state_array[j][i] = BitVector(intVal = self.inv_sub_bytes_table[state_array[j][i].int_val()])

    def inv_mix_columns(self, state_array):
        # creating matrix
        mult_mat = [[BitVector(hexstring="0E"), BitVector(hexstring="0B"), BitVector(hexstring="0D"), BitVector(hexstring="09")],
        [BitVector(hexstring="09"), BitVector(hexstring="0E"), BitVector(hexstring="0B"), BitVector(hexstring="0D")],
        [BitVector(hexstring="0D"), BitVector(hexstring="09"), BitVector(hexstring="0E"), BitVector(hexstring="0B")],
        [BitVector(hexstring="0B"), BitVector(hexstring="0D"), BitVector(hexstring="09"), BitVector(hexstring="0E")]]

        # doing matrix multiplication
        result = [[BitVector(intVal=0, size=8) for _ in range(4)] for _ in range(4)]
        for i in range(4):
            for j in range(4):
                for k in range(4):
                    result[i][j] ^= state_array[k][j].gf_multiply_modular(mult_mat[i][k], self.AES_modulus, 8)
        return result

    def decrypt ( self , ciphertext:str , decrypted:str ) -> None :
        # reading key from file
        key_bv = self.extract_keys()

        # generating words and key scheldule
        self.gen_tables()
        self.key_schedule = self.gen_key_schedule_256(key_bv)

        #creating spot to store encrpyted text
        plain_text_bv = BitVector(size = 0)

        #extracting text
        plain_text = ""
        with open(ciphertext, 'r') as file:
            plain_text = file.read()

        #creating bitvector of whole file
        text_bits = BitVector(hexstring = plain_text)

        # going chunk by chunk
        while text_bits.length() > 0:
            #trying to extract full chunk
            if text_bits.length() > 128:
                text_chunk = text_bits[:128]
                #updating by removing used bits
                text_bits = text_bits[128:]
            #if not full section
            else:
                #padding from right
                text_chunk = text_bits
                text_chunk.pad_from_right(128 - text_chunk.length())
                #updating by removing used bits
                text_bits = BitVector(size = 0)

            # creating state array
            state_array = self.create_state_array(text_chunk)

            # getting last words
            words = self.get_words(14)

            # xoring words with textchunk
            text_chunk = self.flaten_state_array(state_array)
            text_chunk ^= words
            state_array = self.create_state_array(text_chunk)

            for round in range(13, -1, -1):
                # inverse shift rows
                state_array = self.inv_shift_rows(state_array)
                text_chunk = self.flaten_state_array(state_array)

                # inverse sub bytes
                self.inv_sub_bytes(state_array)
                text_chunk = self.flaten_state_array(state_array)

                # Adding round key
                words = self.get_words(round)

                # xoring words with textchunk
                text_chunk ^= words
                state_array = self.create_state_array(text_chunk)

                # inverse mix collumns
                if (round != 0):
                    state_array = self.inv_mix_columns(state_array)
                    text_chunk = self.flaten_state_array(state_array)

            # repeating a bunch of times
            # appending to cipher text
            plain_text_bv.pad_from_right(128)
            plain_text_bv ^= text_chunk

        # writing output file
        with open (decrypted, "w") as file:
            file.write(plain_text_bv.get_bitvector_in_ascii())


if __name__ == "__main__":
    # creating cipher object
    cipher = AES(keyfile = sys.argv[3])
    #determining user choice
    if sys.argv[1] == "-e":
       cipher.encrypt( plaintext = sys.argv[2], ciphertext = sys.argv[4])
    elif sys.argv[1] == "-d":
        cipher.decrypt( ciphertext = sys.argv[2], decrypted = sys.argv[4])
    else:
        sys.exit(" Incorrect Command - Line Syntax ")
