import glob
import math
import os

from pip._vendor.pytoml.writer import long

from ConstantsDesProvider import *
from DESPrinciplesAndDecipheringException import *


#
# Des Implementation for cipher or decipher a message.
#


class Des:

    def __init__(self):
        self.constants_des_provider = ConstantsDesProvider()
        self.constants_by_key = self.constants_des_provider.build_constants_by_key()

        # substitution matrices
        self.substitution_matrices = [self.constants_by_key['S1'], self.constants_by_key['S2'],
                                      self.constants_by_key['S3'], self.constants_by_key['S4'],
                                      self.constants_by_key['S5'], self.constants_by_key['S6'],
                                      self.constants_by_key['S7'], self.constants_by_key['S8']]

        self.key = [0] * 17
        self.shift_keys = [0, 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 6, 7]

    def cipher(self, message, key):
        binary_message = self.__text_to_binary(message)
        return self.__apply_treatment(Constantes.CIPHER, key, binary_message)

    def decipher(self, message, key):
        binary_decrypted_message = self.__apply_treatment(Constantes.DECIPHER, key, message)
        return self.binary_to_text(binary_decrypted_message)

    def __apply_treatment(self, cipher, key, message):
        self.__build_parameterized_key(self.__hash_generated(key))

        plain_message = self.__build_plain_message(message)

        binary_cipher_text_blocks, binary_plaintext_blocks = self.__init_plaintext_and_cipher_text(plain_message)

        # Encrypt or decrypt the blocks
        self.__encrypt_or_decrypt_blocks(cipher, binary_cipher_text_blocks, binary_plaintext_blocks)

        # Build the cipher_text binary text from the blocks
        return self.__build_cipher_text(binary_cipher_text_blocks)

    def __init_plaintext_and_cipher_text(self, plain_message):
        binary_plaintext_blocks = [" "] * math.ceil(len(plain_message) / 64)
        offset = 0
        for i in range(len(binary_plaintext_blocks)):
            binary_plaintext_blocks[i] = plain_message[offset:offset + 64]
            offset += 64
        binary_cipher_text_blocks = [" "] * math.ceil(len(plain_message) / 64)
        return binary_cipher_text_blocks, binary_plaintext_blocks

    def __build_plain_message(self, message):
        plain_message = message
        remainder_message_plain = len(plain_message) % 64
        if 0 != remainder_message_plain:
            for i in range(64 - remainder_message_plain):
                plain_message = "0" + plain_message
        return plain_message

    def __build_cipher_text(self, binary_cipher_text_blocks):
        binary_cipher_text = ""
        for i in range(len(binary_cipher_text_blocks)):
            binary_cipher_text += binary_cipher_text_blocks[i]
        return binary_cipher_text

    def __encrypt_or_decrypt_blocks(self, cipher, binary_cipher_text_blocks, bin_plaintext_blocks):
        for i in range(len(binary_cipher_text_blocks)):
            if Constantes.CIPHER == cipher:
                binary_cipher_text_blocks[i] = self.__encrypt_block(bin_plaintext_blocks[i])
            elif Constantes.DECIPHER == cipher:
                binary_cipher_text_blocks[i] = self.__decipher_block(bin_plaintext_blocks[i])

    def __encrypt_block(self, message):
        return self.__apply_treatment_block(Constantes.CIPHER, message)

    def __decipher_block(self, message):
        return self.__apply_treatment_block(Constantes.DECIPHER, message)

    def __apply_treatment_block(self, cipher, message):
        if 64 != len(message):
            raise DESPrinciplesAndDecipheringException("the block does not have a valid size {0}", len(message))

        message_of_permutations = self.__apply_permutation(-1, message, 'PI')

        left_message = message_of_permutations[0:32]
        right_message = message_of_permutations[32:]

        if Constantes.CIPHER == cipher:
            for i in range(16):
                left_message, right_message = self.__permute_messages(cipher, i, left_message, right_message)
        elif Constantes.DECIPHER == cipher:
            for i in range(16, 0, -1):
                left_message, right_message = self.__permute_messages(cipher, i, left_message, right_message)

        return self.__apply_permutation(-1, right_message + left_message, 'PI_I')

    def __permute_messages(self, cipher, i, left_message, right_message):
        if Constantes.CIPHER == cipher:
            current_key = self.__long_to_binary(self.key[i + 1])
        else:
            current_key = self.__long_to_binary(self.key[i])

        while len(current_key) < 48:
            current_key = "0" + current_key

        binary_right_message = self.__get_right_message(right_message, current_key)

        merged_message = self.__long_to_binary(long(left_message, 2) ^ long(binary_right_message, 2))

        while len(merged_message) < 32:
            merged_message = "0" + merged_message
        left_message = right_message
        right_message = merged_message

        return left_message, right_message

    def __build_parameterized_key(self, key):
        # Permit to convert long key to a binary
        binary_key = self.__long_to_binary(key)

        while len(binary_key) < 64:
            binary_key = "0" + binary_key

        pc1_binary_key = self.__apply_permutation(-1, binary_key, 'CP_1')

        left_integer = int(pc1_binary_key[0:28], 2)
        right_integer = int(pc1_binary_key[28:], 2)

        # Build the keys
        for i in range(1, len(self.key)):
            left_integer = self.__rotate_left(left_integer, self.shift_keys[i])
            right_integer = self.__rotate_left(right_integer, self.shift_keys[i])

            merged_halves = long(left_integer << 28) + right_integer
            merged_key = self.__long_to_binary(merged_halves)

            # if we see that leading zeros absent
            while len(merged_key) < 56:
                merged_key = "0" + merged_key

            # We apply permuted key for 56 bits
            self.__apply_permutation(i, merged_key, 'CP_2')

    def __apply_permutation(self, i, merged_key, constant):
        block = ""
        for j in range(len(self.constants_by_key[constant])):
            block += merged_key[self.constants_by_key[constant][j] - 1]
        if 'CP_2' == constant:
            self.key[i] = long(block, 2)
        return block

    def __rotate_left(self, n, d):
        return (n << d) | (n >> (Constantes.INT_BITS - d))

    def __hash_generated(self, key):
        hash_generated = Constantes.hash
        for i in range(len(key)):
            hash_generated = (31 * hash_generated) + ord(key[i])
        return hash_generated

    def binary_to_text(self, binary):
        return ''.join(chr(int(binary[i * 8:i * 8 + 8], 2)) for i in range(len(binary) // 8))

    def __get_right_message(self, right_message, key):
        e_block = self.__apply_permutation(-1, right_message, 'E')

        binary = self.__build_binary(long(e_block, 2), long(key, 2))

        binary_array = self.__binary_to_array(binary)

        substitution_matrices = self.__init_substitution_matrices(binary_array)

        merged_substitution_matrices = self.__merge__substitution_matrices(substitution_matrices)

        return self.__apply_permutation(-1, merged_substitution_matrices, 'PERM')

    def __merge__substitution_matrices(self, substitution_matrices):
        merged = ""
        for i in range(8):
            merged += substitution_matrices[i]
        return merged

    def __binary_to_array(self, binary):
        binary_array = [" "] * 8
        for i in range(8):
            binary_array[i] = binary[0:6]
            binary = binary[6:]
        return binary_array

    def __init_substitution_matrices(self, sin):
        substitution_matrices = [" "] * 8
        for i in range(8):
            current = sin[i]
            # Get binary according to the position
            row = int(current[0] + "" + current[5], 2)
            col = int(current[1:5], 2)
            substitution_matrices[i] = self.__long_to_binary(self.substitution_matrices[row][col])

            while len(substitution_matrices[i]) < 4:
                substitution_matrices[i] = "0" + substitution_matrices[i]
        return substitution_matrices

    def __build_binary(self, message, key):
        binary = self.__long_to_binary(message ^ key)
        while len(binary) < 48:
            binary = "0" + binary
        return binary

    def __long_to_binary(self, value):
        return "{:b}".format(value)

    def __text_to_binary(self, text):
        text_in_byte = str.encode(text)
        binary_text = ""
        for i in range(len(text_in_byte)):
            value = text_in_byte[i]
            for j in range(8):
                binary_text += '0' if (value & 128) == 0 else '1'
                value <<= 1
        return binary_text

    def get_list_files(self, path):
        os.chdir(path)
        files = []
        files_by_key = dict()
        for file in glob.glob("*"):
            files.append(file)

        i = 1
        while i < 20:
            file = 'Clef_de_' + str(i) + '.txt'
            if file in files:
                files_by_key[file] = 'Chiffrement_DES_de_' + str(i) + '.txt'
            i += 1
        return files_by_key

    def get_chiffrement(self, ciphers, index):
        return ciphers['Clef_de_' + str(index) + '.txt']

    def get_key(self, index):
        return 'Clef_de_' + str(index) + '.txt'
