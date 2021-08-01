# coding:utf8
# python3

import os
import sys
import binascii
from hashlib import md5, sha1, sha256, sha512

BLOCK_SIZE = 1024*1024


def calc_hash(file_path):
    """calc many hash

    Args:
        file_path ([str]): file path
    """
    result = {}
    the_file = open(file_path, 'rb')

    crc32_value = 0
    while True:
        data = the_file.read(BLOCK_SIZE)
        if data:
            crc32_value = binascii.crc32(data, crc32_value)
        else:
            break
    crc32_hex_str = hex(crc32_value)[2:]
    print('{}\t: {}'.format('crc32', crc32_hex_str))

    the_file.seek(0, 0)
    md5_m = md5()
    while True:
        data = the_file.read(BLOCK_SIZE)
        if data:
            md5_m.update(data)
        else:
            break
    md5_hex_str = md5_m.hexdigest()
    print('{}\t: {}'.format('md5', md5_hex_str))

    the_file.seek(0, 0)
    sha1_m = sha1()
    while True:
        data = the_file.read(BLOCK_SIZE)
        if data:
            sha1_m.update(data)
        else:
            break
    sha1_hex_str = sha1_m.hexdigest()
    print('{}\t: {}'.format('sha1', sha1_hex_str))

    the_file.seek(0, 0)
    sha256_m = sha256()
    while True:
        data = the_file.read(BLOCK_SIZE)
        if data:
            sha256_m.update(data)
        else:
            break
    sha256_hex_str = sha256_m.hexdigest()
    print('{}\t: {}'.format('sha256', sha256_hex_str))

    the_file.seek(0, 0)
    sha512_m = sha512()
    while True:
        data = the_file.read(BLOCK_SIZE)
        if data:
            sha512_m.update(data)
        else:
            break
    sha512_hex_str = sha512_m.hexdigest()
    print('{}\t: {}'.format('sha512', sha512_hex_str))

    the_file.close()


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print('usage: {} <file_path>'.format(sys.argv[0]))
    else:
        the_path = sys.argv[1]
        if os.path.isfile(the_path):
            calc_hash(sys.argv[1])
        else:
            print('[!] {} is not a valid file path'.format(the_path))
    input('\nenter any key to exit')