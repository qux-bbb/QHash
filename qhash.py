# coding:utf8
# python3

import os
import sys
import binascii
from hashlib import md5, sha1, sha256, sha512

BLOCK_SIZE = 1024*1024


def calc_hash(file_path, enable_hash_types):
    """calc many hash

    Args:
        file_path ([str]): file path
    """
    the_file = open(file_path, 'rb')

    if enable_hash_types.get('crc32', False):
        crc32_value = 0
        while True:
            data = the_file.read(BLOCK_SIZE)
            if data:
                crc32_value = binascii.crc32(data, crc32_value)
            else:
                break
        crc32_hex_str = hex(crc32_value)[2:]
        print('{}\t: {}'.format('crc32', crc32_hex_str))

    if enable_hash_types.get('md5', False):
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

    if enable_hash_types.get('sha1', False):
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

    if enable_hash_types.get('sha256', False):
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

    if enable_hash_types.get('sha512', False):
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


def print_usage():
        print('\
usage: {0} <file_path> [<hash_type>,]\n\
    hash_type can be "crc32", "md5", "sha1", "sha256", "sha512", "all"\n\
example:\n\
    {0} hello.exe\n\
    {0} hello.exe md5\n\
    {0} hello.exe md5,sha1\n\
    {0} hello.exe all'.format(sys.argv[0]))

def main():
    if len(sys.argv) not in [2, 3]:
        print_usage()
        return

    the_path = sys.argv[1]
    if not os.path.isfile(the_path):
        print('[!] {} is not a valid file path'.format(the_path))
        return

    if len(sys.argv) == 2:
        enable_hash_types = {
            'crc32': False,
            'md5': True,
            'sha1': True,
            'sha256': False,
            'sha512': False,
        }
    else:
        if sys.argv[2] == 'all':
            enable_hash_types = {
                'crc32': True,
                'md5': True,
                'sha1': True,
                'sha256': True,
                'sha512': True,
            }
        else:
            hash_types = sys.argv[2].split(',')
            enable_hash_types = {}
            for hash_type in hash_types:
                if hash_type in ['crc32', 'md5', 'sha1', 'sha256', 'sha512']:
                    enable_hash_types[hash_type] = True
                else:
                    print('[!] error hash_type: {}'.format(hash_type))
                    return

    calc_hash(sys.argv[1], enable_hash_types)


if __name__ == '__main__':
    main()
    input('\nenter any key to exit')
