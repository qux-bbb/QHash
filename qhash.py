# coding:utf8
# python3

import os
import sys
import binascii
from hashlib import md5, sha1, sha256, sha512


def calc_hash(file_path):
    """calc many hash

    Args:
        file_path ([str]): file path
    """
    result = {}
    the_file = open(file_path, 'rb')
    file_content = the_file.read()

    result['crc32'] = hex(binascii.crc32(file_content))[2:]
    result['md5'] = md5(file_content).hexdigest()
    result['sha1'] = sha1(file_content).hexdigest()
    result['sha256'] = sha256(file_content).hexdigest()
    result['sha512'] = sha512(file_content).hexdigest()

    the_file.close()

    print('filename: {}\n'.format(file_path))
    for k in ['crc32', 'md5', 'sha1', 'sha256', 'sha512']:
        print('{}\t: {}'.format(k, result[k]))
    

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