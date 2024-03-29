#!/bin/env python3.10

import base64
import hashlib
from argparse import ArgumentParser
from Cryptodome.Protocol.KDF import PBKDF2
from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import AES
from io import BytesIO
from os import fdopen
from tempfile import mkstemp

BLOCK_SIZE = 16


class filehandler():
    """ class to contain all filesystem related methods

    Handles encryption and decryption for config files
    set default passphrase to hashed mac address if not given
    """
    def __init__(self, passphrase=None, interface='eth0') -> None:
        """ initialization

        :param passphrase: passpharse for file encryption/ decryption. If not set use mac address
        :param interface: interface for MACAddress passphrase generation (default: eth0)
        """
        if not passphrase:
            with open('/sys/class/net/' + interface + '/address') as f:
                passphrase = f.readline()
        passphrase.strip()
        hlib = hashlib.md5()
        hlib.update(passphrase.encode('utf-8'))
        self.password = base64.urlsafe_b64encode(hlib.hexdigest().encode('utf-8'))
        self.salt = get_random_bytes(BLOCK_SIZE)
        self.__passphrase__ = PBKDF2(self.password, self.salt, dkLen=32)

    def encode(self, plaintext) -> bytes:
        """ encode/ encrypt given plaintext

        :param plaintext: plaintext to be encoded with pre-set passphrase
        """
        cipher = AES.new(self.__passphrase__, AES.MODE_EAX)
        buffer = BytesIO()
        buffer.write(self.salt)
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        [buffer.write(x) for x in (cipher.nonce, tag, ciphertext)]
        return buffer.getvalue()

    def decode(self, cipherbuffertext) -> bytes:
        """ decode/ decrypt given ciphertext

        :param ciphertext: ciphertext to be decoded with pre-set passphrase
        """
        if isinstance(cipherbuffertext, str):
            buffer = BytesIO(cipherbuffertext.encode('utf-8'))
        else:
            buffer = BytesIO(cipherbuffertext)
        salt = buffer.read(BLOCK_SIZE)
        key = PBKDF2(self.password, salt, dkLen=32)
        cipher = AES.new(key, AES.MODE_EAX, nonce=buffer.read(BLOCK_SIZE))
        tag = buffer.read(BLOCK_SIZE)
        return cipher.decrypt_and_verify(buffer.read(), tag).decode('utf-8')

    def checkpassword(self, ciphertext) -> bool:
        """ check if currently set password is correct

        :param ciphertext: test cipher to decrypt with given password
        """
        try:
            self.decode(ciphertext)
        except ValueError:
            return False
        return True

    def decrypttofile(self, ciphertext):
        """ decrypt given ciphertext and return path do decrypted file

        :param ciphertext: text to be decrypted

        creates new file with decrypted content
        """
        fd, authpath = mkstemp()
        with fdopen(fd, 'w') as fp:
            fp.write(self.decode(ciphertext))
        return authpath

    def decryptfile(self, inputfile) -> str:
        """ decrypt given file and return path do decrypted file

        :param inputfile: path for file to be decrypted

        creates new file with decrypted content
        """
        with open(inputfile, 'r') as f:
            sourcetext = f.read()
            fd, authpath = mkstemp()
            with fdopen(fd, 'w') as fp:
                fp.write(self.decode(sourcetext).decode('utf-8'))
            return authpath

    def encryptfile(self, inputfile) -> str:
        """ encrypt given file and return path do encrypted file

        :param inputfile: path for file to be encrypted

        creates new file with encrypted content
        """
        with open(inputfile, 'r') as f:
            sourcetext = f.read()
            fd, authpath = mkstemp()
            with fdopen(fd, 'w') as fp:
                fp.write(self.encode(sourcetext).decode('utf-8'))
            return authpath


def crypt(sourcefile, destinationfile, isencrypt, passphrase=None, interface=None) -> None:
    """ en/decrypt given sourcefile to destinationfile

    :param sourcefile: file to be en/decrypted
    :param destinationfile: file for plain/ciphertext to be stored
    :param isencrypt: set to True for encryption, to False for decryption
    :param passphrase: passphrase for encryption/decryption (if not given interface MAC is used)
    :param interface: interface for passphrase generation
    """
    if not sourcefile or not destinationfile:
        print('source or destinationfile not specified')
        return -1

    fenc = filehandler(passphrase, interface)
    with open(sourcefile, 'r') as f:
        sourcetext = f.read()
    desitnationtext = ''
    if isencrypt:
        desitnationtext = fenc.encode(sourcetext)
    else:
        desitnationtext = fenc.decode(sourcetext)

    with open(destinationfile, 'w') as f:
        f.write(desitnationtext)


def encrypt(sourcefile, destinationfile, passphrase=None, interface=None) -> None:
    """ encrypt given sourcefile to destinationfile

    :param sourcefile: file to be encrypted
    :param destinationfile: file for ciphertext to be stored
    :param passphrase: passphrase for encryption/decryption (if not given interface MAC is used)
    :param interface: interface for passphrase generation
    """
    crypt(sourcefile=sourcefile, destinationfile=destinationfile, isencrypt=True, passphrase=passphrase, interface=interface)


def decrypt(sourcefile, destinationfile, passphrase=None, interface=None) -> None:
    """ decrypt given sourcefile to destinationfile

    :param sourcefile: file to be decrypted
    :param destinationfile: file for plaintext to be stored
    :param passphrase: passphrase for encryption/decryption (if not given interface MAC is used)
    :param interface: interface for passphrase generation
    """
    crypt(sourcefile=sourcefile, destinationfile=destinationfile, isencrypt=False, passphrase=passphrase, interface=interface)


def main() -> None:
    """ main method

    initialize logging
    parse given commandline arguments
    start en/decryption process
    """
    parser = ArgumentParser()
    parser.add_argument('--sourcefile', help='source file to be encrypted')
    parser.add_argument('--destinationfile',
                        help='file to store encrypted data')
    parser.add_argument('--encrypt', help='encrypt given file', default=None, action='store_true')
    parser.add_argument('--decrypt', help='decrypt given file', default=None, action='store_true')
    parser.add_argument(
        '--passphrase', help='decrypt/encrypt with given passphrase')
    parser.add_argument(
        '--interface', help='interface to read MAC as passphrase if not given(default: eth0)', default='eth0')
    args = parser.parse_args()

    if not args.encrypt and not args.decrypt:
        print('neither --encrypt nor --decrypt specified...')
        return -1
    elif args.encrypt and args.decrypt:
        print('both --encrypt and --decrypt specified...')
        return -1

    if args.encrypt:
        encrypt(sourcefile=args.sourcefile, destinationfile=args.destinationfile,
                passphrase=args.passphrase, interface=args.interface)
    else:
        decrypt(sourcefile=args.sourcefile, destinationfile=args.destinationfile,
                passphrase=args.passphrase, interface=args.interface)


if __name__ == "__main__":
    main()
