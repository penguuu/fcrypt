#!/usr/bin/python3

import getpass
import os,random,sys,getopt
from hashlib import md5
from Crypto.Cipher import AES

def generate_salt():
    salt = ''.join(chr(random.randint(0,0xFF)) for i in range(8))
    return salt

def get_salt(ifile):
    salt = ifile.read(16)[8:]
    return salt

def get_key_and_IV(pwd,salt,key_len):
    iv = ''
    key = ''
    hash = ''

    while len(iv) < 16:
        hash = md5(hash+pwd+salt).digest()
        iv += hash

    while len(key) < key_len:
        hash = md5(hash+pwd+salt).digest()
        key += hash

    return (iv,key)

def encrypt(ifile,ofile,pwd,key_len=32,chunk_size=16*1024):
    salt = generate_salt()
    (iv,key) = get_key_and_IV(pwd,salt,key_len)
    cipher = AES.new(key,AES.MODE_CBC,iv)
    ofile.write('Salted__'+salt)

    while True:
        chunk = ifile.read(chunk_size)

        if len(chunk) == 0:
            ofile.write(cipher.encrypt(16*chr(16)))
            break
        elif len(chunk) % 16 != 0:
            padding = (16 - len(chunk) % 16)
            chunk += padding * chr(padding)
            ofile.write(cipher.encrypt(chunk))
            break

        ofile.write(cipher.encrypt(chunk))

def decrypt(ifile,ofile,pwd,key_len=32,chunk_size=16*1024):
    salt = get_salt(ifile)
    (iv,key) = get_key_and_IV(pwd,salt,key_len)
    cipher = AES.new(key,AES.MODE_CBC,iv)

    last_chunk = chunk = ''
    while True:
        last_chunk = chunk
        chunk = cipher.decrypt(ifile.read(chunk_size))

        if len(chunk) == 0:
            padding = ord(last_chunk[-1])
            last_chunk = last_chunk[:-padding]
            ofile.write(last_chunk)
            break
        elif len(last_chunk) > 0:
            ofile.write(last_chunk)

def print_help():
    print("fcrypt.py [OPTIONS]")
    print("\t{ -e --encrypt <file>\tencrypts file |")
    print("\t  -d --decrypt <file>\tdecrypts file }")
    print("\t-h --help\tshow this help")
    print("\t-p --password <password>\tpassword for decryption/encryption")
    print("\t-k --keylength [16/24/32]\tset the keylength")
    print("\t-o --outfile <file>\toutput result to this file")

def main(argv):
    mode_encrypt = 0
    mode_decrypt = 0
    password = ''
    infile = ''
    outfile = ''
    keylength = 32

    try:
        opts,args = getopt.getopt(sys.argv[1:],"he:d:p:k:o:",["help","encrypt","decrypt","password","keylength","outfile"])
    except getopt.GetoptError:
        print_help()
        sys.exit(2)

    for opt, arg in opts:
        if opt in ("-h","--help"):
            print_help()
            sys.exit()
        elif opt in("-e","--encrypt"):
            mode_encrypt = 1
            infile = arg
        elif opt in("-d","--decrypt"):
            mode_decrypt = 1
            infile = arg
        elif opt in("-p","--password"):
            password = arg
        elif opt in("-k","--keylenght"):
            keylength = int(arg)
            if keylength != 16 and keylength != 24 and keylength != 32:
                print "Keylength must be 16, 24 or 32 bytes!"
                sys.exit(2)
        elif opt in ("-o","--outfile"):
            outfile = arg
    
    if mode_encrypt == 1 and mode_decrypt == 1:
        print "Illegal options: decryption and encryption modes were both set"
        print_help()
        sys.exit(2)

    if mode_encrypt == 0 and mode_decrypt == 0:
        print "You must select to either encrypt or decrypt file"
        print_help()
        sys.exit(2)

    if password == '':
        password = getpass.getpass('Password:')

    if outfile == '':
        if mode_encrypt == 1:
            outfile = infile+".enc"
        if mode_decrypt == 1:
            outfile = infile+".dec"

        print("Outfile not set. Using " + outfile + " as output file")

    if mode_encrypt == 1:
        ifile = open(infile,'rb')
        ofile = open(outfile,'wb')
        print("Encrypting file " + infile + " to " + outfile)
        encrypt(ifile,ofile,password,keylength)

    if mode_decrypt == 1:
        ifile = open(infile,'rb')
        ofile = open(outfile,'wb')
        print("Decrypting file " + infile + " to " + outfile)
        decrypt(ifile,ofile,password,keylength)

    ifile.close()
    ofile.close()

if __name__ == "__main__":
    main(sys.argv[1:])
