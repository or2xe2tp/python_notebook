'''
This notebook is to save notes with the encrption with SHA-256 and a masterkey
author: Turjo Sarker Pranto
'''

import base64
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto import Random
import sys
from cryptography.fernet import Fernet
from getpass import getpass

'''
	Parameters:
	pwd - This is the masterkey. It is an ascii string. 
	note - the message to encrypt
'''


def encrypt(pwd, note, encode=True):
	note = note.encode()
	pwd = pwd.encode()
	pwd = SHA256.new(pwd).digest()
     # use SHA-256 over our key to get a proper-sized AES key. Outputs in bytes 
	IV = Random.new().read(AES.block_size)  # generate IV
	encryptor = AES.new(pwd, AES.MODE_CBC, IV)
	padding = AES.block_size - len(note) % AES.block_size  # calculate needed padding
	note += bytes([padding]) * padding  # Python 2.x: note += chr(padding) * padding
	data = IV + encryptor.encrypt(note)  # store the IV at the beginning and encrypt
	return base64.b64encode(data).decode() if encode else data


def decrypt(pwd, passw, decode=True):
    passw = passw.encode()
    if decode:
        passw = base64.b64decode(passw)
 	# use SHA-256 over our pwd to get a proper-sized AES pwd
    pwd = pwd.encode()
    pwd = SHA256.new(pwd).digest()

    IV = passw[:AES.block_size]  # extract the IV from the beginning
    decryptor = AES.new(pwd, AES.MODE_CBC, IV)
    data = decryptor.decrypt(passw[AES.block_size:])  # decrypt
    padding = data[-1]  # pick the padding value from the end; Python 2.x: ord(data[-1])
    if data[-padding:] != bytes([padding]) * padding:  # Python 2.x: chr(padding) * padding
        raise ValueError("Invalid padding...")
    return data[:-padding]  # remove the padding 



def view():
    pwd = getpass("give the masterpassword: ") #mastrpassword
    with open('notes.txt', 'r') as f:
        for line in f.readlines():
            data = line.rstrip()
            note_name, passw = data.split("|")
            msg = decrypt(pwd, passw, decode=True)
            print("______________________________________________________")
            print("Note title: ")
            print(note_name)
            print("note:")
            print(msg)
            print("______________________________________________________")

def add():
    note_name = input('note title: ') #note
    print("__________________________________________")
    note = input("input note: ") 
    print("__________________________________________")
    pwd = getpass("enter the masterpassword you want to encrypt with: ") #mastrpassword
    cipher = encrypt(pwd, note, encode=True)
    with open('notes.txt', 'a') as f:
        f.write( note_name + " "+ "|" + cipher + "\n")

while True:
    mode = input("Would you like to add a new note or view existing? press (v--VIEW, a--ADD), press q to quit? ").lower()
    if mode == "q":
        break
    if mode == "v":
        view()
    elif mode == "a":
        add()
    else:
        print("Invalid")
        continue

