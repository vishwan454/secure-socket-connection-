#!/usr/bin/env python3

import os
import signal
import socket 
import threading
from Crypto import Random
from Crypto import Cipher 
import Crypto.Cipher.AES as AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import hashlib

def removePadding(msg):
    return msg.replace('`','')

def padding(msg):
    return msg + ((16 - len(msg) % 16) * '`')


def receiveMsg():
        while True:
            msg = client.recv(2048)
            mesg = removePadding(AESkey_d.decrypt(msg).decode("utf-8"))
            if mesg == FLAG_QUIT:
                print("shutdow the server")
                os.kill(os.getpid(), signal.SIGKILL)
            else:
                print(f"server : {mesg}")


def sendMessage():
        while True:
            msg = input("[@] ENTER:")
            message = AESkey_e.encrypt(padding(msg).encode("utf-8"))
            client.send(message)
            if msg == FLAG_QUIT:
                os.kill(os.getpid(),signal.SIGKILL)



def connection_setup():
    while connected:
        clientPH = client.recv(2046).decode("utf-8")
        split = clientPH.split(":")
        tmpClientPublic = split[0].encode('utf-8')
        clientPublicHash = split[1]
        tmpHashObject = hashlib.md5(tmpClientPublic)
        tmpHash = tmpHashObject.hexdigest()
        

        if tmpHash == clientPublicHash:
            keyy = RSA.importKey(tmpClientPublic.decode("utf-8"))
            clientPublic = PKCS1_OAEP.new(keyy)
            session1 = session.encode("utf-8")
            fsend = (eightByte + b'\n'+session1 + b'\n' + my_hash)
            fsend = clientPublic.encrypt(fsend)
            print(len(fsend))
            client.send(fsend + b'/*' + public)


            clientPH = client.recv(2048)
            if clientPH != "":
                key1 = RSA.importKey(private.decode("utf-8"))
                cipher = PKCS1_OAEP.new(key1) 
                decrypt =cipher.decrypt(clientPH) 
                if decrypt == eightByte:
                    key_aes = eightByte + eightByte[::-1]
                    global AESkey_e, AESkey_d
                    AESkey_e = AES.new(key_aes, AES.MODE_CBC, IV=key_aes)
                    AESkey_d = AES.new(key_aes, AES.MODE_CBC, IV=key_aes)
                    clientMsg = AESkey_e.encrypt(padding(FLAG_READY).encode("utf-8"))
                    client.send(clientMsg)

                    thread__receive = threading.Thread(target=receiveMsg)
                    thread__receive.start()
                    thread_send = threading.Thread(target=sendMessage)
                    thread_send.start()




        



if __name__ == "__main__":
    SERVER = socket.gethostbyname(socket.gethostname())
    PORT = 6543
    ADDR = (SERVER, PORT)
    random = Random.new().read
    RSAkey = RSA.generate(1024,random)
    public = RSAkey.publickey().exportKey()
    private = RSAkey.exportKey()
    FLAG_READY = "Ready"
    FLAG_QUIT = "Quit"

    tmppub = hashlib.md5(public)
    my_hash_public =tmppub.hexdigest() 
    my_hash = (my_hash_public).encode("utf-8")

    eightByte = os.urandom(8)
    # print(eightByte)
    sess = hashlib.md5(eightByte)
    session =sess.hexdigest() 
    print(type(session))
    a = ":"
    b = a.encode("utf-8")
    # print(type(b))
    connected = False


    client = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    client.connect(ADDR)
    connected = True
    thread_connect = threading.Thread(target= connection_setup)
    thread_connect.start()
    