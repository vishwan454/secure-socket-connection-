#!/usr/bin/env python3


import os
import signal
import socket 
import threading
from Crypto import Random 
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
        msg = conn.recv(2048)
        msg = removePadding(AESkey_d.decrypt(msg).decode("utf-8"))
        if msg == FLAG_QUIT:
            print("shutdow the server")
            os.kill(os.getpid(), signal.SIGKILL)
        else:
            print(f"client : {msg}")


def sendMessage():
    while True:
        msg = input("[@] ENTER:")
        message = AESkey_e.encrypt(padding(msg).encode("utf-8"))
        conn.send(message)
        if msg == FLAG_QUIT:
            os.kill(os.getpid(),signal.SIGKILL)



def connection_setup():
    while connected:
        conn.send(public + my_hash)
        msg = conn.recv(2046)
        print(msg)
        split = msg.split(b'/*')
        toDecrypt = split[0]
        serverPublic = split[1]
        print(serverPublic)
        
        key = RSA.importKey(private.decode("utf-8"))
        cipher = PKCS1_OAEP.new(key)
        decrypted = cipher.decrypt(toDecrypt)
        splitDEcrypted= decrypted.split(b'\n')
        print(type(splitDEcrypted))
        eightByte = splitDEcrypted[0]
        hasheightByte = splitDEcrypted[1]
        hashOfPublic = splitDEcrypted[2]
        print(type(decrypted))

        sess = hashlib.md5(eightByte)
        session = sess.hexdigest()

        hashObj = hashlib.md5(serverPublic)
        serverPublic_hash = hashObj.hexdigest()

        print(hashOfPublic.decode("utf-8"))
        print(hasheightByte.decode("utf-8"))
        print(session)
        print(serverPublic_hash)

        if serverPublic_hash.encode("utf-8") == hashOfPublic and session == hasheightByte.decode("utf-8"):
            print("sending the encrypted key")
            encryptedKey = RSA.importKey(serverPublic.decode("utf-8"))
            cipherr = PKCS1_OAEP.new(encryptedKey)
            cipherText = cipherr.encrypt(eightByte)
            conn.send(cipherText)

            key_aes = eightByte + eightByte[::-1]
            global AESkey_e, AESkey_d
            AESkey_e = AES.new(key_aes, AES.MODE_CBC, IV=key_aes)
            AESkey_d = AES.new(key_aes, AES.MODE_CBC, IV=key_aes)
            serverMsg = conn.recv(2048)
            serverMsg = removePadding(AESkey_d.decrypt(serverMsg).decode("utf-8"))
            if serverMsg == FLAG_READY:
                print("[SERVER] server is reday for communication")
                # message = input("enter ur name")
                # conn.send(message.encode("utf-8"))

                thread__receive = threading.Thread(target=receiveMsg)
                thread__receive.start()
                thread_send = threading.Thread(target=sendMessage)
                thread_send.start()
        else:
            print("something is worng")


        
        


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
    my_hash = (":" + my_hash_public).encode("utf-8")

    print(type(public))
    # print(private)
    connected = False

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(ADDR)

    print("[SERVER IS LISTENING ....]")
    server.listen()
    while True:
        conn, addr = server.accept()
        print("[SERVER] server is starting...")
        connected = True
        thread_connect = threading.Thread(target= connection_setup)
        thread_connect.start()

   