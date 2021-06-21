import tkinter as tk
from aes import AES
import os
from tkinter import ttk
from tkinter import *
from tkinter.ttk import *


def test_str():
        thing = entry.get()
        key = '000102030405060708090a0b0c0d0e0f'
        aes = AES(mode='ecb', input_type='text')
        cyphertext = aes.encryption(thing, key)
        print(cyphertext)
        label['text'] = cyphertext
        button.configure(text='Encrypted', foreground='red')

def test_str1():
        cyphertext = entry1.get()
        key = '000102030405060708090a0b0c0d0e0f'
        aes = AES(mode='ecb', input_type='text')
        plaintext = aes.decryption(cyphertext, key)
        print(plaintext)
        label1['text'] =  plaintext
        button1.configure(text='Decrypted',foreground='green')


root = tk.Tk(className=' AES Encryption by Akshat Jalan')
bg = PhotoImage(file = 'localpath of login png' )
photo = PhotoImage(file = "localpath of button1 png")
photo1 = PhotoImage(file = "localpath of button2 png")
canvas = tk.Canvas(root, width=1440, height=780)
canvas.pack()
  
# Display image
canvas.create_image( 0, 0, image = bg, anchor = "nw")
canvas.pack()

entry = tk.Entry(root, width=53, borderwidth=0,background="#f5f4f4",justify='center')
entry.place(x=490, y=163,height=57) 

button = tk.Button(root, width=477, text="Encrypt",image = photo, command=test_str) 
button.place(x=491, y=242,height=59)

label = tk.Label(root, width=50, background="#f5f4f4")
label.place(x=500, y=365)

entry1 = tk.Entry(root, width=53, font=40, borderwidth=0, background="#f5f4f4", justify='center')
entry1.place(x=490, y=480,height=57)

button1 = tk.Button(root, width=477, text="Decrypt", image = photo1, command=test_str1) 
button1.place(x=491, y=559,height=57)

label1 = tk.Label(root, width=50, background="#f5f4f4")
label1.place(x=500, y=680)

root.mainloop()
