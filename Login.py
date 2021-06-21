import tkinter as tk
from tkinter import *
from tkinter.ttk import *
from csv import writer
from aes import AES

def jod(variable):
        key = '000102030405060708090a0b0c0d0e0f'
        aes = AES(mode='ecb', input_type='text')
        cyphertext = aes.encryption(variable, key)
        return cyphertext
        
def registration():
        user = entry.get()
        password = entry1.get()
        password = jod(password)
        List = [user, password]
        with open('database.csv','a') as obj:
                writer_object = writer(obj)
                writer_object.writerow(List)
                obj.close()


root = tk.Tk(className=' Registration Form')
bg = PhotoImage(file = "localpath of Registered page png")
photo = PhotoImage(file = "localpath of registerButton png")
canvas = tk.Canvas(root, width=1440, height=780)
canvas.pack()
  
canvas.create_image( 0, 0, image = bg, anchor = "nw")
canvas.pack()

entry = tk.Entry(root, width=38, background="#f5f4f4")
entry.place(x=542, y=315,height=57) 

entry1 = tk.Entry(root, width=38, font=40, background="#f5f4f4")
entry1.place(x=542, y=422,height=57)

button = tk.Button(root, width=345,borderwidth=0, text="Login",image = photo, command=registration) 
button.place(x=543, y=500,height=60)


root.mainloop()
