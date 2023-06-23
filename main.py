import tkinter as tk
import customtkinter as ctk
import Components as c

window = c.Window()
window.build()

db_handler = c.DbHandler()
enc_handler = c.EncryptionHandler(db_handler)

window.mainloop()