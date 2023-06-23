import tkinter as tk
import customtkinter as ctk
import sqlite3
from enum import Enum

global logger


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


class Logger:
    def __init__(self):
        self.info("Logger", "Created Logger")

    @staticmethod
    def info(name, message):
        print(f"{bcolors.OKGREEN}[INFO - {name}]: {message}{bcolors.ENDC}")

    @staticmethod
    def warn(name, message):
        print(f"{bcolors.WARNING}[WARNING - {name}]: {message}{bcolors.ENDC}")

    @staticmethod
    def error(name, message):
        print(f"{bcolors.FAIL}[ERROR - {name}]: {message}{bcolors.ENDC}")


logger = Logger()


class Contact(ctk.CTkFrame):
    def __init__(self, master, name="", token="", command=""):
        super().__init__(master=master)
        name = ctk.CTkLabel(master=self, text="PLACEHOLDER", width=170)
        name.pack(pady=5, padx=5)
        name.bind(
            "<Button-1>",
            lambda e: print("clicked on contact")
        )
        name.bind(
            "<Button-3>",
            lambda e: print("right button?")
        )


class MessageFrame(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master=master, fg_color="grey")


class ScrollableFrame(ctk.CTkFrame):
    def __init__(self, master, *args, **kwargs):
        super().__init__(master=master, *args, **kwargs)
        canvas = ctk.CTkCanvas(master=self)
        scrollbar = ctk.CTkScrollbar(master=self, orientation="vertical", command=canvas.yview)
        self.scrollable_frame = ctk.CTkFrame(master=canvas, width=170)

        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(
                scrollregion=canvas.bbox("all")
            )
        )

        canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")

        canvas.pack(side="left", fill="y")
        scrollbar.pack(side="right", fill="y", padx=10, pady=10)

        canvas.configure(yscrollcommand=scrollbar.set, width=200, background="green", borderwidth=0)
        self.scrollable_frame.configure(width=170, fg_color="gray")
        self.scrollable_frame.update()


class ContactFrame(ScrollableFrame):
    contacts = []

    def __init__(self, master):
        super().__init__(master=master)

    def add_contact(self):
        new_contact = Contact(master=self.scrollable_frame)
        new_contact.pack(pady=10, padx=10)
        self.contacts.append(new_contact)


class Window(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.message_frame = None
        self.contact_frame = None
        self.title("Meat EE Messenger")
        self.geometry("500x400")
        self.rowconfigure(0, weight=1)
        self.columnconfigure(1, weight=1)

    def build(self):
        self.contact_frame = ContactFrame(master=self)
        self.contact_frame.grid(row=0, column=0, sticky="NSEW", pady=10, padx=10)

        # TODO: remove tmp
        # [START tmp]
        for i in range(30):
            self.contact_frame.add_contact()
        # [END tmp]

        self.message_frame = MessageFrame(master=self)
        self.message_frame.grid(row=0, column=1, sticky="NSEW", pady=10, padx=10)


class DbHandler():
    conn = None
    db = None

    def __init__(self):
        logger.info("DbHandler", "initialized new handler")
        self.conn = sqlite3.connect("messenger.db")
        self.db = self.conn.cursor()
        self.create_tables()

    def create_tables(self):
        self.db.execute("CREATE TABLE IF NOT EXISTS contacts (nickname text, token text, pub_key text)")
        self.db.execute("CREATE TABLE IF NOT EXISTS messages (from_token text, to_token text, timestamp text, "
                        "data text, encrypted_key text)")
        self.db.execute("CREATE TABLE IF NOT EXISTS local_settings (private_key text, public_key text)")
        self.conn.commit()

    def __del__(self):
        logger.warn("DbHandler", "Deleting DbHandler")
        logger.info("DbHandler", "closing connection to messenger.db")
        self.conn.close()
        logger.info("DbHandler", "connection closed")
        logger.info("DbHandler", "deleted handler")

    def get_key_pair(self):
        self.db.execute("SELECT private_key, public_key FROM local_settings")
        try:
            private_key, public_key = self.db.fetchall()
            print(private_key, public_key)

        except:
            logger.error("DbHandler", "no keypair present")
            return 0, 0


class EncryptionHandler:
    db_handler = None
    private_key = None
    public_key = None

    def __init__(self, db_handler):
        self.db_handler = db_handler
        self.check_setup()

    def check_setup(self):
        self.private_key, self.public_key = self.db_handler.get_key_pair()
