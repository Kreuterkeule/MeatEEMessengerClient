from CTkMessagebox import CTkMessagebox
import customtkinter as ctk
import sqlite3
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

global logger


def temp(*args, **kwargs):
    logger.error("TEMP",
                 f"TEMP FUNCTION CALLED THIS IS A BAD SIGN, OR THE FUNCTION YOU SEARCHED FOR DOES NOT EXIST YET")


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
    def debug(name, message):
        print(f"{bcolors.OKBLUE}[DEBUG - {name}]: {message}{bcolors.ENDC}")

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
    def __init__(self, master, nickname="", token="", command=temp):
        super().__init__(master=master)
        name = ctk.CTkLabel(master=self, text=nickname, width=170)
        name.pack(pady=5, padx=5)
        name.bind(
            "<Button-1>",
            lambda e: command(name, token)
        )


class AccountInfo(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master=master, fg_color="#444", height=30)
        name_label = ctk.CTkLabel(master=self, text="TEMP_NAME")
        name_label.pack()

class MessageList(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master=master, fg_color="#555")


class MessageControls(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master=master, fg_color="#444", height=50)
        self.rowconfigure(0, weight=0)
        self.columnconfigure(0, weight=1)
        message_field = ctk.CTkEntry(master=self)
        message_field.grid(row=0, column=0, sticky="NSEW", pady=10, padx=10)
        send_button = ctk.CTkButton(master=self, text="Send > ", command=temp)  # TODO create send method
        send_button.grid(row=0, column=1, pady=10, padx=10)


class MessageFrame(ctk.CTkFrame):
    def __init__(self, master):
        super().__init__(master=master, fg_color="#333")
        account_info = AccountInfo(master=self)
        account_info.grid(row=0, column=0, sticky="NSEW", pady=10, padx=10)
        message_list = MessageList(master=self)
        message_list.grid(row=1, column=0, sticky="NSEW", pady=10, padx=10)
        message_controls = MessageControls(master=self)
        message_controls.grid(row=2, column=0, sticky="NSEW", pady=10, padx=10)
        self.rowconfigure(1, weight=2)
        self.columnconfigure(0, weight=1)


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

        canvas.configure(yscrollcommand=scrollbar.set, width=200, background="#333", borderwidth=0, bg="#333")
        self.scrollable_frame.configure(width=170, fg_color="#333")
        self.scrollable_frame.update()


class ContactFrame(ScrollableFrame):
    contacts = []

    def __init__(self, master):
        super().__init__(master=master)
        self.add_contact_button = ctk.CTkButton(master=self.scrollable_frame, text="Add Contact",
                                                command=temp)  # open dialog box
        self.add_contact_button.pack(pady=10)

    def add_contact(self, name, token, set_active_command):
        new_contact = Contact(master=self.scrollable_frame, nickname=name, token=token, command=set_active_command)
        new_contact.pack(pady=10, padx=10)
        self.contacts.append(new_contact)


class Window(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.message_frame = None
        self.contact_frame = None
        self.title("Meat EE Messenger")
        self.geometry("800x600")
        self.minsize(700, 400)
        self.rowconfigure(0, weight=1)
        self.columnconfigure(1, weight=1)

    def build(self):
        self.contact_frame = ContactFrame(master=self)
        self.contact_frame.grid(row=0, column=0, sticky="NSEW", pady=10, padx=10)
        self.message_frame = MessageFrame(master=self)
        self.message_frame.grid(row=0, column=1, sticky="NSEW", pady=10, padx=10)
        # TODO: remove tmp
        # [START tmp]
        for nickname, token in [("peter", "asdfasdgagasdga"), ("rolf", "eruyspvdxpoxxpovib"),
                                ("dieter", "384520348612-48623046"), ("peter", "asdfasdgagasdga"),
                                ("rolf", "eruyspvdxpoxxpovib"),
                                ("dieter", "384520348612-48623046"), ("peter", "asdfasdgagasdga"),
                                ("rolf", "eruyspvdxpoxxpovib"),
                                ("dieter", "384520348612-48623046"), ("peter", "asdfasdgagasdga"),
                                ("rolf", "eruyspvdxpoxxpovib"),
                                ("dieter", "384520348612-48623046"), ("peter", "asdfasdgagasdga"),
                                ("rolf", "eruyspvdxpoxxpovib"),
                                ("dieter", "384520348612-48623046")]:
            self.contact_frame.add_contact(name=nickname, token=token, set_active_command=temp)
        # [END tmp]


class DbHandler():
    conn = None
    db = None

    def __init__(self):
        logger.info("DbHandler", "initialized new handler")
        self.conn = sqlite3.connect("messenger.db")
        self.db = self.conn.cursor()
        self.create_tables()

    def get_contacts(self):
        self.db.execute("SELECT * FROM contacts")
        return [*self.db.fetchall()]

    def create_contact(self, name, token, pubkey):
        try:
            self.db.execute(f"INSERT INTO contacts VALUES ({name}, {token}, {pubkey})")
            self.conn.commit()

        except:
            logger.warn(self.__class__.__name__, f"failed to create contact with VALUES ({name}, {token}, {pubkey})")

    def create_tables(self):
        self.db.execute("CREATE TABLE IF NOT EXISTS contacts (nickname text, token text, pub_key text)")
        self.db.execute("CREATE TABLE IF NOT EXISTS messages (from_token text, to_token text, timestamp text, "
                        "data text, encrypted_key text)")
        self.db.execute("CREATE TABLE IF NOT EXISTS local_settings (private_key text, public_key text)")
        self.conn.commit()

    def __del__(self):
        logger.warn(self.__class__.__name__, "deleting db handler")
        logger.info(self.__class__.__name__, "closing connection to messenger.db")
        self.conn.close()
        logger.info(self.__class__.__name__, "connection closed")
        logger.info(self.__class__.__name__, "deleted handler")

    def get_keypair(self):
        self.db.execute("SELECT private_key, public_key FROM local_settings")
        try:
            settings = self.db.fetchall()[0]
            return settings[0], settings[1]

        except:
            logger.error("DbHandler", "no keypair present")
            return 0, 0

    def create_keypair(self, new_private_key, new_public_key):
        popup = CTkMessagebox(title="Create New Encryption Keypair", message="You are about to create a new "
                                                                             "encryption keypair, this is necessary, "
                                                                             "do you want to do so"
                              , icon="question", options=["Yes", "No"])

        response = popup.get()
        logger.debug(self.__class__.__name__, f"response: {response}")
        if response != "Yes":
            return False

        self.db.execute(f"INSERT INTO local_settings VALUES (\"{new_private_key}\", \"{new_public_key}\")")
        self.conn.commit()


class EncryptionHandler:
    db_handler = None
    private_key = None
    public_key = None

    def __init__(self, db_handler):
        self.db_handler = db_handler
        self.check_setup()

    def __del__(self):
        logger.warn(self.__class__.__name__, "deleting encryption handler")

    def check_setup(self):
        self.private_key, self.public_key = self.db_handler.get_keypair()
        if (self.private_key, self.public_key) == (0, 0):
            logger.warn(self.__class__.__name__, "Couldn't get keypair")
            self.create_keypair()

    def create_keypair(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        if not self.db_handler.create_keypair(new_private_key=private_pem, new_public_key=public_pem):
            logger.warn(self.__class__.__name__, "user denied creation of new keypair")
