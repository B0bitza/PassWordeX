import random
import sqlite3, hashlib
from tkinter import *
from tkinter import simpledialog
from functools import partial
import uuid
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

backend = default_backend()
salt = b'2444'

kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=backend
)

encryptionKey = 0


def encrypt(message: bytes, key: bytes) -> bytes:
    return Fernet(key).encrypt(message)


def decrypt(message: bytes, token: bytes) -> bytes:
    return Fernet(token).decrypt(message)


# database code
with sqlite3.connect('password_vault.kdbx') as db:
    cursor = db.cursor()

cursor.execute(
    "CREATE TABLE IF NOT EXISTS masterpassword(id INTEGER PRIMARY KEY,password TEXT NOT NULL, recoveryKey TEXT NOT NULL);")

cursor.execute(
    "CREATE TABLE IF NOT EXISTS vault(id INTEGER PRIMARY KEY,website TEXT NOT NULL,username TEXT NOT NULL,password TEXT NOT NULL);")


# Create PopUp
def popUp(text):
    answer = simpledialog.askstring("Introdu datele", text)
    return answer


# Initiate window

window = Tk()
window.update()
window.title("PassWordeX")
window.geometry("300x150")
window.resizable(0, 0)
window.update_idletasks()
x = (window.winfo_screenwidth() - window.winfo_reqwidth()) / 2
y = (window.winfo_screenheight() - window.winfo_reqheight()) / 2
window.geometry("+%d+%d" % (x, y))


def hashPassword(input):
    hash1 = hashlib.sha256(input)
    hash1 = hash1.hexdigest()
    return hash1


def firstTimeScreen():
    cursor.execute('DELETE FROM vault')

    for widget in window.winfo_children():
        widget.destroy()

    window.geometry('300x150')
    lbl = Label(window, text="Alege parola de tip master")
    lbl.config(anchor=CENTER)
    lbl.pack()

    txt = Entry(window, width=20, show="*")
    txt.pack()
    txt.focus()

    lbl1 = Label(window, text="Re-introdu parola de tip master")
    lbl1.config(anchor=CENTER)
    lbl1.pack()

    txt1 = Entry(window, width=20, show="*")
    txt1.pack()

    def savePassword():
        if txt.get() == txt1.get():
            sql = "DELETE FROM masterpassword WHERE id = 1"

            cursor.execute(sql)

            hashedPassword = hashPassword(txt.get().encode('utf-8'))
            key = str(uuid.uuid4().hex)
            recoveryKey = hashPassword(key.encode('utf-8'))

            global encryptionKey
            encryptionKey = base64.urlsafe_b64encode(kdf.derive(txt.get().encode()))

            insert_password = """INSERT INTO masterpassword(password, recoveryKey)
            VALUES(?, ?) """
            cursor.execute(insert_password, ((hashedPassword), (recoveryKey)))
            db.commit()

            recoveryScreen(key)
        else:
            lbl.config(text="Parolele nu se potrivesc")

    btn = Button(window, text="Salvează", command=savePassword)
    btn.pack(pady=5)


def recoveryScreen(key):
    for widget in window.winfo_children():
        widget.destroy()

    window.geometry('300x150')
    lbl = Label(window, text="Salvează această cheie pentru a putea reseta parola")
    lbl.config(anchor=CENTER)
    lbl.pack()

    lbl1 = Label(window, text=key)
    lbl1.config(anchor=CENTER)
    lbl1.pack()

    def copyKey():
        window.clipboard_clear()
        window.clipboard_append(key)

    btn = Button(window, text="Copiază cheia", command=copyKey)
    btn.pack(pady=5)

    def done():
        vaultScreen()

    btn = Button(window, text="Continuă", command=done)
    btn.pack(pady=5)


def resetScreen():
    for widget in window.winfo_children():
        widget.destroy()

    window.geometry('300x150')
    lbl = Label(window, text="Introdu cheia de recuperare")
    lbl.config(anchor=CENTER)
    lbl.pack()

    txt = Entry(window, width=20)
    txt.pack()
    txt.focus()

    lbl1 = Label(window)
    lbl1.config(anchor=CENTER)
    lbl1.pack()

    def getRecoveryKey():
        recoveryKeyCheck = hashPassword(str(txt.get()).encode('utf-8'))
        cursor.execute('SELECT * FROM masterpassword WHERE id = 1 AND recoveryKey = ?', [(recoveryKeyCheck)])
        return cursor.fetchall()

    def checkRecoveryKey():
        checked = getRecoveryKey()

        if checked:
            firstTimeScreen()
        else:
            txt.delete(0, 'end')
            lbl1.config(text='Cheie greșită')

    btn = Button(window, text="Verifică cheia", command=checkRecoveryKey)
    btn.pack(pady=5)


def loginScreen():
    for widget in window.winfo_children():
        widget.destroy()

    window.geometry('300x150')

    lbl = Label(window, text="Introdu parola master")
    lbl.config(anchor=CENTER)
    lbl.pack()

    txt = Entry(window, width=20, show="*")
    txt.pack()
    txt.focus()

    lbl1 = Label(window)
    lbl1.config(anchor=CENTER)
    lbl1.pack(side=TOP)

    def kdf():
        return PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=backend)

    def getMasterPassword():
        checkHashedPassword = hashPassword(txt.get().encode('utf-8'))
        global encryptionKey
        encryptionKey = base64.urlsafe_b64encode(kdf().derive(txt.get().encode()))
        cursor.execute('SELECT * FROM masterpassword WHERE id = 1 AND password = ?', [(checkHashedPassword)])
        return cursor.fetchall()

    def checkPassword():
        password = getMasterPassword()

        if password:
            vaultScreen()
        else:
            txt.delete(0, 'end')
            lbl1.config(text="Parola gresita")

    def resetPassword():
        resetScreen()

    btn = Button(window, text="Enter", command=checkPassword)
    btn.pack(pady=5)

    btn = Button(window, text="Resetează parola", command=resetPassword)
    btn.pack(pady=5)


# password generator
def generatePassword():
    password = ""
    for i in range(0, 15):
        password += chr(random.randint(33, 126))
    return password


def vaultScreen():
    for widget in window.winfo_children():
        widget.destroy()

    def addEntry():
        text1 = "Website"
        text2 = "Username"
        text3 = "Password"
        website = encrypt(simpledialog.askstring("Input", text1, parent=window).encode('utf-8'), encryptionKey)
        username = encrypt(simpledialog.askstring("Input", text2, parent=window).encode('utf-8'), encryptionKey)
        password = encrypt(generatePassword().encode('utf-8'), encryptionKey)
        if website and username and password:
            insert_password = """INSERT INTO vault(website, username, password)
            VALUES(?, ?, ?) """
            cursor.execute(insert_password, ((website), (username), (password)))
            db.commit()
            vaultScreen()
        else:
            vaultScreen()

    def removeEntry(input):
        cursor.execute("DELETE FROM vault WHERE id = ?", (input,))
        db.commit()
        vaultScreen()

    window.geometry('1100x800')
    window.resizable(height=None, width=None)
    window.update_idletasks()
    width = window.winfo_width()
    height = window.winfo_height()
    x = (window.winfo_screenwidth() // 2) - (width // 2)
    y = (window.winfo_screenheight() // 2) - (height // 2)
    window.geometry('{}x{}+{}+{}'.format(width, height, x, y))

    lbl = Label(window, text="Date de autentificare")
    lbl.grid(columnspan=20, padx=80)

    btn = Button(window, text="+", command=addEntry)
    btn.grid(columnspan=20, padx=80)

    lbl = Label(window, text="Website")
    lbl.grid(row=2, column=0, padx=80)
    lbl = Label(window, text="Nume utilizator")
    lbl.grid(row=2, column=2, padx=80)
    lbl = Label(window, text="Parola")
    lbl.grid(row=2, column=4, padx=80)

    cursor.execute('SELECT * FROM vault')
    if (cursor.fetchall() != None):
        i = 0
        while True:
            cursor.execute('SELECT * FROM vault')
            array = cursor.fetchall()

            if (len(array) == 0):
                break

            def copyWebsite(input):
                window.clipboard_clear()
                window.clipboard_append(decrypt(input, encryptionKey))

            lbl1 = Label(window, text=(decrypt(array[i][1], encryptionKey)), font=("Helvetica", 12))
            lbl1.grid(column=0, row=(i + 3))
            btn = Button(window, text="Copy Website", command=partial(copyWebsite, array[i][1]))
            btn.grid(column=1, row=(i + 3), pady=5)

            def copyUsername(input):
                window.clipboard_clear()
                window.clipboard_append(decrypt(input, encryptionKey))

            lbl2 = Label(window, text=(decrypt(array[i][2], encryptionKey)), font=("Helvetica", 12))
            lbl2.grid(column=2, row=(i + 3))
            btn = Button(window, text="Copiază Nume Utilizator", command=partial(copyUsername, array[i][2]))
            btn.grid(column=3, row=(i + 3), pady=5)
            lbl3 = Label(window, text="*****", font=("Helvetica", 12))
            lbl3.grid(column=4, row=(i + 3))

            def copyPassword(input):
                window.clipboard_clear()
                window.clipboard_append(decrypt(input, encryptionKey))

            btn = Button(window, text="Copiază parola", command=partial(copyPassword, array[i][3]))
            btn.grid(column=5, row=(i + 3), pady=5)

            btn = Button(window, text="Șterge Linia", command=partial(removeEntry, array[i][0]))
            btn.grid(column=6, row=(i + 3), pady=5)
            i += 1

            cursor.execute('SELECT * FROM vault')
            if (len(cursor.fetchall()) <= i):
                break


cursor.execute('SELECT * FROM masterpassword')
if (cursor.fetchall()):
    loginScreen()
else:
    firstTimeScreen()
window.mainloop()
