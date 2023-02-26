import secrets
from base64 import urlsafe_b64encode as b64e, urlsafe_b64decode as b64d

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

backend = default_backend()
iterations = 100_000

def _derive_key(password: bytes, salt: bytes, iterations: int = iterations) -> bytes:
    """Derive a secret key from a given password and salt"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt,
        iterations=iterations, backend=backend)
    return b64e(kdf.derive(password))

def password_encrypt(message: bytes, password: str, iterations: int = iterations) -> bytes:
    salt = secrets.token_bytes(16)
    key = _derive_key(password.encode(), salt, iterations)
    return b64e(
        b'%b%b%b' % (
            salt,
            iterations.to_bytes(4, 'big'),
            b64d(Fernet(key).encrypt(message)),
        )
    )

def password_decrypt(token: bytes, password: str) -> bytes:
    decoded = b64d(token)
    salt, iter, token = decoded[:16], decoded[16:20], b64e(decoded[20:])
    iterations = int.from_bytes(iter, 'big')
    key = _derive_key(password.encode(), salt, iterations)
    return Fernet(key).decrypt(token)

###############################

from tkinter import *
import os

# Getting username
username = os.environ.get('USER', os.environ.get('USERNAME'))

# Getting path to Documents folder based on operating system
# If there are is password manager file in Documents, we create it
from sys import platform
path = 'C:\\Users\\' + username + '\\Documents\\password_manager\\'
if os.path.isdir(path)!=True:
    os.mkdir(path)
path_to_check1 = path + 'content\\accounts'
if os.path.isdir(path_to_check1)!=True:
    os.mkdir(path+'content')
    os.mkdir(path+'content\\accounts')
path_to_check2 = path + 'logins'
if os.path.isdir(path_to_check2)!=True:
    os.mkdir(path+'logins')


class App():
    def __init__(self):
        self.root = Tk()
        self.root.geometry('500x500+800+300')
        self.root.title("")
        self.root.iconbitmap(None)
        self.root.configure(background='White')
        self.root.resizable(False, False)

        self.spacing = Label(self.root, bg='White')
        self.welcomeLabel = Label(self.root, text='',fg='black', bg='White', font=("Baskerville", 44))

        self.loginEntry = Entry(self.root, highlightbackground='white')

        self.passwordEntry = Entry(self.root, highlightbackground='white', show="*")

        self.submitLoginButton = Button(self.root, highlightbackground='white', text=">", command=self.getLogin, bg='white', activebackground='white')
        self.submitLoginAndPasswordButton = Button(self.root, highlightbackground='white', text=">", command=self.getPassword, bg='white', activebackground='white')

        self.registerButton = Button(self.root, highlightbackground='white', text='create account', command=self.showRegistrationPage, bg='Green', background='Green', activebackground='white', highlightcolor='white', bd=2)

        self.backButton = Button(self.root, highlightbackground='white', text="<", command=self.showLoginPage)

        # By clicking escape you will always go to log in screen
        self.root.bind("<Escape>", self.showLoginPage)

        # Error messages
        self.wrongPasswordAlert = Button(text='Wrong password', highlightbackground='white', foreground='red')
        self.wrongLoginAlert = Button(text='Account with this login does not exist', highlightbackground='white', foreground='red')
        self.typeLoginAlert = Button(text='Enter your login', highlightbackground='white', foreground='red')
        self.typeLoginAlertAndPasswordAlert = Button(text='Enter login and password', highlightbackground='white', foreground='red')

        self.loggedBefore = False

        self.showLoginPage()

        self.root.mainloop()

    def nothing(self, _Event=None):
        pass

    def showRegistrationPage(self):
        self.wrongPasswordAlert.place(x=6000,y=10)
        self.wrongLoginAlert.place(x=6000,y=10)

        self.loginEntry.place(x=6000, y=6000)
        self.passwordEntry.place(x=6000, y=6000)
        self.submitLoginButton.place(x=6000, y=6000)
        self.submitLoginAndPasswordButton.place(x=6000, y=6000)
        self.registerButton.place(x=6000,y=6000)

        def createaccountdef():
            login = self.showRegistrationPageLogin.get()
            password = self.showRegistrationPagePassword.get()

            if login != "" and password != "":
                path = 'C:\\Users\\' + username + '\\Documents\\password_manager\\logins\\'

                with open(path+login+'.txt', 'w') as f:
                    pass

                # We will create a content file in the future, but it must be immediately, from the beginning encrypted with something, because then logging is whether the algorithm will decrypt it, if not it crashes the wrong password
                encryptedNothing = password_encrypt("".encode(), password)
                path = 'C:\\Users\\' + username + '\\Documents\\password_manager\\content\\accounts\\'

                with open(path + login+'.txt', 'wb') as f:
                    f.write(encryptedNothing)
   
                self.showRegistrationPageLogin.place(x=6000, y=6000)
                self.showRegistrationPagePassword.place(x=6000, y=6000)
                self.showRegistrationPageSend.place(x=6000, y=6000)

                self.welcomeLabel.configure(text='Welcome User?')
                self.showLoginPage()

            else:
                self.typeLoginAlertAndPasswordAlert.place(x=75,y=40)

        self.welcomeLabel.configure(text='registration')

        self.spacing.place(x=6000,y=6000)
        self.welcomeLabel.place(x=6000,y=6000)

        self.backButton.pack(pady=5)
        self.spacing.pack()
        self.welcomeLabel.pack(pady=15)

        self.showRegistrationPageLogin = Entry(self.root, highlightbackground='white')
        self.showRegistrationPageLogin.pack(pady=5)
        self.showRegistrationPageLogin.focus()

        self.showRegistrationPagePassword = Entry(self.root, highlightbackground='white', show="*")
        self.showRegistrationPagePassword.pack(pady=0)

        self.showRegistrationPageSend = Button(self.root, highlightbackground='white', text='create new account', command=createaccountdef)
        self.showRegistrationPageSend.pack(pady=25)

    def showLoginPage(self, _Event=None):

        self.root.protocol("WM_DELETE_WINDOW", lambda: self.root.destroy())

        if self.loggedBefore == True:
            self.savePreviousText()

        self.welcomeLabel.configure(text='Welcome User !')
        self.root.configure(background='white')
        self.typeLoginAlertAndPasswordAlert.place(x=6000,y=40)

        try:
            self.backButton.place(x=6000,y=6000)
        except: 
            pass

        try:
            self.scrollb.destroy()
        except:
            pass

        try:
            self.notetext.destroy()
            self.powrotbutton.destroy()
        except:
            pass

        try:
            self.canvas.destroy()
        except:
            pass

        try:
            self.showRegistrationPageLogin.destroy()
            self.showRegistrationPagePassword.destroy()
            self.showRegistrationPageSend.destroy()
        except:
            pass

        try:
            self.szukaj.destroy()
        except:
            pass

        try:
            self.stworzkonto.destroy()
        except:
            pass

        self.spacing.pack(pady=35)
        self.welcomeLabel.pack()
        self.loginEntry.pack(pady=10)
        self.loginEntry.focus()
        self.submitLoginButton.pack(pady=10)
        self.registerButton.pack(pady=40)

        self.loginEntry.bind("<Return>", self.getLogin)

    def getLogin(self,_Event=None):
        self.login = self.loginEntry.get()

        if self.login != "":
            targetFile = self.login + ".txt"

            isThere = False
            directory = 'C:\\Users\\' + username + '\\Documents\\password_manager\\logins'
 
            for filename in os.listdir(directory):
                if filename == targetFile:
                    isThere = True

            if isThere==False:
                self.wrongPasswordAlert.place(x=8000,y=10)
                self.typeLoginAlert.place(x=6000,y=100)
                self.wrongLoginAlert.place(x=20,y=10)
                self.loginEntry.focus()

            if isThere==True:
                # when there will be a login in the database, we will show the password field
                self.wrongLoginAlert.place(x=6000,y=10)
                self.typeLoginAlert.place(x=6000,y=10)

                # we are building a formation from the beginning
                self.submitLoginButton.place(x=6000,y=6000)
                self.registerButton.place(x=6000,y=6000)

                self.passwordEntry.pack()
                self.passwordEntry.focus()
                self.passwordEntry.bind("<Return>", self.getPassword)

                self.submitLoginAndPasswordButton.pack(pady=10)
                self.registerButton.pack(pady=30)

        else:
            self.wrongLoginAlert.place(x=6000,y=10)
            self.typeLoginAlert.place(x=80,y=10)

    def getPassword(self, _Event=None):
        self.password = self.passwordEntry.get()

        self.loggedin(self.login)

    def savePreviousText(self):
        # try because even if it is sometimes after logging in and someone clicks registration, there was an error
        try:
            textData = self.notetext.get("1.0",END)

            if textData!= "":
                # ENCRYPTING THERE
                encryptedData = password_encrypt(textData.encode(), self.password)
                path = 'C:\\Users\\' + username + '\\Documents\\password_manager\\content\\accounts\\'

                with open(path + self.target, 'wb') as f:
                    f.write(encryptedData)
        except:
            pass

    def loggedin(self, login):
        self.wrongPasswordAlert.place(x=6000,y=10)
        self.wrongLoginAlert.place(x=6000,y=10)

        self.loginEntry.delete(0, END)
        self.passwordEntry.delete(0, END)

        self.loginEntry.place(x=6000, y=6000)
        self.passwordEntry.place(x=6000, y=6000)
        self.submitLoginAndPasswordButton.place(x=6000, y=6000)
        self.registerButton.place(x=6000, y=6000)
        self.welcomeLabel.place(x=6000,y=6000)
        self.spacing.place(x=5000,y=6000)

        self.target = login + ".txt"

        def read():
            path = 'C:\\Users\\' + username + '\\Documents\\password_manager\\content\\accounts\\'

            with open(path + self.target, 'r') as f:
                content = f.read()

            # DECRYPTING THERE
            try:
                decryptedData = password_decrypt(content, self.password).decode()
                self.notetext.delete('1.0', END)
                self.notetext.insert('1.0', decryptedData)

                self.loggedBefore = True

            except Exception as e:
                print(e)

                self.wrongPasswordAlert.place(x=80,y=10)
                self.showLoginPage()

        def saveOnExit(_Event=None):
            textData = self.notetext.get("1.0",END)

            if textData!= "":
                # ENCRYPTING THERE
                encryptedData = password_encrypt(textData.encode(), self.password)
                path = 'C:\\Users\\' + username + '\\Documents\\password_manager\\content\\accounts\\'

                with open(path + self.target, 'wb') as f:
                    f.write(encryptedData)

            self.root.destroy()

        def search(_Event=None):
            self.notetext.tag_remove('found', '1.0', END)

            s = self.searchent.get() # Grabs the text from the entry box
            if s:
                idx = '1.0'
                while 1:
                    idx = self.notetext.search(s, idx, nocase=1, stopindex=END)
                    if not idx: break
                    lastidx = '%s+%dc' % (idx, len(s))
                    self.notetext.tag_add('found', idx, lastidx)
                    idx = lastidx
                    self.notetext.see(idx)  # Once found, the scrollbar automatically scrolls to the text
                self.notetext.tag_config('found', background='yellow')
                    
            self.searchent.focus_set()

        def search2(_Event=None):
            if self.ifSearched==False:
                self.searchent.focus()
                self.searchent.place(x=50, y=5, height=30, width=100)
                self.ifSearched = True
            else:
                self.notetext.focus()
                self.searchent.place(x=5000, y=10, height=40, width=100)

                self.notetext.tag_remove('found', '1.0', END)
                
                self.ifSearched=False

        global clickedddd
        clickedddd = False
        def pokazsearchent():
            global clickedddd

            if clickedddd==False:
                clickedddd = True
                self.searchent.place(x=110,y=2)
                self.searchent.focus()

            else:
                self.notetext.tag_remove('found', '1.0', END)
                self.searchent.place(x=6000,y=0)
                self.searchent.delete(0, END)

                clickedddd = False


        self.notetext = Text(self.root, bd=0, highlightbackground='white', highlightthickness=0,font=('SF Text', 16), bg='white', fg='black')
        
        self.scrollb = Scrollbar(self.root, command=self.notetext.yview, width=14)
        self.notetext['yscrollcommand'] = self.scrollb.set

        self.scrollb.place(x=286,y=34, height=360)

        self.szukaj = Button(self.root, text='search', highlightbackground='white', command=pokazsearchent)
        self.szukaj.place(x=215,y=0)

        self.searchent = Entry(self.root, width=10, highlightbackground='white')

        self.searchent.bind("<Return>", search)
        self.searchent.bind("<Control-f>", search2)

        self.backButton.place(x=2, y=0)
        
        self.notetext.place(x=4, y=38, width=285, height=360)

        self.canvas = Canvas(self.root, bg='white', bd=0, highlightbackground='white')
 
        # This creates a line of length 200 (straight horizontal line)
        self.canvas.create_line(0, 5, 300, 5, fill='gray')
 
        # This pack the canvas to the main window and make it expandable
        self.canvas.place(x=0,y=29, width=300, height=9)

        self.root.protocol("WM_DELETE_WINDOW", saveOnExit)

        read()

App()