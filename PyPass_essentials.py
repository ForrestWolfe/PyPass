# from kivy.uix.widget import Widget
from sqlite3 import Error
import sqlite3
import json
from kivy.logger import Logger
import datetime
from kivy.uix.popup import Popup
from kivy.uix.label import Label
import bcrypt
import base64
from random import randint
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

"""------------------------------------------------------------------------------"""

def update_data(database, sql, *args):
    try:
        connection = sqlite3.connect(database)
        cursor = connection.cursor()
        props = [arg for arg in args if len(args) > 0]
        if bool(props):
            for arg in props:
                cursor.execute(sql, arg)
                connection.commit(), cursor.close()
        else:
            cursor.execute(sql)
            connection.commit(), cursor.close()
    except sqlite3.Error as error:
        log_errors(error)
        error_pop(size=(.3, .5), title='Error', text=error)


def createDB(username):
    sqlite_query = '''CREATE TABLE MyData(UAID TEXT NOT NULL, Account TEXT NOT NULL, EMAIL TEXT NOT NULL,
                          Username TEXT NOT NULL, Password TEXT NOT NULL);'''

    def create_table(database_name, table):
        try:
            connection = sqlite3.connect(database_name)
            cursor = connection.cursor()
            cursor.execute(table)
            connection.commit()
            cursor.close()
        except sqlite3.Error as creation_error:
            error_pop(size=(.5, .35), title='Error', text='Check Error Log')
            log_errors(creation_error)
    return create_table(username + ".db", sqlite_query)



"""---------------------------------------------------------------------------------
need a wrapper for all_user_data and find_active"""

def all_user_data(database_name, sql_query):
    try:
        connection = sqlite3.connect(database_name)
        cursor = connection.cursor()
        cursor.execute(sql_query)
        return cursor.fetchall()
    except sqlite3.Error as error:
        print(error, database_name)


def find_active(database):
    data = all_user_data(database, "SELECT * from Account_Login")
    for x in range(len(data)):
        if data[x][2] == 1:
            return data[x][0]


def database_size(database):
    return str(len(all_user_data(database, 'SELECT * from MyData')))


def is_decrypted(database):
    print('testing to see if its decrypted')
    try:
        connection = sqlite3.connect(database)
        cursor = connection.cursor()
        cursor.execute("""SELECT * from Mydata""")
        connection.commit()
        print('was left decrypted')
        return True
    except sqlite3.DatabaseError:
        print('most definitely encrypted')
        return False



"""Deleting user data wrapper I will be doing more wrappers on these function pages for structuring
---------------------------------------------------------------------------------------------------"""
# The steps that are called upon when using the delete function
# delete(databases/hunter.db, example1, example2)
# printing this is before the execution of database changes
# delete_multiples checks to see if there is multiple uaids
# finally user data is removed from the database because delete_userData is being called


def delete_wrapper(func, database_name, uaid):

    def inside_wrapper():
        print("This, is before the execution of database changes")
        func(uaids=uaid, database=database_name)
        print('function has been executed')

    return inside_wrapper


def delete_multiples(uaids, database):
    uaid = uaids.split(',')
    if len(uaid) <= 1:
        uaid = uaids.split(', ')
    for id_ in uaid:
        id_ = id_.replace(" ", "")
        delete_userData(uaid=id_, database=database)


def delete_userData(uaid, database):
    try:
        sql_delete_row = """DELETE from MyData where UAID = ?"""
        connection = sqlite3.connect(database=database)
        cursor = connection.cursor()
        cursor.execute(sql_delete_row, (uaid,))
        connection.commit()
        cursor.close()
    except sqlite3.Error as error:
        log_errors(error)


def delete(database, uaid):
    delete_ = delete_wrapper(delete_multiples, database, uaid)
    delete_()

# from PyPass_ManageData import *
print("pypyass essentials")

# A function for adding multiple widgets at once
def add_widgets(obj, *args):
    for widget in args:
        obj.add_widget(widget=widget)

# A function for removing multiple widgets at once
# pretty useless unless you have specific things you want to remove and leave others in place
def remove_widgets(obj, *args):
    for widget in args:
        obj.remove_widget(widget=widget)


# uaid generates the user account ID which is how we identify the data in PyPass
# uaid is really only used for a simple solution to deleting data and making changes to it
# i wanted to give them unique random ID's so this was my solution
def uaid(user):
    return chr(randint(65, 90)) + str(randint(0, 9)) + chr(randint(97, 121)) + \
           str(len(all_user_data(str(user) +'.db', "select * from MyData"))+1)


"""--------------------------Error Handling----------------------------------"""
def error_pop(size, title, text):
    Logger.error("Error Event:" + text)
    log_errors(text)
    popup = Popup(size_hint=size, title=title, content=Label(text=text))
    popup.open()

def pop(size, title, text):
    popup = Popup(size_hint=size, title=title, content=Label(text=text))
    popup.open()


# JsonWrap is used to format the errors that are sent to the error log
# and presented to the user in a pop up

def JsonWrap(func, error_code):
    def _data_():
        error = func(error_code)
        return("[ERROR CODE]:" + " || "+error[0]  + "\n[ERROR TYPE]: || " +
                error[1]  + "\n[ERROR TEXT]: || " + error[2] )
    return _data_()


def json_errors(error_code):
    err = []
    with open('PyPass_Errors.json') as json_file:
        for p in json.load(json_file)['Errors']:
            for x in p.keys():
                if error_code == p.get(x):
                    err.append(p.get("ERROR CODE"))
                    err.append(p.get("ERROR TYPE"))
                    err.append(p.get("ERROR"))
    return err


def log_errors(error):
    try:
        with open('PyPass.log', 'a') as file:
            file.write("[Error event] " + error + " [" + str(datetime.datetime.now()) + ']\n')
    except FileNotFoundError:
        print(Logger.error("Logging File Not Found"))



def logIt(head, info):
    header = ['LOGIN', 'LOGOUT', 'NEW ACCOUNT', 'ACCOUNT DELETED', 'PASSWORD UPDATED']
    try:
        with open('PyPass.log', 'a') as file:
            file.write("["+str(header[int(head)])+"]\t" + info + "\t[" + str(datetime.datetime.now()) + ']\n')
    except FileNotFoundError:
        print(Logger.error("Logging File Not Found"))

"""------------------------------User Input Modifications----------------------------------------------"""

# just a regex to find an email when looping through lists and tuples
# regex('HUnterWolfe@Live.com', 'hunterwolfe@Live.com')
def regex(word, seek):
    reg = re.compile(str(word), re.IGNORECASE)
    if reg.match(str(seek)): return True
    else: return False


# This function modifies the users input so that it can fit in the database display
# it is only used on account email and username to shorten the output so the database display
# can stay aligned because the size of each column/obj is fixed not dynamic
def modify_input(*args, max_length=15, new_length=13):
    data = []
    for arg in args:
        if arg.__contains__('@'):
            pos = arg.index('@')
            data.append(str(arg[:pos]+"{}"+arg[pos:]).format('\n'))
        else:
            if len(arg) > int(max_length):
                data.append(str(arg[:int(new_length)] + "{}".format(".") * 2))
            else:
                data.append(arg)
    return data

"""--------------------------Security Hashing & encryption --------------------------------"""


# Create key is very important because it is used to create the users key which will
# encrypt and decrypt the users database using the user password and salt which is the
# the users hashed password, this is called password based encryption
def create_key(password, s):
    password = password.encode()
    salt = s
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=50000,
        backend=default_backend()
    )
    Logger.info("Creating Key: User Key Has Been Generated")
    return base64.urlsafe_b64encode(kdf.derive(password))

# the encrypt function just encrypts the users database
# the path to the database is needed and the password based encryption key
# that is generated is used to encrypt the data
# the database is read in its original format and then encrypted and re-written to the same file
def encrypt(filename, key):
    f = Fernet(key)
    with open(filename, "rb") as file:
        file_data = file.read()
        encrypted_data = f.encrypt(file_data)
    with open(filename, "wb") as file:
        file.write(encrypted_data)
    Logger.info(filename + ": Database File Encrypted")


# decrypt is the opposite of encryption
# it uses the database file path and the password based encryption generated key to decrypt the database
# first it reads the database in its encrypted state and then decrypts using the generated key
# lastly it re-writes the file in its original decrypted form.

def decrypt(filename, key):
    f = Fernet(key)
    with open(filename, "rb") as file:
        encrypted_data = file.read()
    decrypted_data = f.decrypt(encrypted_data)
    with open(filename, "wb") as file:
        file.write(decrypted_data)
    Logger.info(filename + ": Database File Decrypted")


def hash_pass(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(15))


def check_pass(password, hashed_password):
    return bcrypt.checkpw(password=password.encode('utf-8'), hashed_password=hashed_password)


