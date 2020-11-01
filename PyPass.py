import os
from os import listdir

import time
import datetime
import json
import re
from random import randint

import base64
import bcrypt
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

import sqlite3
from kivy_deps import sdl2
from kivy.app import App
from kivy.core.window import Window
from kivy.clock import Clock as Clk
from kivy.config import Config
from kivy.graphics import Rectangle, RoundedRectangle, Color
from kivy.lang import Builder
from kivy.core.clipboard import Clipboard
from kivy.properties import ObjectProperty, ListProperty
from kivy.uix.boxlayout import BoxLayout as BL
from kivy.uix.gridlayout import GridLayout as GL
from kivy.uix.image import Image
from kivy.uix.textinput import TextInput as TI
from kivy.uix.switch import Switch
from kivy.uix.slider import Slider
from kivy.uix.scrollview import ScrollView
from kivy.uix.scatter import Scatter
from kivy.uix.button import Button as Btn
from kivy.uix.screenmanager import ScreenManager, Screen
from kivy.uix.widget import Widget
from kivy.uix.popup import Popup
from kivy.uix.label import Label
from kivy.logger import Logger
import PyPass_Config
import Const
from PyPass_essentials import *

global _secret

# Login Widget is the login container which holds the
# hashing, decryption and login functionality of the application
class Login(Widget):
    global _secret

    def __init__(self, **kwargs):
        global _secret
        super().__init__(**kwargs)
        ###########################################################
        _secret = None
        login_container = BL(orientation='vertical', size_hint=(None, None), height=350, width=400, pos=(300, 150))
        with login_container.canvas.before:
            Color(.1, .29, .49, 1)
            RoundedRectangle(size=(390, 320), pos=(290, 140))
        with login_container.canvas.before:
            Color(.94, .53, .086, 1)
            RoundedRectangle(size=(370, 300), pos=(300, 150))
        self.labs_inps = BL(orientation='vertical', size_hint=(None, None), height=245, width=260, pos=(360, 180))
        title = Label(text='[font=NovusGraecorumRegular.ttf][b]PyPass[/b][/font]', font_size=30,
                      color=[0, 0, 0, 1], markup=True, size_hint=(None, None), height=40, width=250)
        with title.canvas.before:
            Color(.2, .2, .2, .7)
            RoundedRectangle(size=(225, 15), pos=(370, 370))
        self.labs_inps.add_widget(title)
        self.labs_inps.add_widget(Label(text='[font=NovusGraecorumRegular.ttf][b]Username[/b][/font]',
                                        color=[0, 0, 0, 1], size_hint=(None, None), height=40, width=250, markup=True))
        self.username = TI(text='', size_hint=(None, None), halign='center', height=35, width=250, multiline=False)
        self.labs_inps.add_widget(self.username)
        self.labs_inps.add_widget(Label(text='[font=NovusGraecorumRegular.ttf][b]Password[/b][/font]',
                                        color=[0, 0, 0, 1], size_hint=(None, None), height=40, width=250, markup=True))
        self.password = TI(text='', password=True, size_hint=(None, None), halign='center',
                           height=35, width=250, multiline=False)
        self.labs_inps.add_widget(self.password)
        self.login_button = Btn(text='Login', size_hint=(None, None), height=35, width=248)
        self.login_button.bind(on_release=self.verification)
        self.labs_inps.add_widget(self.login_button)
        self.switch = Switch(active=False, size_hint=(None, None), height=25, width=80, pos=(575, 260))
        self.switch.bind(active=self.reveal_password)
        self.add_widget(login_container), self.add_widget(self.labs_inps), self.add_widget(self.switch)
        self.add_widget(Label(text="[i]PyPass Secure Password Manager\nBuilt with Python and Kivy\nAuthor: Forrest H. Wolfe[/i]",
                              markup=True, pos=(400, -275), font_size=12, color=(1, 1, 1, 1)))

        ##########################################################################################

        # revealing the login password

    def reveal_password(self, instance, value):
        if value: self.password.password = False
        else: self.password.password = True

    def verification(self, instance):
        global _secret
        # Verifying the password is longer than 10 digits
        if len(self.password.text) < 10:
            return error_pop(size=(.6, .3), title='ERROR', text=JsonWrap(json_errors, '0005'))
        # data checks the database if the entered username is in it
        data = [tup for tup in all_user_data(Const.PYPASS_DB, Const.PYPASS_ALL_DATA) if self.username.text in tup]
        # if username in database
        if bool(data):
            # if password is correct call login function else call the json error passwords don't match popup
            if check_pass(password=self.password.text, hashed_password=data[0][1]):
                _secret = self.password.text
                self.login()
            else:
                return error_pop(size=(.5, .3), title='ERROR', text=JsonWrap(json_errors, '0000'))
        else:
            # if username isn't in database json error popup
            return error_pop(size=(.5, .3), title="ERROR", text=JsonWrap(json_errors, '0002'))

        # login function updates active to 1 if the username is found in the database
        # if the database is decrypted decrypt data is called upon and username+password are both cleared
        # finally database screen is called upon to switch the screen to the database screen

    def login(self):
        _active = find_active(Const.PYPASS_DB)
        if _active == None or _active == self.username.text:
            try:
                update_data(Const.PYPASS_DB, "Update Account_Login set Active = 1 Where Username = ?",
                            (self.username.text,))
                if not is_decrypted(database=self.username.text + ".db"):
                    self.decrypt_data()
                else:
                    log_errors("User Database Was Left Decrypted, Remember To Logout")
                #self.username.text, self.password.text = '', ''
            except sqlite3.Error as error:
                log_errors(error)
                error_pop(size=(.3, .5), title='Error', text=error)
            finally:
                logIt(0, self.username.text+" has successfully logged in to PyPass")
                self.username.text, self.password.text, self.switch.active = '', '', False
                self.Database_screen()
        else:
            return error_pop(size=(.5, .3), title="ERROR", text=str(_active) + " is still logged in \n"
                                                                               "you can proceed after " + str(_active) +
                                                                               " logs out")

        # if username in database create key using the password entered and decrypt the user database file
        # the key decrypts the userdatabase file it is encrypted using the users hashed password

    def decrypt_data(self):
        users = [tup for tup in all_user_data(Const.PYPASS_DB, Const.PYPASS_ALL_DATA) if self.username.text in tup]
        if bool(users):
            __key = create_key(self.password.text, users[0][1])
            decrypt(self.username.text + ".db", __key)

    # This function switches over to the database screen
    def Database_screen(self, instance=None):
        app = App.get_running_app()
        app.root.transition.direction = 'left'
        app.root.current = 'Database'


# The login widget is added to the login screen
# The LoginScreen just contains the two buttons (new user, delete user)
# The functionality in this includes the login widget and its functions
# the popup that allows a user to delete their user account
# finally the new user button just transitions the user to the new user screen
class LoginScreen(Screen):

    def __init__(self, **kwargs):
        super(LoginScreen, self).__init__(**kwargs)
        Window.clearcolor = [.9, .3, .0, .1]
        ###########################################
        # user button container contains the buttons that are aligned on the right side of the login screen
        # the container, contains the new user button and the delete user button
        # the new user button calls the new user screen button which switches the screen to the new user screen
        # the delete user button just calls a popup to allow the user to input the info so they can delete their account

        user_button_container = GL(cols=1, rows=2, size_hint=(None, None), spacing=5, height=80, width=100,
                                   pos=(900, 500))
        self.new_user = Btn(text='[b]New User[/b]', size_hint=(None, None), markup=True,
                            background_color=[.94, .53, .086, 1], height=35, width=100)
        self.new_user.bind(on_release=self.new_user_screen)
        self.del_user = Btn(text='[b]Delete User[/b]', size_hint=(None, None), markup=True,
                            background_color=[.94, .53, .086, 1], height=35, width=100)
        self.del_user.bind(on_release=self.del_pypassUsr)
        user_button_container.add_widget(self.new_user), user_button_container.add_widget(self.del_user)
        self.add_widget(user_button_container)

        # the del scatter contains the del_usrBox gridlayout which contains the username label
        # the password label, the username input and password input, the cancel and delete button.

        self.del_scatter = Scatter(size_hint=(None, None), size=(340, 170), pos=(100, 390))
        #self.del_switch = Switch(active=False, size_hint=(None, None), height=25, pos=(780, 552), width=80)
        self.del_usrBox = GL(cols=2, rows=4, padding=[5, 5], size_hint=(None, None), pos=(0, 0), height=170,
                             width=330)
        with self.del_scatter.canvas.before:
            Color(.2, .2, .2, .8)
            RoundedRectangle(size=(340, 170), pos=(0, 0))
        self.del_usrLab = Label(text='[b]Username[/b]', color=[.9, .3, 0, 1], size_hint=(None, None), markup=True,
                                height=45, width=130)
        self.del_user = TI(text='', halign='center', size_hint=(None, None), height=35, width=200, multiline=False)
        self.del_passLab = Label(text='[b]Password[/b]', color=[.9, .3, 0, 1], size_hint=(None, None), markup=True, height=45, width=130)
        self.del_password = TI(text='', halign='center', password=True, size_hint=(None, None), height=35, width=200,multiline=False)
        self.switch_lab = Label(text='')
        self.switchbox = GL(cols=2, rows=1)
        self.switchbox.add_widget(Label(text=''))
        self.del_switch = Switch(active=False, size_hint=(None, None), height=33, width=80)
        self.switchbox.add_widget(self.del_switch)
        self.del_cancel = Btn(text='Cancel', size_hint=(None, None), height=35, width=130)
        self.del_btn = Btn(text='Delete', size_hint=(None, None), height=35, width=200)
        self.del_cancel.bind(on_release=self.cancel)
        self.del_btn.bind(on_release=self.del_account)
        self.add_widget(Image(source='shadow-hard.png', size_hint=(None, None), height=250, width=500, pos=(230, 390)))
        ###########################################################
        self.add_widget(Login())

    # if delete verification function returns true, remove the user from the database
    # then it removes the users database file thats stored inside of the database directory
    # finally a popup comes up ensuring the deletion of the user and user database
    # lastly the input is cleared
    def del_account(self, instance):
        if self.del_verification():
            update_data(Const.PYPASS_DB, "DELETE from Account_Login where Username = ?", (self.del_user.text,))
            os.remove(self.del_user.text + ".db")
            error_pop(size=(.3, .3), title='User Deleted', text=self.del_user.text + ' has been removed')
            self.del_user.text, self.del_password.text = '', ''
        else:
            error_pop(size=(.5, .3), title="ERROR", text=JsonWrap(json_errors, '0002'))

    # to speed up the password verification process I made sure the password is more then 10 digits
    # the reason is because the password has to be more than 10 digits so it can't be correct if its less than 10
    # if the username entered is in the database check the passwords to ensure when hashed it matches the stored password
    # if not del_verification will return false, serving the user a error popup
    def del_verification(self):
        if len(self.del_password.text) < 10:
            return error_pop(size=(.6, .3), title='ERROR', text=JsonWrap(json_errors, '0005'))
        data = [tup for tup in all_user_data(Const.PYPASS_DB, Const.PYPASS_ALL_DATA) if self.del_user.text in tup]
        if bool(data):
            if check_pass(password=self.del_password.text, hashed_password=data[0][1]):
                return True
            else:
                return False

    # del scatter the switch is in the top right of the deletion container the switch reveals the delete container password
    # delete account label is to the left of the switch, the scatter is added to the screen, and the usrBox container is
    # added to the delete scatter. the usrBox contains delete user label, username input, the password the delete button
    # and the cancel button
    def del_pypassUsr(self, instance):
        #self.del_scatter.add_widget(self.del_switch)
        self.del_switch.bind(active=self.reveal_del)
        self.del_scatter.add_widget(Label(text='[b]Delete Account[/b]', pos=(650, 515), markup=True))
        # the first property in add_widgets function is the obj which is the del_usrBox which is a BoxLayout
        add_widgets(self.del_usrBox, self.del_usrLab, self.del_user, self.del_passLab,
                    self.del_password,self.switch_lab, self.switchbox, self.del_cancel, self.del_btn)
        self.del_scatter.add_widget(self.del_usrBox)
        self.add_widget(self.del_scatter)

    # revealing the delete account popup password
    def reveal_del(self, instance, value):
        if value: self.del_password.password = False
        else: self.del_password.password = True

    # cancelling the del_user container thus removing it from the database screen
    def cancel(self, instance):
        self.del_user.text, self.del_password.text = '', ''
        self.del_usrBox.clear_widgets()
        self.del_scatter.clear_widgets()
        self.remove_widget(self.del_scatter)

    # This function will switch the screen to the new user screen
    def new_user_screen(self, instance):
        app = App.get_running_app()
        app.root.transition.direction = 'left'
        app.root.current = 'NewUser'


class NewUser(Screen):

    def __init__(self, **kwargs):
        super(NewUser, self).__init__(**kwargs)
        global secret
        self.SYM, self.DIG, self.CAP = 0, 0, 0
        Window.clearcolor = [.11, .13, .14, 1]
        new_container = BL(orientation='vertical', size_hint=(None, None), height=350, width=400, pos=(300, 150))
        """login canvas's the first one creates the border around the white rounded rectangle"""
        with new_container.canvas.before:
            Color(.1, .29, .49, 1)
            RoundedRectangle(size=(390, 320), pos=(290, 140))
        with new_container.canvas.before:
            Color(.94, .53, .086, 1)
            RoundedRectangle(size=(370, 300), pos=(300, 150))

        """
        labels and inputs for login container
        """

        labs = BL(orientation='vertical', size_hint=(None, None), height=270, width=260, pos=(360, 165))
        tit = Label(text='[font=NovusGraecorumRegular.ttf][b]PyPass[/b][/font]', font_size=30,
                      color=[0, 0, 0, 1], markup=True, size_hint=(None, None), height=40, width=250)
        with tit.canvas.before:
            Color(.2, .2, .2, .7)
            RoundedRectangle(size=(225, 15), pos=(370, 390))
        labs.add_widget(tit)
        labs.add_widget(Label(text='[font=NovusGraecorumRegular.ttf][b]Username[/b][/font]',
                              color=[0, 0, 0, 1], size_hint=(None, None), height=35, width=250, markup=True))
        #username
        self.un = TI(text='', size_hint=(None, None), halign='center', height=30, width=250, multiline=False)
        labs.add_widget(self.un)
        labs.add_widget(Label(text='[font=NovusGraecorumRegular.ttf][b]Password[/b][/font]',
                              color=[0, 0, 0, 1], size_hint=(None, None), height=35, width=250, markup=True))
        self.password = TI(text='', password=True, size_hint=(None, None), halign='center',
                           height=30, width=250, multiline=False)
        labs.add_widget(self.password)
        labs.add_widget(Label(text='[font=NovusGraecorumRegular.ttf][b]Verify[/b][/font]',
                              color=[0, 0, 0, 1], size_hint=(None, None), height=35, width=250, markup=True))
        self.password2 = TI(text='', password=True, size_hint=(None, None), halign='center',
                           height=30, width=250, multiline=False)
        labs.add_widget(self.password2)
        self.login_btn = Btn(text='Login', size_hint=(None, None), height=35, width=248)
        self.login_btn.bind(on_release=self.verification_wrapper)
        # self.login_btn.bind(on_release=self.verification)
        labs.add_widget(self.login_btn)

        # switch for revealing the password and confirmation password
        self.swtch = Switch(active=False, size_hint=(None, None), height=25, width=80, pos=(575, 300))
        self.swtch.bind(active=self.reveal_pass)
        self.add_widget(new_container), self.add_widget(labs), self.add_widget(self.swtch)
        self.back_btn = Btn(text='Back', size_hint=(None, None), height=40, width=70)
        self.back_btn.bind(on_release=self.loginscreen)
        self.add_widget(self.back_btn)


    def reveal_pass(self, instance, value):
        if value: self.password.password, self.password2.password = False, False
        else: self.password.password, self.password2.password = True, True

    def verification_wrapper(self, instance):
        _active = find_active(Const.PYPASS_DB)
        if _active == None:
            if len(self.password.text) <= 9:
                error_pop(size=(.5, .30), title='Error', text=JsonWrap(json_errors, '0005'))
                return
            if self.user_confirmation():
                if self.password_match():
                    self.password_requirements()
                    if self.SYM >= 1 and self.DIG >= 1:
                        if self.CAP >= 1:
                            try:
                                update_data(Const.PYPASS_DB, """INSERT INTO Account_Login ('Username', 'Password', 'Active')
                                                                VALUES(?,?,?);""", (self.un.text, hash_pass(self.password.text), 1))
                                createDB(self.un.text)
                            except sqlite3.Error as error:
                                error_pop(size=(.6, .3), title="ERROR", text=error)
                                return
                            finally:
                                global _secret
                                _secret = self.password.text
                                logIt(2, self.un.text + " Has Been Added To the PyPass User Database")
                                self.un.text, self.password.text, self.password2.text = '', '', ''
                                app = App.get_running_app()
                                app.root.current = "Database"
                        else:
                            error_pop(size=(.7, .35), title='Error', text=JsonWrap(json_errors, '0007'))
                    else:
                        error_pop(size=(.7, .35), title='Error', text=JsonWrap(json_errors, '0007'))
                else:
                    self.SYM, self.DIG, self.CAP = 0, 0, 0
                    error_pop(size=(.5, .35), title='Error', text=Const.BEFORE_ERROR + self.password.text + "    " +
                                                                  self.password2.text + "\n" + JsonWrap(json_errors, "0006"))
                    return
        else:
            return error_pop(size=(.5, .3), title="ERROR", text=str(_active) + " is still logged in \n"
                                                                               "you can proceed after " + str(_active) +
                                                                                " logs out")

    def user_confirmation(self):
        if len(self.un.text) <= 20 and len(self.un.text) != 0:
            data = [tup for tup in all_user_data(Const.PYPASS_DB, Const.PYPASS_ALL_DATA) if self.un.text in tup]
            if not bool(data):
                return True
            else:
                error_pop(size=(.5, .35), title='Error', text=JsonWrap(json_errors, '0003'))
                return False
        else:
            error_pop(size=(.7, .35), title='Error', text=JsonWrap(json_errors, '0001'))
            return False

    def password_match(self):
        return bool(self.password.text == self.password2.text)

    def password_requirements(self):
        for chars in self.password.text:
            if chars in Const.REQUIRED[0]:self.SYM += 1
            if chars in Const.REQUIRED[1]:self.DIG += 1
            if chars.isupper():self.CAP += 1

    def loginscreen(self, instance):
        self.un.text, self.password.text, self.password2.text = '', '', ''
        app = App.get_running_app()
        app.root.transition.direction = 'right'
        app.root.current = 'LoginScreen'


# This is the labels in the user inputbox the account name, email name,
# username and length of the newly generated password"""

class InputLabels(Widget):

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        inp_labels = GL(cols=1, rows= 3, size_hint=(None, None), height=125, width=100, pos=(110, 452.5))
        with inp_labels.canvas.before:
            Color(1, 1, 1, 1)
            RoundedRectangle(size=(100, 30), pos=(110, 540))
            RoundedRectangle(size=(100, 30), pos=(110, 500))
            RoundedRectangle(size=(100, 30), pos=(110, 460))
        inp_labels.add_widget(Label(text='[b]Account[/b]', markup=True, color=[0, 0, 0, 1], font_size=17))
        inp_labels.add_widget(Label(text='[b]Email[/b]', markup=True, color=[0, 0, 0, 1], font_size=17))
        inp_labels.add_widget(Label(text='[b]Username[/b]', markup=True, color=[0, 0, 0, 1], font_size=17))
        self.add_widget(inp_labels)



class DatagridLabels(Widget):

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.datagrid_labels = BL(orientation='horizontal', width=900, height=40, pos=(40, 350))
        self.datagrid_labels.add_widget(Label(text='[b]UAID[/b]', markup=True, font_size=15, width=110, color=[0, 0, 0, 1], size_hint=(None, 1)))
        self.datagrid_labels.add_widget(Label(text='[b]Account[/b]', markup=True, font_size=15, width=120, color=[0, 0, 0, 1], size_hint=(None, 1)))
        self.datagrid_labels.add_widget(Label(text='[b]Email[/b]', markup=True, font_size=15, width=165, color=[0, 0, 0, 1], size_hint=(None, 1)))
        self.datagrid_labels.add_widget(Label(text='[b]Username[/b]', markup=True, font_size=15, width=135, color=[0, 0, 0, 1], size_hint=(None, 1)))
        self.datagrid_labels.add_widget(Label(text='[b]Password[/b]', markup=True, font_size=15, width=200, color=[0, 0, 0, 1], size_hint=(None, 1)))
        self.datagrid_labels.add_widget(Label(text='[b]User Database[/b]', markup=True, font_size=15, width=200, color=[0, 0, 0, 1], size_hint=(None, 1)))
        self.add_widget(self.datagrid_labels)



class DataCanvas(Widget):

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        """----------------------------------------------------------------------------------"""
        # RoundedRectangle(size=(160, 30), pos=(690, 470))
        # slate gray of database
        self.DataGrid = BL(orientation='horizontal', size_hint=(None, None), width=870, height=740, pos=(12, 0))

        with self.DataGrid.canvas.before:
            Color(.94, .53, .086, 1), RoundedRectangle(size=(955, 390), pos=(30, 0))
            Color(.1, .29, .49, 1), RoundedRectangle(size=(945, 390), pos=(35, 0))
            # grey overlap of database slategrey
            Color(1, 1, 1, .6), RoundedRectangle(size=(900, 370), pos=(55, 0))
            # white half database
            RoundedRectangle(size=(405, 370), pos=(550, 0))
            Color(.1, .29, .49, 1), RoundedRectangle(size=(956, 40), pos=(30, 351.5))
            # orange bar across the top of the grid
            Color(.94, .53, .086, 1), RoundedRectangle(size=(951, 35), pos=(32.5, 354))
            #Color(1, 1, 1, .5), RoundedRectangle(size=(945, 35), pos=(35.5, 352.5))
            # white label spots for UAID, acc, email, username and password
            Color(1, 1, 1, 1)
            Rectangle(size=(60, 27), pos=(65, 356.5)), Rectangle(size=(115, 27), pos=(150, 356.5))
            Rectangle(size=(110, 27), pos=(295, 356.5)), Rectangle(size=(100, 27), pos=(449, 356.5))
            Rectangle(size=(110, 27), pos=(615, 356.5)), Rectangle(size=(120, 27), pos=(810, 356.5))
            Color(1, 1, 1, 1)
            poy = 10
            for x in range(8):
                Rectangle(size=(495, 25), pos=(55, poy))
                poy += 45
            poy = 10
            # orange highlighted account container
            Color(.94, .53, .086, .5)
            Rectangle(size=(140, 350), pos=(140, 0))
            for x in range(8):
                Rectangle(size=(405, 25), pos=(550, poy))
                poy += 45
        self.add_widget(self.DataGrid)



class Database(Screen):
    #char = ObjectProperty()
    def __init__(self, **kwargs):
        super(Database, self).__init__(**kwargs)
        #self.add_widget(UserInput())

        self.active_user = ''

        """Building grid and scroll layout"""
        self.scrollDB = ScrollView(do_scroll_x=False, do_scroll_y=True, size_hint=(None, None), pos=(60, 0), height=340, width=900)
        self.database = GL(cols=7, rows=1, size_hint_x=None, size_hint_y=None, height=350, spacing=10, width=925)

        "the edit scatter and edit container contain the database editing popup"
        self.edit_scatter = Scatter(pos=(200, 200), size_hint_y=None, height=170)
        self.edit_container = GL(cols=4, rows=2, padding=[10, 20], spacing=[5, 5], size_hint=(None, None), height=100,
                                 width=550, pos=(5, 50))
        self.active_editor = False


        #User input container that has 2 columns the first of which is the input labels
        #such as Account, Email, Username and finally the slider which determines the length of the password.
        #the second column contains the three user inputs the co-align with Account, Email, Username and the
        #value of the slider along with the input button that adds the user inputted data into the user database
        user_input_container = GL(cols=2, size_hint=(None, None), spacing=10, width=385, height=150, pos=(90, 425))
        #The input label container that contains the labels Account, Email and Username. This also contains the canvasing
        #for the input labels, along with the slider.
        inp_labels = GL(cols=1, rows=4, size_hint=(None, None), spacing=10, height=150, width=150)
        with inp_labels.canvas.before:
            Color(1, 1, 1, 1)
            Rectangle(size=(90, 30), pos=(120, 545))
            Rectangle(size=(70, 30), pos=(130, 505))
            Rectangle(size=(100, 30), pos=(115, 465))
        inp_labels.add_widget(Label(text='[b]Account[/b]', halign='left', markup=True, color=[.1, .29, .49, 1], font_size=18))
        inp_labels.add_widget(Label(text='[b]Email[/b]', halign='left', markup=True, color=[.1, .29, .49, 1], font_size=18))
        inp_labels.add_widget(Label(text='[b]Username[/b]', halign='left', markup=True, color=[.1, .29, .49, 1], font_size=18))
        self.slide = Slider(value=10, min=10, max=25, step=1, value_track=True,
                            value_track_color=[.2, .2, .2, 1], size_hint=(None, None), height=32, width=150)
        inp_labels.add_widget(self.slide)
        user_input_container.add_widget(inp_labels)
        """
        This is the input container that contains the text inputs for Account, Email, Username and the slider value
        """
        usr_inps = BL(orientation='vertical', size_hint=(None, None), spacing=10, height=150, width=192.5)
        with user_input_container.canvas.before:
            # slategrey container that contains the label container and user inps
            Color(.1, .29, .49, 1)
            RoundedRectangle(size=(370, 190), pos=(85, 405))
            # orange label container
            Color(.94, .53, .086, 1)
            RoundedRectangle(size=(360, 180), pos=(90, 410))
            Color(.3, .3, .3, .7)
            RoundedRectangle(size=(150, 175), pos=(92, 412))
        self.account = TI(text='', size_hint=(None, None), height=30, width=180)
        self.Email = TI(text='', size_hint=(None, None), height=30, width=180)
        self.username = TI(text='', size_hint=(None, None), height=30, width=180)
        # This is the input button in the user input box and on release inserting_data function is going to be called
        self.inp_button = Btn(text="Input", size_hint=(None, None), height=25, width=70)
        self.inp_button.bind(on_release=self.inserting_data)
        """Adding the text inputs to the usr_inps (user inputs) and also adding the input button"""
        usr_inps.add_widget(self.account), usr_inps.add_widget(self.Email), usr_inps.add_widget(self.username)

        """ The value input box contains the input button and the slider value along with the sliders canvas"""
        val_inp_box = GL(cols=2, size_hint=(None, None), height=30, width=180)
        # This is a scheduled interval every millisecond the slide value function is being called
        Clk.schedule_interval(self.slide_val, .1)
        self.val = Label(text=str(self.slide.value), color=[0, 0, 0, 1], font_size=20)
        # this is the little white square canvas that contains the slider value
        with usr_inps.canvas.before:
            Color(1, 1, 1, 1)
            RoundedRectangle(size=(45, 35), pos=(282.5, 422.5))
        """adding the slider value and the input button to the usr_inps boxlayout"""
        val_inp_box.add_widget(self.val)
        val_inp_box.add_widget(self.inp_button)
        usr_inps.add_widget(val_inp_box)

        """adding the usr input container to the user_input_container"""
        user_input_container.add_widget(usr_inps)
        self.add_widget(user_input_container)

        # This is the canvasing of the users database grid
        self.add_widget(DataCanvas())

        # The database must come after the Datacanvas or the data will appear under the canvas

        self.scrollDB.add_widget(self.database)
        self.add_widget(self.scrollDB)


        self.add_widget(DatagridLabels())


        # Container is the information container as well as the account editing root container
        # Box is a layout that contains the active username and database size
        # Box2 contains The three buttons Update account, Delete account, and logout
        # update account allows the user to change their username and password
        # delete account contains an input the user can use to delete one of their stored accounts in their database
        # logout contains an input that logs the user out and encrypts their database

        Container = GL(cols=1, rows=2, size_hint=(None, None), spacing=5, height=70, width=400, pos=(515, 440))
        with Container.canvas.before:
            # user information blue background container
            Color(.1, .29, .49, 1)
            RoundedRectangle(size=(400, 135), pos=(470, 430))
            Color(1, 1, 1, 1)
            RoundedRectangle(size=(210, 45), pos=(567, 520))
            # user information orange container
            Color(.94, .53, .086, 1)
            RoundedRectangle(size=(390, 80), pos=(475, 435))
            Color(1, 1, 1, 1)
            Rectangle(size=(260, 25), pos=(490, 480))
            Rectangle(size=(260, 25), pos=(590, 480))
        Box = BL(orientation='horizontal', size_hint=(None, None), height=35, spacing=0, width=330)
        # box2 contains the 3 buttons update account, delete account and logout
        Box2 = GL(cols=3, rows=1, size_hint=(None, None), spacing=10, height=35, width=325)
        self.alive = Label(text='', color=[0, 0, 0, 1], font_size=14, markup=True)
        self.database_size = Label(text='', color=[0, 0, 0, 1], font_size=14, markup=True)
        self.change_acc = Btn(text='Update Acc', size_hint_y=None, height=25)
        self.change_acc.bind(on_release=self.update)
        self.active_update = False
        self.delete_acc = Btn(text='Delete Acc', size_hint_y=None, height=25)
        self.delete_acc.bind(on_release=self.delete)
        self.active_delete = False
        self.logout = Btn(text='Logout', size_hint_y=None, height=25)
        self.logout.bind(on_release=self.signout)
        self.active_logout = False
        Box.add_widget(self.alive), Box.add_widget(self.database_size)
        Box2.add_widget(self.change_acc), Box2.add_widget(self.delete_acc), Box2.add_widget(self.logout)
        Container.add_widget(Box), Container.add_widget(Box2)
        self.add_widget(Container)


        # two important clocks that grab active user and active users database
        self.grab_user = Clk.schedule_interval(self.retrieve_active, 1)
        # Grabbing all the user data
        Clk.schedule_interval(self.grab_data, 2)
        """
        -----------------------------------------------------
        """
        # This is the logout container that appears after the logout button is released
        # The logout container contains password text input
        # The enter button on press encrypts the user database and on release
        # it removes the logout widget and clears the password input
        # and the cancel button that removes the logout and clears any input

        self.scatter = Scatter(size_hint=(None, None), height=160, width=350, pos=(300, 250))
        self.active_user = ''
        with self.scatter.canvas.before:
            # blue background to logout box
            Color(.1, .29, .49, 1)
            RoundedRectangle(size=(350, 160), pos=(0, 0))
            # orange background to logout box
            Color(.94, .53, .086, 1)
            RoundedRectangle(size=(340, 120), pos=(5, 5))
        self.secret = TI(text='', font_size=16, multiline=False, password=True, halign='center', size_hint=(None, None),
                         width=250, height=35, pos=(50, 50))
        self.enter_button = Btn(text='Enter', size_hint=(None, None), width=65, height=25, pos=(85, 10))
        self.enter_button.bind(on_press=self.encrypt_user_data, on_release=self.cancel_logout)
        self.cancel_button = Btn(text='Cancel', size_hint=(None, None), width=65, height=25, pos=(15, 10))
        self.cancel_button.bind(on_release=self.cancel_logout)
        self.switch = Switch(active=False, pos=(250, 5), size_hint=(None, None), height=40, width=60)
        self.switch.bind(active=self.reveal_pass)

        """
        
        +++++++++++++++++++++++++++++++++++++++++++++++++++++++++
        
        """
        # user account update layout
        self.update_scatter = Scatter(pos=(250, 250), size_hint=(None, None), height=300, width=350)
        self.user_update = GL(cols=2, rows=4, size_hint=(None, None), height=170, width=330, pos=(5, 50))
        """
        
        ==========================================================
        
        """
        self.delete_scatter = Scatter(pos=(250, 250), size_hint=(None, None), height=160, width=350)
        self.UAID = TI(text='', font_size=16, multiline=False, halign='center', size_hint=(None, None),
                       width=250, height=35, pos=(50, 50))


    # getting the value of the slider
    def slide_val(self, instance):
        self.val.text = str(self.slide.value)

    # generating random password
    @staticmethod
    def generate(length):
        PyPass = ''
        for i in range(length):
            PyPass += chr(randint(64, 123))
        return PyPass

    # switch that is used to reveal the password
    def reveal_pass(self, instance, value):
        if value: self.secret.password = False
        else: self.secret.password = True

        # retrieving the active user, which also grabs the size of the users database and
        # changes the self.database_size.text to welcome the user and display its size

    def retrieve_active(self, dt):
        user = find_active(Const.PYPASS_DB)
        if user is not None:
            self.active_user = str(user)
            self.alive.text = f"[b]Welcome, {self.active_user}[/b]"
            self.database_size.text = "[b]Passwords Stored | [/b]" + str(database_size(f'{user}.db'))
            Clk.unschedule(self.grab_user)

    # This is called upon to grab all the user data and populate the datagrid
    def grab_data(self, dt):
        self.database.clear_widgets()
        user = find_active(Const.PYPASS_DB)
        if user is not None:
            #self.active_user = str(user)
            data_tuple = all_user_data(str(user) + ".db", "SELECT * from MyData")
            for tup in data_tuple:
                self.database.rows = len(data_tuple)
                self.database.height = len(data_tuple) * 47.5
                account, email, username = tup[1], tup[2], tup[3]
                #corrected_input = modify_input(account, email, username)
                uaid = Btn(text=str(tup[0]), size_hint=(None, None), height=30, width=75, color=[1, 1, 1, 1])
                self.database.add_widget(uaid)
                uaid.bind(on_release=self.copy_uaid)
                self.database.add_widget(Label(text=str(account), size_hint_x=None, width=130, color=[0, 0, 0, 1]))
                self.database.add_widget(Label(text=str(email), size_hint_x=None, width=130, color=[0, 0, 0, 1]))
                self.database.add_widget(Label(text=str(username), size_hint_x=None, width=130, color=[0, 0, 0, 1]))
                self.database.add_widget(Label(text=str(tup[4]), size_hint_x=None, width=225, color=[0, 0, 0, 1]))
                edit_button = Btn(text='Edit', size_hint=(None, None), height=35, width=50)
                copy_button = Btn(text='Copy Pass', size_hint=(None, None), height=35, width=80)
                copy_button.bind(on_release=self.copy), edit_button.bind(on_release=self.edit)
                self.database.add_widget(copy_button), self.database.add_widget(edit_button)
                #self.database.add_widget(copy_box)
            Clk.unschedule(self.grab_data)

    # inserting data inserts the data into the users database
    # clears the widgets in the database adds a row to the database
    # finally grab_data is called again with the instance that its initiated inserting_data in the first place
    def inserting_data(self, instance):
        if self.account.text != '':
            if self.Email.text != '' or self.username.text != '':
                password = self.generate(int(self.val.text))
                sql_insert = """INSERT INTO MyData (UAID, Account, EMAIL, Username, Password)
                                      VALUES(?,?,?,?,?);"""
                modified = modify_input(str(uaid(self.active_user)), self.account.text, self.Email.text, self.username.text)
                data_tup = modified[0], modified[1], modified[2], modified[3], password
                self.account.text, self.Email.text, self.username.text = '', '', ''
                update_data(self.active_user + ".db", sql_insert, data_tup)
                self.database.clear_widgets()
                self.database.rows += 1
                self.grab_data(instance), self.retrieve_active(instance)
            else:
                error_pop(size=(.35, .35), title='Error', text="User Must Input Email or Username")
        else:
            error_pop(size=(.35, .35), title='Error', text="User Must Input Account Name")



    # copy is called upon when the user wants to copy their password that is displayed in the database grid
    def copy(self, instance):
        usr_data = []
        for child in self.database.children:
            usr_data.append(child)
            if instance == child:
                copied_password = self.database.children[int(usr_data.index(instance))+1].text
                Clipboard.copy(copied_password)

    # copy uaid is the button that contains the UAID and this function copies the UAID
    def copy_uaid(self, instance):
        Clipboard.copy(instance.text)

    # edit is the function that pops up the popup that contains the labels and textinputs
    # those labels and textinputs allow the user to edit the user inputted data
    # allows the user to edit the account name, email address, username and password
    # the cancel button will remove the widget from the screen
    # the apply button has no function yet but it will apply the changes to the users database

    def edit(self, instance):
        if not self.active_editor:
            self.active_editor = True
            # This is the canvasing of the edit_scatter
            with self.edit_scatter.canvas.before:
                Color(.1, .29, .49, 1)
                RoundedRectangle(size=(550, 170), pos=(5, 0))
                Color(.94, .53, .086, 1)
                RoundedRectangle(size=(540, 130), pos=(10, 5))
            usr_data = []
            for child in self.database.children:
                usr_data.append(child)
                if instance == child:
                    # The edit container contains the user database updating text inputs
                    self.acc = self.database.children[int(usr_data.index(instance))+5].text
                    self.email = self.database.children[int(usr_data.index(instance))+4].text
                    self.username_ = self.database.children[int(usr_data.index(instance))+3].text
                    self.password_ = self.database.children[int(usr_data.index(instance))+2].text
                    self.edit_container.add_widget(Label(text='Account', size_hint=(None, None), height=35, width=65))
                    self.account_update = TI(text=str(self.acc), multiline=False, size_hint=(None, None), height=35, width=185)
                    self.edit_container.add_widget(self.account_update)
                    self.edit_container.add_widget(Label(text='Email', size_hint=(None, None), height=35, width=65))
                    self.email_update = TI(text=str(self.email), multiline=False, size_hint=(None, None), height=35, width=185)
                    self.edit_container.add_widget(self.email_update)
                    self.edit_container.add_widget(Label(text='Username', size_hint=(None, None), height=35, width=65))
                    self.username_update = TI(text=str(self.username_), multiline=False, size_hint=(None, None), height=35, width=185)
                    self.edit_container.add_widget(self.username_update)
                    self.edit_container.add_widget(Label(text='Password', size_hint=(None, None), height=35, width=65))
                    self.password_update = TI(text=str(self.password_), multiline=False, size_hint=(None, None), height=35, width=185)
                    self.edit_container.add_widget(self.password_update)

            # button container that contains generate random password button, apply changes button, and cancel button
            button_container = GL(cols=3, rows=1, size_hint=(None, None), height=35, width=305, pos=(230, 10))
            # The generate random password button this feature may be something that is removed in the future we will see
            gen_rand = Btn(text='Random Password', size_hint=(None, 1), width=155)
            gen_rand.bind(on_release=self.generate_new)
            button_container.add_widget(gen_rand)
            # apply button calls the apply_edit function
            apply_button = Btn(text='Apply', size_hint=(None, 1), width=75)
            apply_button.bind(on_release=self.apply_edit)
            button_container.add_widget(apply_button)
            # cancel_button calls the cancel_edit function and is apart of the button container
            cancel_button = Btn(text='Cancel', size_hint=(None, 1), width=75)
            cancel_button.bind(on_release=self.cancel_edit)
            button_container.add_widget(cancel_button)
            # This is the Desklabz logo that is added to the edit scatter which is the main container
            self.edit_scatter.add_widget(Image(source='fulllogo.png', size_hint=(None, None), height=40, width=150, pos=(15, 130)))
            # Adding the edit container which contains the text inputs to the edit scatter
            # Adding the button container to the edit scatter
            self.edit_scatter.add_widget(self.edit_container), self.edit_scatter.add_widget(button_container)
            # adding the edit_scatter to the Database screen
            self.add_widget(self.edit_scatter)

        else:
            error_pop(size=(.5, .35), title='Error', text="Cannot have more than one editor active")

    def generate_new(self, instance):
        self.password_update.text = ''
        self.password_update.text = str(Database.generate(14))


    def apply_edit(self, instance):
        data = all_user_data(str(self.active_user)+'.db', "SELECT * from MyData")
        for x in data:
            if self.acc == x[1] and self.email == x[2] and self.username_ == x[3] and self.password_ == x[4]:
                modded = modify_input(self.account_update.text, self.email_update.text, self.username_update.text)
                update_data(str(self.active_user) + ".db", "Update MyData set Account = ? Where UAID = ?",
                            (modded[0], x[0]))
                update_data(str(self.active_user) + ".db", "Update MyData set EMAIL = ? Where UAID = ?",
                            (modded[1], x[0]))
                update_data(str(self.active_user)+".db", "Update MyData set Username = ? Where UAID = ?",
                            (modded[2], x[0]))
                update_data(str(self.active_user)+".db", "Update MyData set Password = ? Where UAID = ?",
                            (self.password_update.text, x[0]))
                self.cancel_edit(instance), self.grab_data(instance)




    # cancel will clear the edit widget from the screen
    def cancel_edit(self, instance):
        self.edit_container.clear_widgets()
        self.edit_scatter.clear_widgets()
        self.remove_widget(self.edit_scatter)
        self.active_editor = False

    # signout will popup the signout container which will allow the user to log out
    # signout contains the enter button which will call upon the encryption of the users database
    # the cancel button will remove the signout widget from the screen
    def signout(self, instance):
        if not self.active_logout:
            self.active_logout = True
            self.scatter.add_widget(Image(source='fulllogo.png', size_hint=(None, None),
                                          height=50, width=120, pos=(15, 115)))
            self.scatter.add_widget(Label(text='[b]Enter User Password[/b]', color=[.1, .29, .49, 1], font_size=17,
                                          size_hint=(None, None), height=40, width=300, pos=(30, 90), markup=True))
            self.scatter.add_widget(self.secret), self.scatter.add_widget(self.cancel_button),
            self.scatter.add_widget(self.enter_button), self.scatter.add_widget(self.switch), self.add_widget(self.scatter)
            logIt(1, self.active_user + " Has successfully logged out")
            self.secret.text = ''
        else:
            error_pop(size=(.5, .35), title='Error', text="Cannot Have Multiple Signout Containers Open")

    def cancel_logout(self, instance):
        self.scatter.clear_widgets()
        self.switch.active = False
        self.remove_widget(self.scatter)
        self.active_logout = False

    # super important functions like this I think i will use a decorator on to maybe simplify the look of things
    # finds the active user, verifies the users credentials, encrypts the users database and calls the logout function
    def encrypt_user_data(self, instance):
        #active_user = find_active(Const.PYPASS_DB)
        self.active_logout = False
        for data in all_user_data(Const.PYPASS_DB, Const.PYPASS_ALL_DATA):
            if self.active_user in data:
                if check_pass(self.secret.text, data[1]):
                    k = create_key(self.secret.text, data[1])
                    encrypt(str(self.active_user) + '.db', k)
                    self.logoutUser()
                    self.database.clear_widgets()
                    self.switch.active = False
                    Clk.schedule_once(self.grab_user)
                    Clk.schedule_interval(self.grab_data, 2)
                    app = App.get_running_app()
                    app.root.transition.direction = 'right'
                    app.root.current = 'LoginScreen'
                else:
                    error_pop(size=(.5, .35), title='Error', text=JsonWrap(json_errors, "0000"))


    # Changes the users activity to inactive
    def logoutUser(self):
        update_data(Const.PYPASS_DB, "Update Account_Login set Active = 0 Where Username = ?",
                    (find_active(Const.PYPASS_DB),))

    # the delete function allows the user to delete a stored account from their database
    # the delete function uses the user account ID to to identify and remove the users stored data
    # the cancel button will clear the delete widget from the database screen

    def delete(self, instance):
        if not self.active_delete:
            self.active_delete = True
            # delete_container =
            with self.delete_scatter.canvas.before:
                # blue background to logout box
                Color(.1, .29, .49, 1)
                RoundedRectangle(size=(350, 160), pos=(0, 0))
                # orange background to logout box
                Color(.94, .53, .086, 1)
                RoundedRectangle(size=(340, 120), pos=(5, 5))
            self.delete_scatter.add_widget(Image(source='fulllogo.png', size_hint=(None, None), height=50, width=120, pos=(15, 115)))
            self.delete_scatter.add_widget(Label(text='[b]Enter UAID[/b]', color=[.1, .29, .49, 1], font_size=17,
                                                 size_hint=(None, None), height=40, width=300, pos=(30, 95),
                                                 markup=True))
            self.delete_scatter.add_widget(Label(text="[i]Delete multiple accounts by seperating UAIDs with a comma[/i]", font_size=11,
                                                 pos=(125, 45), markup=True))
            self.delete_scatter.add_widget(self.UAID)
            delete_button = Btn(text='Enter', size_hint=(None, None), width=65, height=25, pos=(270, 10))
            delete_button.bind(on_release=self.delete_account)
            self.delete_scatter.add_widget(delete_button)
            cancel_button = Btn(text='Cancel', size_hint=(None, None), width=65, height=25, pos=(200, 10))
            cancel_button.bind(on_release=self.cancel_delete)
            self.delete_scatter.add_widget(cancel_button)
            self.add_widget(self.delete_scatter)
        else:
            error_pop(size=(.5, .35), title='Error', text="Cannot Have Multiple Delete Containers Open")


    # delete account removes the selected user account ID or ID's from the users database
    def delete_account(self, instance):
        self.active_delete = False
        delete(self.active_user + ".db", self.UAID.text)
        self.database.clear_widgets()
        self.grab_data(instance)
        self.delete_scatter.clear_widgets()
        self.remove_widget(self.delete_scatter)
        self.retrieve_active(instance)
        self.UAID.text = ''

        # self.clear_data(instance=instance)
        # self.edit_database(self.account_search, self.email_search)
        # self.active_deletion = True

    # cancel delete clears the delete widget from the database screen
    def cancel_delete(self, instance):
        self.delete_scatter.clear_widgets()
        self.remove_widget(self.delete_scatter)
        self.active_delete = False

    # update populates the container that allows the user to change
    # their own username and password by either changing their password
    # by entering the users old password, their new password and the confirmation of their new password
    # apply button will allow those changes to be made
    # the cancel button will clear the update widget from the database screen

    def update(self, instance):
        if not self.active_update:
            self.active_update = True
            with self.update_scatter.canvas.before:
                # blue background to logout box
                Color(.1, .29, .49, 1)
                RoundedRectangle(size=(350, 300), pos=(0, 0))
                # orange background to logout box
                Color(.94, .53, .086, 1)
                RoundedRectangle(size=(340, 260), pos=(5, 5))
            self.update_scatter.add_widget(Image(source='fulllogo.png', size_hint=(None, None), height=50,
                                                 width=120, pos=(15, 255)))
            self.update_scatter.add_widget(Label(text='[b]Update User Account[/b]', markup=True,
                                                 color=[.1, .29, .49, 1], font_size=18, pos=(125, 190)))
            self.user_update.add_widget(Label(text='Username', size_hint=(None, 1), width=130))
            # username input in user account update container
            #self.updated_username = TI(text=self.active_user, multiline=False, size_hint=(1, None), height=35)
            self.user_update.add_widget(Label(text=self.active_user, size_hint=(1, None), height=35))
            # old user password input in user account update container
            self.user_update.add_widget(Label(text='Old Password', size_hint=(None, 1), width=130))
            self.old_password = TI(text='', multiline=False, password=True, size_hint=(1, None), height=35)
            self.user_update.add_widget(self.old_password)
            # new user password input in user account update container
            self.user_update.add_widget(Label(text='New Password', size_hint=(None, 1), width=130))
            self.new_password = TI(text='', multiline=False, password=True, size_hint=(1, None), height=35)
            self.user_update.add_widget(self.new_password)
            # confirmation password in user account update container
            self.confirm_password = TI(text='', multiline=False, password=True, size_hint=(1, None), height=35)
            self.user_update.add_widget(Label(text='Confirm Password', size_hint=(None, 1), width=140))
            self.user_update.add_widget(self.confirm_password)
            # switch for allowing password to be visible
            self.update_pass_reveal = Switch(active=False, size_hint=(None, None), pos=(25, 13), height=20, width=60)
            self.update_pass_reveal.bind(active=self.expose_password)
            self.update_scatter.add_widget(self.update_pass_reveal)
            # delete_scatter.add_widget(UAID)
            apply_button = Btn(text='Apply', size_hint=(None, None), width=65, height=25, pos=(260, 10))
            apply_button.bind(on_release=self.apply_changes)
            self.update_scatter.add_widget(apply_button)
            # self.delete_scatter.add_widget(delete_button)
            cancel_button = Btn(text='Cancel', size_hint=(None, None), width=65, height=25, pos=(190, 10))
            cancel_button.bind(on_release=self.cancel_update)
            self.update_scatter.add_widget(cancel_button)
            # cancel_button.bind(on_release=self.cancel_update)
            #  self.delete_scatter.add_widget(cancel_button)
            self.update_scatter.add_widget(self.user_update)
            self.add_widget(self.update_scatter)
        else:
            error_pop(size=(.5, .35), title='Error', text="Cannot Have Multiple Update Containers Open")

    def expose_password(self, instance, value):
        if value: self.old_password.password, self.new_password.password, self.confirm_password.password = False, False, False
        else: self.old_password.password, self.new_password.password, self.confirm_password.password = True, True, True

    def apply_changes(self, instance):
        self.active_update = False
        if str(self.confirm_password.text) == str(self.new_password.text):
            for data in all_user_data(Const.PYPASS_DB, Const.PYPASS_ALL_DATA):
                if self.active_user in data:
                    if check_pass(password=self.old_password.text, hashed_password=data[1]):
                        new_password = bcrypt.hashpw(self.new_password.text.encode('utf-8'), bcrypt.gensalt(15))
                        update_data(Const.PYPASS_DB, "Update Account_Login set Password = ? Where Username = ?",
                                    (new_password, self.active_user))
                        pop(size=(.5, .3), title='Password Updated', text="User Password Updated")
                        logIt(4, self.active_user + " Has changed their password")
                        self.cancel_update(instance=instance)
                    else:
                        error_pop(size=(.5, .3), title='ERROR', text='User Password is Incorrect ')
        else:
            error_pop(size=(.5, .3), title='ERROR', text="Password's Don't Match")


    # cancel update clears the update widget from the database screen
    def cancel_update(self, instance):
        self.user_update.clear_widgets()
        self.update_scatter.clear_widgets()
        self.remove_widget(self.update_scatter)
        self.active_update = False


class WindowManager(ScreenManager):
    pass


class PyPassApp(App):


    def build(self):
        Window.size = (1000, 600)
        self.close_request = False
        self.icon = 'logo.ico'
        Window.bind(on_request_close=self.on_request_close)
        kv = Builder.load_file("PyPass.kv")
        Window.fullscreen = 0
        layout = BL(size_hint=(None, None), width=1000, height=600)
        layout.add_widget(Image(source='background.jpg'))
        Window.add_widget(layout)
        return kv

    def on_request_close(self, *args):
        self.active_user = find_active(Const.PYPASS_DB)
        if not self.close_request:
            if self.active_user != None:
                self.quicklogout(title='User Error', text=self.active_user + " You must logout to encrypt database")
            else:
                self.AreYouSure(title='Exit', text='Are you sure you want to exit?')
        return True

    def quicklogout(self, title='', text=''):
        self.close_request = True
        box = BL(orientation='vertical')
        box.add_widget(Label(text=text))
        mybutton = Btn(text='Quick Logout', size_hint=(1, 0.25))
        box.add_widget(mybutton)
        self.popup = Popup(title=title, content=box, size_hint=(None, None), size=(600, 300))
        mybutton.bind(on_press=self.ensure_encryption)
        self.popup.open()

    def ensure_encryption(self, instance):
        if _secret != None:
            for data in all_user_data(Const.PYPASS_DB, Const.PYPASS_ALL_DATA):
                if self.active_user in data:
                    if check_pass(_secret, data[1]):
                        k = create_key(_secret, data[1])
                        encrypt(str(self.active_user) + '.db', k)
                        update_data(Const.PYPASS_DB, "Update Account_Login set Active = 0 Where Username = ?",
                                    (find_active(Const.PYPASS_DB),))
                        self.stop()
                    else:
                        box = BL(orientation='vertical')
                        box.add_widget(Label(text='User password is incorrect. Have active user \n sign back in and log out to proceed!'))
                        popup = Popup(title='Password error', content=box, size_hint=(None, None), size=(500, 270))
                        popup.open()
                else:
                    box = BL(orientation='vertical')
                    box.add_widget(Label(text='User not found in database, restart application \n'
                                              'check database folder in application location and\n'
                                              'see if your database is located there.'))
                    close = Btn(text='Close', size_hint=(1, 0.25))
                    close.bind(on_release=self.stop)
                    box.add_widget(close)
                    popup = Popup(title='Application Error', content=box, size_hint=(None, None), size=(500, 270))
                    popup.open()
        else:
            box = BL(orientation='vertical')
            box.add_widget(Label(text=str(self.active_user) + " please log back in and log out \npassword not stored in cache\n"
                                                              "or just log out regulary if you're currently logged in"))
            close = Btn(text='Close and come back later', size_hint=(1, 0.25))
            close.bind(on_release=self.stop)
            box.add_widget(close)
            popup = Popup(title='Application Error', content=box, size_hint=(None, None), size=(500, 270))
            popup.open()
            self.close_request = False


    def AreYouSure(self, title='', text=''):
        self.close_request = True
        box = BL(orientation='vertical')
        box.add_widget(Label(text=text))
        mybutton = Btn(text='yes', size_hint=(1, 0.25))
        box.add_widget(mybutton)
        popup = Popup(title=title, content=box, size_hint=(None, None), size=(600, 300))
        mybutton.bind(on_release=self.stop)
        popup.open()


if __name__ == '__main__':
    PyPassApp().run()
