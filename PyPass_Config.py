from kivy.config import Config
import os
print('hellobitch')
Config.set('kivy', 'log_dir', 'PyPassLog/')
Config.set('kivy', 'log_enable', 1)
Config.set('kivy', 'log_name', 'PyPass_%y-%m-%d_%_.txt')
Config.set('kivy', 'log_maxfiles', 100)
Config.set('kivy', 'window_icon', 'logo.png')
Config.set('graphics', 'resizable', '0')
Config.write()
print('fuckyoubitch')
