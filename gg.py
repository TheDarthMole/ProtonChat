class Member:
    def __init__(self):
        print("Member made")
    def func(self):
        print("Member class func")

class Admin(Member):
    def __init__(self):
        print("Admin made")
    def func(self):
        print("Admin class func")
file = r"C:\Users\User\Desktop\Client Server Chat\notification-sound.mp3"
import pygame
pygame.mixer.init(44100, -16, 2, 2048)
pygame.mixer.music.set_volume(1)
pygame.mixer.music.load(file)
pygame.mixer.music.play()
# import os
# os.system("start notification-sound.mp3")
gg=Member()
gg.__class__=Admin
# print(gg.__class__)
# print(gg.__class__.__name__.format_map.__dict__)
gg.func()
