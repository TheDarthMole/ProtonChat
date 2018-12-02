class inherited:
    def __init__(self, *args, **kwargs):
        self.hh="Hey there, You've inherited"
        print(self.hh)

class gg(inherited):
    def __init__(self):
        inherited.__init__(self)


hh=gg()
print(hh.hh)
