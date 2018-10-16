# Sample 1
def AccountSuccessfulyCreated():
    print("AccountSuccessfulyCreated!")
def ErrorCreatingAccount():
    print("ErrorCreatingAccount!")
def SuccessfulyLoggedIn():
    print("SuccessfulyLoggedIn")

switcher = {
    "ASC": AccountSuccessfulyCreated,
    "ERR": ErrorCreatingAccount,
    "SLI": SuccessfulyLoggedIn}

#switcher["ASC"]()

# Sample 2

class Members:
    def __init__(self, NickName, Password):
        self.NickName=NickName
        self.Password=Password
        if self.NickName == "Nick":
            self.__class__ = Admin
        print(self.__class__)
        if self.__class__ == Admin:
            self.sendMessage("Hey there")
        self.switcher = {
            "CSP": self.ChangeStandardPassword,
            "ERR": self.Adminfunc,
            "SLI": self.SuccessfulyLoggedIn}
        print(self.switcher["ERR"])
    def ChangeStandardPassword(self):
        print("ChangeStandardPassword")
    def ErrorCreatingAccount(self):
        print("ErrorCreatingAccount")
    def SuccessfulyLoggedIn(self):
        print("SuccessfulyLoggedIn")


class Admin(Members):
    def __init__(self):
        super().__init__(NickName, Password)
    def sendMessage(self, message):
        print(message)
    def Adminfunc(self):
        print("Admin rights!")


Nick = Members("Nick","PAssword")
