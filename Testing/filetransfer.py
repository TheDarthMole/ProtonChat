import os
os.remove("New__test.py")
with open("test.py","rb") as ff:
    with open("New__test.py","wb") as sf:
        tosave = ff.read(1024).hex()
        sf.write(tosave)
        while tosave != b"":
            tosave = ff.read(1024).hex()
            sf.write(tosave)
