import tkMessageBox, tkSimpleDialog, Tkinter

initialised = False

def init():
    global initialised
    window = Tkinter.Tk()
    window.wm_withdraw()
    initialised = True

def show_message(message, title):
    if not initialised:
        init()
    tkMessageBox.showinfo(title, message)

def askstring(message, text, title, **kwargs):
    if not initialised:
        init()
    return tkSimpleDialog.askstring(title, message, initialvalue=text, **kwargs)

def ask_question(message, text, title):
    return askstring(message, text, title)

def ask_password(message, text, title):
    # Passing 'show' here is undocumented, but seems to work.
    return askstring(message, text, title, show='*')
