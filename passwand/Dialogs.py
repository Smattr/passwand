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
    tkMessageBox.showinfo(message, title)

def ask_question(message, text, title):
    if not initialised:
        init()
    return tkSimpleDialog.askstring(title, message, initialvalue=text)
