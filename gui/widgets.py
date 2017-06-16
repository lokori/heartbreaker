
from Tkinter import *
import ttk
import Tkinter as tk



class TextEntry(ttk.Entry):
	def __init__(self, parent,r,c):
		ttk.Entry.__init__(self, parent)
		self.var = StringVar()
		self.config(textvariable = self.var)
		self.grid(row=r, column=c)


class TextExtension(tk.Frame):
	"""Extends Frame.  Intended as a container for a Text field.  Better related data handling
	and has Y scrollbar now."""


	def __init__( self, parent, textvariable, *args, **kwargs ):
		self.textvariable = textvariable
		tk.Frame.__init__(self, parent)
		self.textvariable.set = self.SetText
		self.YScrollbar = Scrollbar( self, orient = VERTICAL )
		self.Text = Text( self, yscrollcommand = self.YScrollbar.set, *args, **kwargs )
		self.YScrollbar.config( command = self.Text.yview )
		#self.YScrollbar.pack( side = RIGHT)
		self.YScrollbar.grid(row=0, column=1, sticky=E+NS) 
		self.YScrollbar.rowconfigure(0, weight=1)
		self.YScrollbar.columnconfigure(1, weight=1)

		#self.Text.pack( side = LEFT, expand = 1)
		self.Text.grid(row=0, column=0, sticky=N+S+E+W)
		self.Text.rowconfigure(0, weight=1)
		self.Text.columnconfigure(0, weight=1)

		self.Text.tag_configure("green",foreground = "green")
		self.Text.tag_configure("blue",foreground = "blue")
		self.Text.tag_configure("red",foreground = "red")
		self.Text.tag_configure("brown",foreground = "brown")
		self.Text.tag_configure("binary",foreground = "white",background = "grey")
		self.Text.tag_configure("orange",foreground = "orange")
		self.Text.tag_configure("black",foreground = "black")

	def highlight_pattern(self, pattern, tag, start="1.0", end="end", regexp=False):
		'''Apply the given tag to all text that matches the given pattern
		If 'regexp' is set to True, pattern will be treated as a regular expression
		'''
		#re.DOTALL
		start = self.Text.index(start)
		end = self.Text.index(end)
		self.Text.mark_set("matchStart",start)
		self.Text.mark_set("matchEnd",start)
		self.Text.mark_set("searchLimit", end)

		count = tk.IntVar()
		while True:
			index = self.Text.search(pattern, "matchEnd","searchLimit",count=count, regexp=regexp)
			if index == "": break
			self.Text.mark_set("matchStart", index)
			self.Text.mark_set("matchEnd", "%s+%sc" % (index,count.get()))
			self.Text.tag_add(tag, "matchStart","matchEnd")

	def Clear( self ):
		self.Text.delete( 1.0, END )


	def GetText( self ):
		text = self.Text.get( 1.0, tkinter.END )
		if ( text is not None ):
			text = text.strip()
		if ( text == "" ):
			text = None
		return text


	def SetText( self, value ):
		self.Clear()
		if ( value is not None ):
			self.Text.insert( END, value.strip() )

class LabeledTextFrame(tk.Frame):
	def __init__(self, parent,labeltext,w,r,c):
		tk.Frame.__init__(self, parent)
		Label(self, text=labeltext).grid(row=0,column=0)
		self.textfield = TextEntry(self,0,1)
		self.textfield.config(width=w)
		self.grid(row=r, column=c, columnspan=3, sticky=W)


class Labeled3RadioButtonFrame(tk.Frame):
	def __init__(self, parent,labeltext,item1,item2,item3,mycommand,r,c):
		tk.Frame.__init__(self, parent)
		Label(self, text=labeltext).grid(row=0,column=0)
		self.var = StringVar()
		self.button1 = Radiobutton(self, text=item1,variable=self.var, value=item1,command=mycommand)
		self.button1.grid(row=1,column=0)
		self.button2 = Radiobutton(self, text=item2, variable=self.var, value=item2,command=mycommand)
		self.button2.grid(row=2,column=0)
		self.button3 = Radiobutton(self, text=item3, variable=self.var, value=item3,command=mycommand)
		self.button3.grid(row=3,column=0)
		self.grid(row=r,column=c, rowspan=3, sticky=N+W)


class CheckButton(ttk.Checkbutton):
	def __init__(self, parent, buttontext, mycommand,r,c):
		ttk.Checkbutton.__init__(self, parent)
		self.var = BooleanVar()
		self.config(text=buttontext, onvalue= True , variable = self.var, offvalue = False, command=mycommand)
		self.grid(row=r,column=c)		

class ActivatedInputFrame(tk.Frame):
	def __init__(self, parent,labeltext,r,c):
		tk.Frame.__init__(self, parent)
		self.buttonfield = CheckButton(self, labeltext, self.activate,0,0)
		self.buttonfield.config(state='disabled')
		self.textfield = TextEntry(self,0,1)
		self.textfield.config(state='disabled',width=5)
		self.grid(row=r,column=c)
	def activate(self):
		if self.buttonfield.var.get():
			self.textfield.config(state='enabled')
		else:
			self.textfield.config(state='disabled')


class PressButton(ttk.Button):
	def __init__(self, parent, buttontext, mycommand,r,c):
		ttk.Button.__init__(self, parent)
		self.config(text = buttontext, command=mycommand)
		self.grid(row=r,column=c)



