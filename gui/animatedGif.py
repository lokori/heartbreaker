#!/usr/bin/env python
# encoding: utf-8
"""
animatedGif.py

Created by Chris Davies-Barnard on 2014-03-14.
Copyright (c) 2014 Compu2Learn. All rights reserved.
"""
from Tkinter import * 
from PIL import Image, ImageTk

class AnimatedGif():
	filename = ""
	delay = 100
	frames = []
	cFrame = 0
	fCount = 0
	def __init__(self, newFilename):
		#Open our image
		self.filename = newFilename
		im = Image.open(self.filename)
		
		#Load the sequence
		seq = []
		try:
				while 1:
						seq.append(im.copy())
						im.seek(len(seq)) # skip to next frame
		except EOFError:
				pass # we're done
		
		#Try and get the delay so we can use it in the nextFrame method
		try:
			self.delay = im.info['duration']
		except KeyError:
			print "No delay"
		
		#Get the first image
		first = seq[0].convert('RGBA')
		self.frames = [ImageTk.PhotoImage(first)]
		
		#Now do all the others.
		temp = seq[0]
		for image in seq[1:]:
			temp.paste(image)
			frame = temp.convert('RGBA')
			self.frames.append(ImageTk.PhotoImage(frame))
		
		#store the length of the array
		self.fCount = len(self.frames)
		
	#Returns the next frame
	def nextFrame(self):
		returnFrame = self.frames[self.cFrame]
		self.cFrame = self.cFrame + 1
		if self.cFrame == self.fCount:
			self.cFrame = 0
		return returnFrame
	
	#Return current frame	
	def currentFrame(self):
		return self.frames[self.cFrame]
		
	#Get Animated Gif Info
	def info(self):
		print "Animated Gif info for " + self.filename
		print "Frame Count:" + str(self.fCount)
		print "Delay:" + str(self.delay)
