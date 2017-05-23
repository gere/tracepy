Tracepy
===

Tracepy is a simple implementation of the classic traceroute in Python. 
No external dependancies are used.

Since it needs `sudo` to run (because of raw sockets), I had to add an hash bang at the beginning of the file. 
Adjust it according to your environment. Python 3 is needed.

Usage : sudo ./tracepy.py `<hostname>`

Keys:

	CTRL-Q: Interrupt (in a very abrupt way)

It works on MacOS and should work on Linux to. Windows, for now, is a show stopper.

