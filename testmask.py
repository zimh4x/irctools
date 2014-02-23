#!usr/bin/python
#produce copypasta-able commands to mass-testmask from a host/IP list

import sys


f=open(sys.argv[1],'r')
line=f.readline()
while line:
	print('/quote testmask *!*@'+ line[:-1])
	line=f.readline()
f.close()
