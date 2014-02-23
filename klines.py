#1usr/bin/python

import sys

f=open(sys.argv[1],'r')
line=f.readline()
while line:
	#print('/quote testmask *!*@'+ line[:-1])
	print('/quote kline 28800 *@' + line[:-1] + ' :drones/flooding')
	line=f.readline()
f.close()
