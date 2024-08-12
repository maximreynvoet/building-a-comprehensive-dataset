import re
import subprocess
import os
import json
import sqlite3
from glob import glob
from os.path import join, isfile
import re


class Malware:
    def __init__(self, name, location, tobe):

        self.name = name
        self.location = location
        self.tobe = tobe
    
    def setLocation(self, location):
        self.location = location

    def setTobe(self, tobe):
        self.tobe = tobe

    def __repr__(self):
        return f"<Malware  name :{self.name} location:{self.location} tobe :{self.tobe} >"


file1 = open('/home/maxim/Malware10_tosearch.csv', 'r')
tobelocation = "/home/maxim/MalwareSampleThes"
Lines = file1.readlines()
count = 0
for line in Lines:
    count = count + 1
    print(line)
    p1 = Malware(line, "", tobelocation)

    strCommand = "fd " + line.strip() + " /media/maxim/5E25-78BA/malwaresamples"
    # print(str(count) + ":" + strCommand)
    fileStream = os.popen(strCommand)
    location = fileStream.read()
    print(str(count) + ":" + location)
    if (len(location) < 1):
        print(str(count) + "ERROR: location not found")
    strCopyCommand = "cp -t " + tobelocation + " " + location
    print(str(count) + strCopyCommand)
    result = os.popen(strCopyCommand).read()
    print(result)
