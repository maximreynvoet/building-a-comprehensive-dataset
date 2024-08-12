import re
import subprocess
import os
import json
import sqlite3
from glob import glob
from os.path import join, isfile
import re

## SETUP


SQLITE_DB_PATH = "/home/maxim/Documents/thesis/signatureMapping.sqlite"
CLASS = "(Signature)"

# create a SQLite database connection
def create_connection(path):
    connection = None
    try:
        connection = sqlite3.connect(path)
        print("Connection to SQLite DB successful")
    except sqlite3.Error as e:
        print(f"The error '{e}' occurred")
    return connection

db_connection = create_connection(SQLITE_DB_PATH)

# execute the given SQLite query on the given connection
def execute_query(connection, query):
    cursor = connection.cursor()
    try:
        cursor.execute(query)
        connection.commit()
        print("Query executed successfully")
    except sqlite3.Error as e:
        print(f"The error '{e}' occurred")


# create table for evasion techniques
create_signature_table = """
CREATE TABLE IF NOT EXISTS signatureStat (
    id INTEGER PRIMARY KEY,
    name TEXT ,
    description TEXT ,
    technique TEXT ,
    byMaxim TEXT,
    count integer
);
"""

execute_query(db_connection, create_signature_table)


# query to insert new sample into the database
insert_sample = """
INSERT INTO
    signatureStat (id, name, description, technique, byMaxim, count)
VALUES
    (?, ?, ? , ? , ? , ?);
"""

# execute query to insert sample into the database
def execute_insertion_query(connection, id, name, description, technique, byMaxim, count):
    cursor = connection.cursor()
    try:
        cursor.execute(insert_sample, (id, name, description, technique, byMaxim, count))
        connection.commit()
        print("Sample inserted successfully for id" + str(id))
    except sqlite3.Error as e:
        print(f"The error '{e}' occurred")



class Signature:
    def __init__(self, id, name, description, technique, count):
        self.id = id.rstrip()
        self.name = name.rstrip()
        self.description = description.rstrip()
        self.technique = technique.rstrip()
        self.count = count

    def setCount(self, count):
        self.count = count

    def __repr__(self):
        return f"<Signature id:{self.id} name :{self.name} description:{self.description} technique :{self.technique} count : {self.count}>"



# file1 = open('/home/maxim/signaturesEvasiveproc.csv', 'r')
file1 = open('/home/maxim/signaturesAll.csv', 'r')
Lines = file1.readlines()
count = 0
for line in Lines:
    print(line)
    byMaxim = "false"
    record = line.split(";")                  
    p1 = Signature(record[0], record[2], record[3], record[5], 0)
    if "[By" in record[3]:
        print("found byMaxim in " + record[3])
        byMaxim = "true"
    else:
        print("not found in " + record[3])
        byMaxim = "false"

    #print(repr(p1))
    # hack to prevent double counting parent process explorer was deleting 3 rows from signatureAll : id 623, 624 and 625, and renaming "explorer 1" to "explorer"
    
    strCommand = "grep -rnc \"" + p1.name + "\" Malwarefinalfinal.csv"
    print(strCommand)
    result = result = os.popen(strCommand).read()
    counter = result.rstrip()
    p1.setCount(int(counter))
    print(repr(p1))
    execute_insertion_query(db_connection, p1.id, p1.name , p1.description, p1.technique , byMaxim, p1.count)
    db_connection.commit()

db_connection.close()
