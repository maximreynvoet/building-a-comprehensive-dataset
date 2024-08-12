import json
import sqlite3
from glob import glob
from os.path import join, isfile
import re

## SETUP

COMMUNITY_PATH = "/home/maxim/projects/communitysignatures/community/modules/signatures/windows/"
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
CREATE TABLE IF NOT EXISTS signatures (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT NOT NULL,
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    category TEXT,
    mapping TEXT
);
"""

execute_query(db_connection, create_signature_table)


# query to insert new sample into the database
insert_sample = """
INSERT INTO
    signatures (filename, name , description, category, mapping)
VALUES
    (?, ?, ? , ? , ?);
"""

# execute query to insert sample into the database
def execute_insertion_query(connection, filename, name, description, category, mapping):
    cursor = connection.cursor()
    try:
        cursor.execute(insert_sample, (filename, name, description, category, mapping))
        connection.commit()
        print("Sample inserted successfully")
    except sqlite3.Error as e:
        print(f"The error '{e}' occurred")



## CREATE THE DATABASE

# get paths of the analysis reports (excluding the 'latest' folder)
dir_signature_file_paths = COMMUNITY_PATH
filelist = [filename for filename in glob(join(dir_signature_file_paths, '*')) if isfile(filename)]
filelist = sorted(filelist)
for f in filelist:
    with open(f, "r") as sigfile:
        print("parsing " + f);
        filename = f

        classFound = False
        categoriesFound = False
        descriptionContinuation = False
        count = 0
        for line in sigfile:

            # line = re.sub(r"[\n\t]*", "", line)
            # line = line.strip()
            print (str(count) + ":" + line)
            count = count + 1
            # print("Line{}: {}".format(count, line.strip()))
            if "(Signature)" in line:
                classFound = True
                print("sig found in " + line)
                continue
            if "name = " in line and classFound:
                name = line.split("=")[1]
                name = name.strip()
                print ("namefound:" + name)
                continue
            if "description = " in line and classFound:
                description = line.replace("description = ","")
                description = re.sub(r"[\n\t]*", "", description)
                description = description.strip()
                print ("description entered:" + description)
                if description.startswith("("):
                    print("continuation found")
                    descriptionContinuation = True
                    print ("description:" + description)
                continue
            if descriptionContinuation:
                line = re.sub(r"[\n\t]*", "", line)
                line = line.strip()
                if line.startswith(")"):
                    descriptionContinuation = False
                description = description + line
                description = description.strip()
                print ("description continued:" + description)
                continue
            if  "categories = " in line and classFound:
                categories = line.replace("categories = ","")
                categoriesFound = True
                categories = re.sub(r"[\n\t]*", "", categories)
                categories = categories.strip()
                print ("categories:" + categories)

            if classFound and categoriesFound:
                print("insert:" + filename + ";" + name + ";" + description + ";" + categories + ";")
                execute_insertion_query(db_connection, filename, name , description, categories, "")
                db_connection.commit()
                classFound = False
                categoriesFound = False
            if not line:
                break

db_connection.close()
