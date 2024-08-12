import json
import sys
import traceback
import shutil
from pathlib import Path
from age.models import Vertex
import unittest
import decimal
import age
import argparse
import sqlite3
import psycopg2
import age
from glob import glob

# SETUP

GRAPH_NAME = "metx"
TEST_HOST = "localhost"
TEST_PORT = 5455
TEST_DB = "postgresDB"
TEST_USER = "beevasion"
TEST_PASSWORD = "beevasion"
TEST_GRAPH_NAME = "metx"

SQLITE_DB_PATH = "/home/maxim/Documents/thesis/signatureMapping.sqlite"

SCRIPT_DEST_FILE = "/home/maxim/Documents/thesis/edges.sql"
SCRIPT_FILE_SOURCE_TEMPLATE = "/home/maxim/Documents/thesis/edges_template.sql"


def copy_and_rename(src_path, dest_path, new_name):
    # Copy the file
    shutil.copy(src_path, dest_path)

    # Rename the copied file
    new_path = f"{dest_path}/{new_name}"
    shutil.move(f"{dest_path}/{src_path}", new_path)

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


def updateSignatureString(dic, key, val):
    signatureString = ""
    if key in dic:
        print("Present, so appending")
        signatureString = dic[key]
        signatureString = signatureString + ";" + val
        dic[key] = signatureString
    else:
        print("Not present, so adding")
        dic[key] = val


# execute the given SQLite query on the given connection
def execute_query_mapping(connection, signature):
    cursor = connection.cursor()
    try:
        sql_select_query = """select mapping from signatures where name like ?"""
        print(sql_select_query + signature + ":")
        cursor.execute(sql_select_query, [f"%{signature}%"])
        result = cursor.fetchone()
        if result is not None:
            print(result)
        cursor.close()
        return result

    except sqlite3.Error as error:
        print("Failed to read data from sqlite table", error)
    except sqlite3.Error as e:
        print(f"The error '{e}' occurred")


class TestAgeBasic():
    ag = None
    args: argparse.Namespace = argparse.Namespace(
        host=TEST_HOST,
        port=TEST_PORT,
        database=TEST_DB,
        user=TEST_USER,
        password=TEST_PASSWORD,
        graphName=TEST_GRAPH_NAME
    )

    def setUp(self):
        print("Connecting to Test Graph.....")
        args = dict(
            host=self.args.host,
            port=self.args.port,
            dbname=self.args.database,
            user=self.args.user,
            password=self.args.password,
        )

        dsn = "host={host} port={port} dbname={dbname} user={user} password={password}".format(
            **args
        )
        self.ag = age.connect(dsn, graph=self.args.graphName, **args)

    def tearDown(self):
        # Clear test data
        print("Deleting Test Graph.....")
        age.deleteGraph(self.ag.connection, self.ag.graphName)
        self.ag.close()

    def testExec(self, name, signature_techniques):
        print("\n---------------------------------------------------")
        print("creating Malware")
        print("---------------------------------------------------\n")
        implementationString = ""
        for signature in signature_techniques:
            implementationString = implementationString + \
                "[name:" + signature + "],"
        implementationString = implementationString[:-1]

        with self.ag.connection.cursor() as cursor:
            try:
                self.ag.cypher(cursor, "CREATE (m:Malware {name: %s , Implementations: %s}) ", params=(
                    name, implementationString))

                # You must commit explicitly
                self.ag.commit()
            except Exception as ex:
                print(ex)
                self.ag.rollback()

    def createEdges(self, name, paramkey, paramImplementationString):
        print("\n---------------------------------------------------")
        print("creating Edges")
        print("---------------------------------------------------\n")
        implementationStringEdge = ""
        implementations = paramImplementationString.split(";")
        for implementation in implementations:
            implementationStringEdge = implementationStringEdge + \
                "[name:" + implementation + "],"
        implementationStringEdge = implementationStringEdge[:-1]

        query = "SELECT * from cypher('" + TEST_GRAPH_NAME + "', $$ MATCH (m:Malware), (t:Technique) WHERE m.name = '" + name + "' AND t.id = '" + \
            paramkey + "' CREATE (m)-[r:USES {Implementations: '" + \
            implementationStringEdge + \
                "'}]->(t) RETURN r $$) as (USES agtype);\n"
        print(query + "\n")
        try:
            f = open(SCRIPT_DEST_FILE, "a")
            f.write(query)
            f.write("\n")
            f.close()
        except Exception as ex:
            print(ex)


#        cursor = ag.execCypher("""CREATE (m:Malware {id : "C01" }) SET c.name = "Malware Evasion Techniques Catalog" RETURN c $$) as (catalog agtype);
#                RETURN p """)

    # for row in cursor:
    #        print("CREATED EDGE WITH PROPERTIES: %s" % row[0])
    #        self.assertEqual(row[0][1].properties["weight"], 5)
if __name__ == "__main__":
    shutil.copy(SCRIPT_FILE_SOURCE_TEMPLATE, SCRIPT_DEST_FILE)
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-host",
        "--host",
        help='Optional Host Name. Default Host is "127.0.0.1" ',
        default=TEST_HOST,
    )
    parser.add_argument(
        "-port",
        "--port",
        help="Optional Port Number. Default port no is 5432",
        default=TEST_PORT,
    )
    parser.add_argument(
        "-db", "--database", help="Required Database Name", default=TEST_DB
    )
    parser.add_argument(
        "-u", "--user", help="Required Username Name", default=TEST_USER
    )
    parser.add_argument(
        "-pass",
        "--password",
        help="Required Password for authentication",
        default=TEST_PASSWORD,
    )
    parser.add_argument(
        "-gn",
        "--graphName",
        help='Optional Graph Name to be created. Default graphName is "test_graph"',
        default=TEST_GRAPH_NAME,
    )

    args = parser.parse_args()
    t = TestAgeBasic()
    t.args = args
    t.setUp()

    print("Connection to graph DB successful")
    report_file_paths = glob(
        "/opt/CAPEv2/storage/analyses/[0-9]*/reports/report.json", recursive=True)
    # get the triggered yara rules (= evasion techniques used)
    for report_file_path in sorted(report_file_paths):
        antidebug_techniques = []
        signature_techniques = []
        antivm_techniques = []
        name = ""
        with open(report_file_path, "r") as json_file:
            report = json.load(json_file)
            # print(json.dumps(report, indent = 4, sort_keys=True))
            try:
                name = Path(report["target"]["file"]["path"]).name
                print(name)
                # create_malware(name, conn)
                if report["signatures"]:
                    signatures_list = report["signatures"]
                    for signature in signatures_list:
                        signaturename = signature["name"]
                        signature_techniques.append(signaturename)
            except Exception as e:
                e = sys.exc_info()
                print('Error Return Type: ', type(e))
            json_file.close()
        t.testExec(name, signature_techniques)
        # print the evasion techniques to console
        print(name + "\n" + "-" * len(name))
        print("SIGNATURES:\n")
        print("\n".join(sorted(signature_techniques)))
        dic = {}
        signatureString = ""
        for signature in (sorted(signature_techniques)):
            # check if signature is of evasive type
            mapping = execute_query_mapping(db_connection, signature)
            if (mapping is not None) and (len(mapping[0]) > 0):
                print("mapping for signature " + signature +
                      " found : " + mapping[0] + "current=" + signatureString)
                updateSignatureString(dic, mapping[0], signature)
        for key in dic:
            val = dic[key]
            print(
                "would add string USES: {Implementations: " + val + "for dictkey " + key + "\n")
            t.createEdges(name, key, val)


db_connection.close()

# conn = create_connection(GRAPH_NAME)
# get paths of the analysis reports (excluding the 'latest' folder)
# report_file_paths = glob(CAPE_PATH + "storage/analyses/[0-9]*/reports/report.json", recursive=True)

# conn.close()
# def create_malware(name, connection):
#    with conn.cursor() as cursor:
