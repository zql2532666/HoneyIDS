import sqlite3
from sqlite3 import Error
import json
from time import sleep


class HPfeedsDB:

    def __init__(self, path_to_db_file):
        self.path_to_db_file = path_to_db_file
        self.hpfeeds_channels = {
            "cowrie": ["cowrie.sessions"], 
            "drupot": ["agave.events"],
            "elastichoney": ["elastichoney.events"],
            "shockpot": ["shockpot.events"], 
            "snort": ["snort.alerts"], 
            "sticky_elephant": ["sticky_elephant.connections", "sticky_elephant.queries"],
            "wordpot": ["wordpot.events"],
            "dionaea": ["dionaea.connections", "dionaea.capture", "mwbinary.dionaea.sensorunique", "dionaea.capture.anon", "dionaea.caputres"]
        }
        self.connection = self.create_connection()


    def create_connection(self):
        conn = None
        try:
            conn = sqlite3.connect(self.path_to_db_file)
        except Error as e:
            print(e)
    
        print("hpfeeds database connection created")
        return conn


    def add_honeynode_credentials(self, hpfeeds_identifier, hpfeeds_secret, honeypot_type, nids_type):
        sql_statement = "INSERT INTO authkeys (owner, ident, secret, pubchans, subchans) VALUES (?,?,?,?,?)"
        curr = self.connection.cursor()
        pubchans = self.hpfeeds_channels[honeypot_type] + self.hpfeeds_channels[nids_type]

        try:
            curr.execute(sql_statement, ('honeyids', hpfeeds_identifier, hpfeeds_secret, json.dumps(pubchans), json.dumps([])))
            self.connection.commit()
        except Error as e:
            print(e)

        return curr.lastrowid

    
    def delete_honeynode_credentials(self, hpfeeds_identifier):
        sql_statement = "delete from authkeys where ident=?"
        curr = self.connection.cursor()

        try:
            curr.execute(sql_statement, (hpfeeds_identifier,))
            self.connection.commit()
        except Error as e:
            print(e)

        return curr.lastrowid

    
    def add_collector_hpfeeds_credentials(self):
        sleep(5)
        sql_statement = "INSERT INTO authkeys (owner, ident, secret, pubchans, subchans) VALUES (?,?,?,?,?)"
        curr = self.connection.cursor()
        subchans = [channel for channels in self.hpfeeds_channels.values() for channel in channels]

        try:
            curr.execute(sql_statement, ('honeyids', 'collector', 'collector', json.dumps([]), json.dumps(subchans)))
            self.connection.commit()
        except Error as e:
            print(e)

        return curr.lastrowid

    



            

