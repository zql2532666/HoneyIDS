import json
import datetime
from datetime import datetime as dt
from traceback import print_tb
from flask_mysqldb import MySQL
import time 
from flask import Flask, render_template, request, jsonify, abort, redirect, url_for, flash, send_file, session
import mysql.connector

class DbAccess:

    def __init__(self, app, mysql_conn):
        # self.mysql = MySQL(app)
        self.mysql = mysql_conn

    def query_db(self, cursor, result):
        r = [dict((cursor.description[i][0], value) for i, value in enumerate(row)) for row in result]
        return r

    def myconverter(self,obj):
        if isinstance(obj, datetime.datetime):
            return obj.strftime('%Y-%m-%d %H:%M:%S')

    def retrieve_all_nodes(self):
        json_data = {}

        # Mysql connection
        cur = self.mysql.cursor()

        sql = "select * from nodes"
        cur.execute(sql)
        result = cur.fetchall()
        result_value = len(result)
        if result_value > 0:
            my_query = self.query_db(cur, result)
            json_data = json.dumps(my_query, default=self.myconverter)
        else:
            json_data = {}
        print(json_data)
        return json_data

    def retrieve_all_active_nodes(self):
        
        json_data = {}

        # Mysql connection
        cur = self.mysql.cursor()

        sql = "select * from nodes where heartbeat_status='True'"
        cur.execute(sql)
        result = cur.fetchall()
        result_value = len(result)
        if result_value > 0:
            my_query = self.query_db(cur, result)
            json_data = json.dumps(my_query, default=self.myconverter)

        return json_data

    def retrieve_all_general_logs(self):
        
        json_data = {}

        # Mysql connection
        cur = self.mysql.cursor()

        sql = "select * from general_logs"
        cur.execute(sql)
        result = cur.fetchall()
        result_value = len(result)
        if result_value > 0:
            my_query = self.query_db(cur, result)
            json_data = json.dumps(my_query, default=self.myconverter)

        return json_data

    def retrieve_all_virus_total_logs(self):
        
        json_data = {}

        # Mysql connection
        cur = self.mysql.cursor()

        sql = "select *, (select honeynode_name from nodes where virus_total_logs.token = nodes.token) as honeynode_name from virus_total_logs;"
        cur.execute(sql)
        result = cur.fetchall()
        result_value = len(result)
        if result_value > 0:
            my_query = self.query_db(cur, result)
            json_data = json.dumps(my_query, default=self.myconverter)

        return json_data

    def retrieve_all_nids_logs(self):
        
        json_data = {}

        # Mysql connection
        cur = self.mysql.cursor(prepared=True)

        sql = "select * from nids_logs"
        cur.execute(sql)
        result = cur.fetchall()
        result_value = len(result)
        if result_value > 0:
            my_query = self.query_db(cur, result)
            json_data = json.dumps(my_query, default=self.myconverter)

        return json_data

    def retrieve_all_session_logs(self):
        
        json_data = {}

        # Mysql connection
        cur = self.mysql.cursor()

        sql = "select * from session_logs"
        cur.execute(sql)
        result = cur.fetchall()
        result_value = len(result)
        if result_value > 0:
            my_query = self.query_db(cur, result)
            json_data = json.dumps(my_query, default=self.myconverter)

        return json_data

    def retrieve_all_nodes_for_heartbeat(self):
        json_data = {}

        # Mysql connection
        cur = self.mysql.cursor()

        sql = "select * from nodes"
        cur.execute(sql)
        result = cur.fetchall()
        result_value = len(result)
        if result_value > 0:
            my_query = self.query_db(cur, result)
            json_data = json.loads(json.dumps(my_query, default=self.myconverter))
        heartbeat_dict = dict()
        for data in json_data:
            # convert the time format to time since epoch
            last_heard = data.get("last_heard")
            last_heard_struct_time_local = time.strptime(last_heard, "%Y-%m-%d %H:%M:%S")
            last_heard_epoch = time.mktime(last_heard_struct_time_local)
            heartbeat_dict[data.get("token")] = {
                    'heartbeat_status' : data.get("heartbeat_status"),
                    'last_heard' : last_heard_epoch
            }

        return heartbeat_dict

    def retrieve_node(self, token):
        json_data = {}

        # Mysql connection
        cur = self.mysql.cursor()

        sql = "select * from nodes where token=%s"
        params = (token, )
        cur.execute(sql, params)
        result = cur.fetchall()
        result_value = len(result)
        if result_value > 0:
            my_query = self.query_db(cur, result)
            json_data = json.dumps(my_query, default=self.myconverter)

        return json_data

    def create_node(self, json):

        #Mysql connection
        cur = self.mysql.cursor(prepared=True)

        honeynode_name = json['honeynode_name']
        ip_addr = json['ip_addr']
        subnet_mask = json['subnet_mask']
        honeypot_type = json['honeypot_type']
        nids_type = json['nids_type']
        no_of_attacks = json['no_of_attacks']
        date_deployed = json['date_deployed']
        heartbeat_status = json['heartbeat_status']
        last_heard = json['last_heard']
        token = json['token']
        
        sql = """insert into nodes(honeynode_name, ip_addr, subnet_mask, honeypot_type, nids_type, no_of_attacks, date_deployed, heartbeat_status, token, last_heard) values(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"""
        params = (honeynode_name, ip_addr, subnet_mask, honeypot_type, nids_type, int(no_of_attacks), date_deployed, heartbeat_status, token, last_heard,)
        
        result_value = 0

        try:
            result_value = cur.execute(sql, params)
            self.mysql.commit()
            cur.close()
        except Exception as err:
            print(err)

        return result_value

    def update_node(self, json, token):

        # Mysql connection
        cur = self.mysql.cursor(prepared=True)

        honeynode_name = '' if not json.__contains__('honeynode_name') else json['honeynode_name']
        ip_addr = '' if not json.__contains__('ip_addr') else json['ip_addr']
        subnet_mask = '' if not json.__contains__('subnet_mask') else json['subnet_mask']
        honeypot_type = '' if not json.__contains__('honeypot_type') else json['honeypot_type']
        nids_type = '' if not json.__contains__('nids_type') else json['nids_type']
        no_of_attacks = '' if not json.__contains__('no_of_attacks') else int(json['no_of_attacks'])
        date_deployed = '' if not json.__contains__('date_deployed') else json['date_deployed']
        heartbeat_status = '' if not json.__contains__('heartbeat_status') else json['heartbeat_status']
        last_heard = '' if not json.__contains__('last_heard') else json['last_heard']

        sql = """update nodes set honeynode_name=IF(%s = '', honeynode_name, %s), \
            ip_addr=IF(%s = '', ip_addr, %s), \
            subnet_mask=IF(%s = '', subnet_mask, %s), \
            honeypot_type=IF(%s = '', honeypot_type, %s), \
            nids_type=IF(%s = '', nids_type, %s), \
            no_of_attacks=IF(%s = '', no_of_attacks, %s), \
            date_deployed=IF(%s = '', date_deployed, %s), \
            heartbeat_status=IF(%s = '', heartbeat_status, %s), \
            last_heard=IF(%s = '', last_heard, %s) where token=%s""" 
        params = (honeynode_name, honeynode_name, ip_addr, ip_addr, subnet_mask, subnet_mask, honeypot_type, honeypot_type, nids_type, nids_type, int(no_of_attacks), int(no_of_attacks), date_deployed, date_deployed, heartbeat_status, heartbeat_status , last_heard , last_heard , token)
        result_value = 0

        try:
            result_value = cur.execute(sql,params)
            self.mysql.commit()
            cur.close()
        except Exception as err:
            print(err)

        return result_value

    def update_node_heartbeat_status(self, token, json):
    
        # Mysql connection
        cur = self.mysql.cursor(prepared=True)

        heartbeat_status = '' if not json.__contains__('heartbeat_status') else json['heartbeat_status']

        ############### DO EPOCH PARSING HERE ###########################
        last_heard_epoch = '' if not json.__contains__('last_heard') else json['last_heard']
        last_heard_epoch = float(last_heard_epoch)
        last_heard_struct_time = time.localtime(last_heard_epoch)
        last_heard = f"{last_heard_struct_time[0]}-{last_heard_struct_time[1]}-{last_heard_struct_time[2]} {last_heard_struct_time[3]}:{last_heard_struct_time[4]}:{last_heard_struct_time[5]}"
        
        sql = """update nodes set \
            heartbeat_status=IF(%s = '', heartbeat_status, %s), \
            last_heard=IF(%s = '', last_heard , %s) where token=%s"""
        params = (heartbeat_status, heartbeat_status, last_heard, last_heard, token)

        result_value = 0

        try:
            result_value = cur.execute(sql,params)
            self.mysql.commit()
            cur.close()
        except Exception as err:
            print(err)

        return result_value

    def delete_node(self, token):

        # Mysql connection
        cur = self.mysql.cursor(prepared=True)

        sql = """delete from nodes where token=%s"""
        params=(token, )
        result_value = 0

        try:
            result_value = cur.execute(sql,params)
            self.mysql.commit()
            cur.close()
        except Exception as err:
            print(err)

        return result_value



    """
    Author: Derek
    Database Access for virustotal logs
    """

    def insert_vt_log(self, vt_data):
        # Mysql connection
        cur = self.mysql.cursor(prepared=True)
        scan_id  = vt_data["scan_id"]
        md5 = vt_data["md5"]
        sha1 =  vt_data["sha1"]
        sha256 =  vt_data["sha256"]
        scan_date =  vt_data["scan_date"]
        permalink = vt_data["permalink"]
        positives =  int(vt_data["positives"])
        total =  int(vt_data["total"])
        scans =  json.dumps(vt_data["scans"])
        zipped_file_path =  vt_data["zipped_file_path"]
        time_at_file_received =  vt_data["time_at_file_received"]
        token =  vt_data["token"]
        response = int(vt_data["response_code"])
        zipped_file_password = vt_data["zipped_file_password"]

        # sql = f"insert into virus_total_logs(scan_id, md5, sha1, sha256, scan_date, permalink,positives, total, scans, zipped_file_path,time_at_file_received, token) \
        #     values(%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s','%s','%s')" % (scan_id,md5,sha1,sha256,scan_date,permalink,positives,total,scans,zipped_file_path,time_at_file_received,token)
        sql = """insert into virus_total_logs(scan_id, md5, sha1, sha256, scan_date, permalink,positives, total, scans, zipped_file_path,time_at_file_received, token,response, zipped_file_password) \
            values(\
                %s,\
                %s,\
                %s,\
                %s,\
                %s,\
                %s,\
                %s,\
                %s,\
                %s,\
                %s,\
                %s,\
                %s,\
                %s,\
                %s)"""
        params = (scan_id, md5, sha1, sha256,scan_date, permalink, int(positives), int(total), scans, zipped_file_path,  time_at_file_received, token, int(response), zipped_file_password )   
        result_value = 0
        try:
            result_value = cur.execute(sql,params)
            self.mysql.commit()
            cur.close()
        except Exception as err:
            print(err)

        return result_value

    def insert_vt_log_file_path(self, vt_data):
        cur = self.mysql.cursor(prepared=True)
        md5 = vt_data["md5"]
        zipped_file_path =  vt_data["zipped_file_path"]
        time_at_file_received =  vt_data["time_at_file_received"]
        token =  vt_data["token"]
        response = int(vt_data["response_code"])
        zipped_file_password = vt_data["zipped_file_password"]       
        print("\n\n----VT DATA ---- \n\n")
        print(vt_data)
        print("\n\n----VT DATA ---- \n\n")
        sql = """insert into virus_total_logs(md5, zipped_file_path,time_at_file_received, token,response,zipped_file_password) \
            values(\
                %s, \
                %s, \
                %s,\
                %s,\
                %s,\
                %s)"""     
        params=(md5, zipped_file_path, time_at_file_received, token, int(response), zipped_file_password)
        result_value = 0
        try:
            result_value = cur.execute(sql,params)
            self.mysql.commit()
            cur.close()
        except Exception as err:
            print(err)

        return result_value


    """
    Author: rongtao
    Database Access for general logs
    """
    def insert_general_log(self, general_log_data):
        # Mysql connection
        cur = self.mysql.cursor(prepared=True)

        sql = """insert into general_logs(capture_date, honeynode_name, source_ip, source_port, destination_ip, destination_port, protocol, token, raw_logs) \
            values(%s, %s, %s, %s, %s, %s, %s, %s, %s)"""
        params=(general_log_data['capture_date'],
            general_log_data['honeynode_name'],
            general_log_data['source_ip'],
            general_log_data['source_port'],
            general_log_data['destination_ip'],
            general_log_data['destination_port'],
            general_log_data['protocol'],
            general_log_data['token'],
            json.dumps(general_log_data['raw_logs']))
        print('\n\n')
        print("type in insert")
        print(type(general_log_data['raw_logs']))
        result_value = 0

        try:
            result_value = cur.execute(sql,params)
            print("\n\n")
            print("insert raw log")
            print(general_log_data['raw_logs'])
            self.mysql.commit()
            cur.close()
        except Exception as err:
            print(err)

        return result_value


    # Insert NIDS Logs
    def insert_snort_log(self,snort_log_data):
        cur = self.mysql.cursor(prepared=True)
        nids_type = 'snort'
        sql = """insert into nids_logs(nids_type,date,token,honeynode_name,source_ip,source_port,destination_ip, destination_port,priority, classification,signature, raw_logs) 
            values(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"""
        params=(nids_type, snort_log_data['date'], snort_log_data['token'],  snort_log_data['honeynode_name'],snort_log_data['source_ip'], snort_log_data['source_port'], snort_log_data['destination_ip'],  snort_log_data['destination_port'], snort_log_data['priority'], snort_log_data['classification'], snort_log_data['signature'], json.dumps(snort_log_data['raw_logs']))

        result_value = 0

        try:
            result_value = cur.execute(sql,params)
            self.mysql.commit()
            cur.close()
        except Exception as err:
            print(err)

        return result_value

    
    # Insert cowrie session logs
    def insert_session_log(self, session_log_data):
        cur = self.mysql.cursor(prepared=True)

        token = session_log_data['token']
        honeynode_name = session_log_data['honeynode_name']
        source_ip = session_log_data['source_ip']
        source_port = session_log_data['source_port']
        destination_ip = session_log_data['destination_ip']
        destination_port = session_log_data['destination_port']
        commands = json.dumps(session_log_data['commands'])
        logged_in = json.dumps(session_log_data['logged_in'])
        start_time = session_log_data['start_time']
        end_time = session_log_data['end_time']
        session = session_log_data['session']
        urls = json.dumps(session_log_data['urls'])
        credentials = json.dumps(session_log_data['credentials'])
        hashes = json.dumps(session_log_data['hashes'])
        version = session_log_data['version']
        unknown_commands = json.dumps(session_log_data['unknown_commands'])


        sql = """insert into session_logs(token,honeynode_name,source_ip,source_port,destination_ip, destination_port, commands, logged_in, start_time, end_time, session, urls, credentials, hashes, version, unknown_commands) 
            values( \
            %s, \
            %s, \
            %s, \
            %s, \
            %s, \
            %s, \
            %s, \
            %s, \
            %s, \
            %s, \
            %s, \
            %s, \
            %s, \
            %s, \
            %s, \
            %s)"""
        params=(token, honeynode_name, source_ip, source_port, destination_ip, destination_port,  commands, logged_in, start_time,  end_time, session, urls, credentials, hashes, version, unknown_commands)

        result_value = 0

        try:
            result_value = cur.execute(sql,params)
            self.mysql.commit()
            cur.close()
        except Exception as err:
            print(err)

        return result_value


    def update_bruteforce_log(self, bruteforce_log_data):
        cur = self.mysql.cursor(prepared=True)
        
        token = bruteforce_log_data['token']
        start_time = bruteforce_log_data['start_time']
        end_time = bruteforce_log_data['end_time']
        source_ip = bruteforce_log_data['source_ip']
        credentials = json.dumps(bruteforce_log_data['credentials'])

        sql = """update session_logs set end_time=%s, credentials=%s where token = %s and source_ip = %s and start_time=%s"""
        params=(end_time, credentials,  token, source_ip, start_time)
        result_value = 0

        try:
            result_value = cur.execute(sql,params)
            self.mysql.commit()
            
            sql1 = """SELECT log_id, raw_logs from general_logs where token = %s and source_ip = %s"""
            params=(token, source_ip)
            cur.execute(sql1, params)
            result = cur.fetchall()
            result_value_1 = len(result)
            if result_value_1 > 0:
                rows = self.query_db(cur, result)
                for row in rows:
                    raw_log_dict = json.loads(row['raw_logs'])
                    if raw_log_dict['startTime'].split(".")[0].replace("T", " ") == start_time:
                        raw_log_dict_new = raw_log_dict
                        raw_log_dict_new['credentials'] = bruteforce_log_data['credentials']

                        sql3 = """update general_logs set raw_logs=%s where log_id = %s""" 
                        params=(json.dumps(raw_log_dict_new), row['log_id'])
                        print("\n\n")
                        print("sql query")
                        print(sql3)

                        result_value_2 = cur.execute(sql3,params)
                        self.mysql.commit()
                        print(result_value_2)
                        
            cur.close()
        except Exception as err:
            print(err)

        return result_value

    
    def delete_general_logs_by_id(self, log_id_list):
        cur = self.mysql.cursor(prepared=True)
        # log_id_list = [69, 70, 71, 72]

        placeholder = '%s'
        place_holders = ','.join((placeholder,) * len(log_id_list))
        sql = "delete from general_logs where log_id in ( %s )" % place_holders
        params=(log_id_list)
       

        print(sql)
        result_value = 0

        try:
            result_value = cur.execute(sql,params)
            self.mysql.commit()
            cur.close()
        except Exception as err:
            print(err)
            return 0

        return result_value


    def delete_snort_logs_by_id(self, log_id_list):
        cur = self.mysql.cursor(prepared=True)

        placeholder = '%s'
        place_holders = ','.join((placeholder,) * len(log_id_list))

        sql = """delete from nids_logs where nids_log_id in (%s)""" % place_holders
        params=(log_id_list)
        print(sql)
        result_value = 0

        try:
            result_value = cur.execute(sql,params)
            self.mysql.commit()
            cur.close()
        except Exception as err:
            print(err)
            return 0

        return result_value

    
    def delete_session_logs_by_id(self, log_id_list):
        cur = self.mysql.cursor(prepared=True)

        placeholder = '%s'
        place_holders = ','.join((placeholder,) * len(log_id_list))

        sql = """delete from session_logs where session_log_id in (%s)""" % place_holders
        params=(log_id_list)
        print(sql)

        result_value = 0

        try:
            result_value = cur.execute(sql,params)
            self.mysql.commit()
            cur.close()
        except Exception as err:
            print(err)
            return 0

        return result_value

    
    def delete_vt_logs_by_id(self, log_id_list):
        cur = self.mysql.cursor(prepared=True)

        placeholder = '%s'
        place_holders = ','.join((placeholder,) * len(log_id_list))

        sql = """delete from virus_total_logs where id in (%s)""" % place_holders
        params=(log_id_list)
        print(sql)

        result_value = 0

        try:
            result_value = cur.execute(sql,params)
            self.mysql.commit()
            cur.close()
        except Exception as err:
            print(err)
            return 0

        return result_value

    """
    Data correlation sql methods
    """
    def retrieve_all_general_logs_last_24_hours(self):
        json_data = {}

        # Mysql connection
        cur = self.mysql.cursor()

        sql = "SELECT * FROM general_logs where capture_date >= now() - INTERVAL 1 DAY;"
        cur.execute(sql)
        result = cur.fetchall()
        result_value = len(result)
        if result_value > 0:
            my_query = self.query_db(cur, result)
            json_data = json.dumps(my_query, default=self.myconverter)
        return json_data

    def retrieve_all_nids_logs_last_24_hours(self):
        json_data = {}

        # Mysql connection
        cur = self.mysql.cursor()

        sql = "SELECT * FROM nids_logs where `date` >= now() - INTERVAL 1 DAY;"
        cur.execute(sql)
        result = cur.fetchall()
        result_value = len(result)
        if result_value > 0:
            my_query = self.query_db(cur, result)
            json_data = json.dumps(my_query, default=self.myconverter)
        return json_data

    def retrieve_all_general_logs_date_range(self, start_date, end_date):
        json_data = {}

        # Mysql connection
        cur = self.mysql.cursor(prepared=True)

        sql = """SELECT * FROM general_logs where capture_date between %s and %s;"""
        params=(start_date, end_date, )
        cur.execute(sql, params)
        result = cur.fetchall() 
        result_value = len(result)
        if result_value > 0:
            my_query = self.query_db(cur, result)
            json_data = json.dumps(my_query, default=self.myconverter)
        return json_data

    def retrieve_all_nids_logs_date_range(self, start_date, end_date):
        json_data = {}

        # Mysql connection
        cur = self.mysql.cursor(prepared=True)

        sql = """SELECT * FROM nids_logs where `date` between %s and %s;"""
        params=(start_date, end_date, )
        cur.execute(sql, params)
        result = cur.fetchall()
        result_value = len(result)
        if result_value > 0:
            my_query = self.query_db(cur, result)
            json_data = json.dumps(my_query, default=self.myconverter)
        return json_data

    def check_user_exists(self, email):
    
        json_data = {}

        cur = self.mysql.cursor(prepared=True)

        sql = """select * from user where name=%s"""
        params=(email, )
        # cur.execute(sql)
        
        cur.execute(sql, params)
        result = cur.fetchall()
        result_value = len(result)
        if result_value > 0:
            my_query = self.query_db(cur, result)
            json_data = json.dumps(my_query, default=self.myconverter)
        else:
            json_data = "{}"

        return json_data

    def update_password(self, password, email):
        
        cur = self.mysql.cursor(prepared=True)

        sql = """update user set \
            password=%s where email=%s"""
        params=(password, email)

        result_value = 0

        try:
            result_value = cur.execute(sql,params)
            self.mysql.commit()
            cur.close()
        except Exception as err:
            print(err)

        return result_value

    def insert_user(self, email, name, password):
    
        cur = self.mysql.cursor(prepared=True)

        sql = """insert into user(email, name, password) \
            values(%s, %s, %s)"""
        params=(email, name, password)

        result_value = 0

        try:
            result_value = cur.execute(sql,params)
            self.mysql.commit()
            cur.close()
        except Exception as err:
            print(err)

        return result_value

    def print_test_results(self):
        
        now = datetime.datetime.now()

        vt_log_test_json = {
            "id": 89,
            "scan_id": "f9bb340fcf275e76c4b45574cf96f2d9bbdc3c4853d9bc626df9913679d8b7b0-1597215113",
            "md5": "f212da551d6d584124731c9b93d8515c",
            "sha1": "9af3df4a5f7c2e71beb3212110195cec23525acc",
            "sha256": "f9bb340fcf275e76c4b45574cf96f2d9bbdc3c4853d9bc626df9913679d8b7b0",
            "scan_date": "2020-08-12 06:51:53",
            "permalink": "https://www.virustotal.com/gui/file/f9bb340fcf275e76c4b45574cf96f2d9bbdc3c4853d9bc626df9913679d8b7b0/detection/f-f9bb340fcf275e76c4b45574cf96f2d9bbdc3c4853d9bc626df9913679d8b7b0-1597215113",
            "positives": 55,
            "total": 70,
            "scans": {"AVG": {"result": "Win32:Trojan-gen", "update": "20200812", "version": "18.4.3895.0", "detected": True}, "CMC": {"result": None, "update": "20200811", "version": "2.7.2019.1", "detected": False}, "MAX": {"result": "malware (ai score=100)", "update": "20200812", "version": "2019.9.16.1", "detected": True}, "APEX": {"result": None, "update": "20200810", "version": "6.58", "detected": False}, "Bkav": {"result": None, "update": "20200812", "version": "1.3.0.9899", "detected": False}, "K7GW": {"result": "Trojan ( 000017c51 )", "update": "20200812", "version": "11.129.34967", "detected": True}, "ALYac": {"result": "Generic.Malware.GSk.61507CC5", "update": "20200812", "version": "1.1.1.5", "detected": True}, "Avast": {"result": "Win32:Trojan-gen", "update": "20200814", "version": "18.4.3895.0", "detected": True}, "Avira": {"result": "BDS/Haxor.A.2", "update": "20200811", "version": "8.3.3.8", "detected": True}, "Baidu": {"result": None, "update": "20190318", "version": "1.0.0.2", "detected": False}, "Cynet": {"result": "Malicious (score: 100)", "update": "20200811", "version": "4.0.0.24", "detected": True}, "Cyren": {"result": "W32/Risk.GDOV-6887", "update": "20200812", "version": "6.3.0.2", "detected": True}, "DrWeb": {"result": "BackDoor.Generic.288", "update": "20200812", "version": "7.0.46.3050", "detected": True}, "GData": {"result": "Generic.Malware.GSk.61507CC5", "update": "20200812", "version": "A:25.26571B:27.19773", "detected": True}, "Panda": {"result": "Bck/Haxor", "update": "20200811", "version": "4.6.4.2", "detected": True}, "VBA32": {"result": "Backdoor.Haxor", "update": "20200811", "version": "4.4.1", "detected": True}, "VIPRE": {"result": "Trojan.Win32.Generic!BT", "update": "20200812", "version": "85872", "detected": True}, "Zoner": {"result": None, "update": "20200812", "version": "0.0.0.0", "detected": False}, "ClamAV": {"result": None, "update": "20200810", "version": "0.102.4.0", "detected": False}, "Comodo": {"result": "Backdoor.Win32.Haxor.10@4bdz", "update": "20200728", "version": "32668", "detected": True}, "F-Prot": {"result": "W32/Malware!673d", "update": "20200812", "version": "4.7.1.166", "detected": True}, "Ikarus": {"result": "Trojan.Win32.Haxor", "update": "20200811", "version": "0.1.5.2", "detected": True}, "McAfee": {"result": "Generic BackDoor.b", "update": "20200812", "version": "6.0.6.653", "detected": True}, "Rising": {"result": "Backdoor.Haxor.a (CLOUD)", "update": "20200812", "version": "25.0.0.26", "detected": True}, "Sophos": {"result": "Troj/Haxor", "update": "20200812", "version": "4.98.0", "detected": True}, "Yandex": {"result": "Backdoor.Haxor!vBscqTx2V4M", "update": "20200707", "version": "5.5.2.24", "detected": True}, "Zillya": {"result": "Backdoor.Haxor.Win32.1", "update": "20200810", "version": "2.0.0.4151", "detected": True}, "Acronis": {"result": None, "update": "20200806", "version": "1.1.1.77", "detected": False}, "Alibaba": {"result": "Backdoor:Win32/Haxor.479f8077", "update": "20190527", "version": "0.3.0.5", "detected": True}, "Arcabit": {"result": "Generic.Malware.GSk.61507CC5", "update": "20200812", "version": "1.0.0.877", "detected": True}, "Cylance": {"result": "Unsafe", "update": "20200812", "version": "2.3.1.101", "detected": True}, "Elastic": {"result": None, "update": "20200727", "version": "4.0.6", "detected": False}, "FireEye": {"result": "Generic.Malware.GSk.61507CC5", "update": "20200812", "version": "32.36.1.0", "detected": True}, "Sangfor": {"result": "Malware", "update": "20200423", "version": "1.0", "detected": True}, "TACHYON": {"result": None, "update": "20200812", "version": "2020-08-12.01", "detected": False}, "Tencent": {"result": "Win32.Backdoor.Haxor.Dziw", "update": "20200812", "version": "1.0.0.1", "detected": True}, "ViRobot": {"result": "Backdoor.Win32.Haxor.37376", "update": "20200812", "version": "2014.3.20.0", "detected": True}, "Webroot": {"result": "W32.Trojan.Trojan-Backdoor.Gen.", "update": "20200812", "version": "1.0.0.403", "detected": True}, "eGambit": {"result": "Generic.Malware", "update": "20200812", "version": None, "detected": True}, "Ad-Aware": {"result": "Generic.Malware.GSk.61507CC5", "update": "20200812", "version": "3.0.5.370", "detected": True}, "AegisLab": {"result": "Trojan.Win32.Haxor.4!c", "update": "20200812", "version": "4.2", "detected": True}, "Emsisoft": {"result": "Generic.Malware.GSk.61507CC5 (B)", "update": "20200812", "version": "2018.12.0.1641", "detected": True}, "F-Secure": {"result": "Backdoor.BDS/Haxor.A.2", "update": "20200812", "version": "12.0.86.52", "detected": True}, "Fortinet": {"result": "W32/Haxor.A!tr.bdr", "update": "20200812", "version": "6.2.142.0", "detected": True}, "Invincea": {"result": None, "update": "20200502", "version": "6.3.6.26157", "detected": False}, "Jiangmin": {"result": "Backdoor/Haxor", "update": "20200812", "version": "16.0.100", "detected": True}, "Kingsoft": {"result": None, "update": "20200812", "version": "2013.8.14.323", "detected": False}, "Paloalto": {"result": "generic.ml", "update": "20200812", "version": "1.0", "detected": True}, "Symantec": {"result": "W32.Gosys", "update": "20200811", "version": "1.11.0.0", "detected": True}, "AhnLab-V3": {"result": "Win-Trojan/Mediag.37376", "update": "20200811", "version": "3.18.1.10026", "detected": True}, "Antiy-AVL": {"result": "Trojan[Backdoor]/Win32.Haxor", "update": "20200812", "version": "3.0.0.1", "detected": True}, "Kaspersky": {"result": "Backdoor.Win32.Haxor", "update": "20200812", "version": "15.0.1.13", "detected": True}, "Microsoft": {"result": "Backdoor:Win32/Haxor", "update": "20200812", "version": "1.1.17300.4", "detected": True}, "Qihoo-360": {"result": "Win32/Backdoor.d96", "update": "20200812", "version": "1.0.0.1120", "detected": True}, "ZoneAlarm": {"result": "Backdoor.Win32.Haxor", "update": "20200812", "version": "1.0", "detected": True}, "Cybereason": {"result": "malicious.51d6d5", "update": "20190616", "version": "1.2.449", "detected": True}, "ESET-NOD32": {"result": "Win32/Haxor.10", "update": "20200812", "version": "21808", "detected": True}, "TrendMicro": {"result": "BKDR_HAXOR.A", "update": "20200812", "version": "11.0.0.1006", "detected": True}, "BitDefender": {"result": "Generic.Malware.GSk.61507CC5", "update": "20200812", "version": "7.2", "detected": True}, "CrowdStrike": {"result": None, "update": "20190702", "version": "1.0", "detected": False}, "K7AntiVirus": {"result": "Trojan ( 000017c51 )", "update": "20200812", "version": "11.129.34967", "detected": True}, "SentinelOne": {"result": None, "update": "20200725", "version": "4.4.0.0", "detected": False}, "Malwarebytes": {"result": None, "update": "20200812", "version": "3.6.4.335", "detected": False}, "TotalDefense": {"result": "Win32/Tnega.PcSZMIB", "update": "20200812", "version": "37.1.62.1", "detected": True}, "CAT-QuickHeal": {"result": "Backdoor.Haxor", "update": "20200812", "version": "14.00", "detected": True}, "NANO-Antivirus": {"result": "Trojan.Win32.Haxor-Bd.fgtz", "update": "20200812", "version": "1.0.134.25119", "detected": True}, "BitDefenderTheta": {"result": "AI:Packer.2795E7D51C", "update": "20200805", "version": "7.2.37796.0", "detected": True}, "MicroWorld-eScan": {"result": "Generic.Malware.GSk.61507CC5", "update": "20200812", "version": "14.0.409.0", "detected": True}, "SUPERAntiSpyware": {"result": None, "update": "20200807", "version": "5.6.0.1032", "detected": False}, "TrendMicro-HouseCall": {"result": "BKDR_HAXOR.A", "update": "20200812", "version": "10.0.0.1040", "detected": True}},
            "zipped_file_path": "test-dionaea_malware_files/bcb7deb3-df9d-4f32-a7c7-6ab9649d6dad/2021-02-03 17:39:09_f212da551d6d584124731c9b93d8515c.zip",
            "time_at_file_received":"2021-02-03 17:39:14",
            "token": "bcb7deb3-df9d-4f32-a7c7-6ab9649d6dad",
            "response_code": 1,
            "zipped_file_password":"test-honeyid$" 
        }

        vt_log_file_path_test_json = {
            "md5": "f212da551d6d584124731c9b93d8515c",
            "zipped_file_path": "test-log-file-dionaea_malware_files/bcb7deb3-df9d-4f32-a7c7-6ab9649d6dad/2021-02-03 17:39:09_f212da551d6d584124731c9b93d8515c.zip",
            "time_at_file_received":"2021-02-03 17:39:14",
            "token": "bcb7deb3-df9d-4f32-a7c7-6ab9649d6dad",
            "response_code": 1,
            "zipped_file_password":"test-log-file-honeyid$" 
        }

        general_logs_test_json =  {
            "capture_date": "2021-02-03 17:38:28",
            "honeynode_name": "HoneyNode-1-Cowrie",
            "source_ip": "192.168.148.128",
            "source_port": 40900,
            "destination_ip": "192.168.148.167",
            "destination_port": 22,
            "protocol": "tcp",
            "token": "49a0445c-738c-4176-9588-4236676e9d39",
            "raw_logs": {
                "urls": [],
                "hashes": [],
                "hostIP": "192.168.148.167",
                "peerIP": "192.168.148.128",
                "ttylog": "010000000000000000000000000000002ca30d60c314080003000000000000001e010000020000002ca30d60c41508000a5468652070726f6772616d7320696e636c756465642077697468207468652044656269616e20474e552f4c696e75782073797374656d20617265206672656520736f6674776172653b0a74686520657861637420646973747269627574696f6e207465726d7320666f7220656163682070726f6772616d206172652064657363726962656420696e207468650a696e646976696475616c2066696c657320696e202f7573722f73686172652f646f632f2a2f636f707972696768742e0a0a44656269616e20474e552f4c696e757820636f6d65732077697468204142534f4c5554454c59204e4f2057415252414e54592c20746f2074686520657874656e740a7065726d6974746564206279206170706c696361626c65206c61772e0a030000000000000004000000020000002ca30d609b1808001b5b346803000000000000000f000000020000002ca30d6000190800726f6f74407365727665723a7e2320030000000000000001000000010000002ca30d602d570e006c030000000000000001000000020000002ca30d607b570e006c030000000000000001000000010000002da30d608dce000073030000000000000001000000020000002da30d6016cf000073030000000000000001000000010000002da30d60565a03000d030000000000000001000000020000002da30d60a55a03000a030000000000000004000000020000002da30d60a25e03001b5b346c030000000000000004000000020000002da30d60aa5f03001b5b346803000000000000000f000000020000002da30d6043600300726f6f74407365727665723a7e2320030000000000000001000000010000002da30d60c2ca090077030000000000000001000000020000002da30d601ccc090077030000000000000001000000010000002da30d6001c30b0068030000000000000001000000020000002da30d60b2c30b0068030000000000000001000000010000002da30d60ff200f006f030000000000000001000000020000002da30d6049210f006f030000000000000001000000010000002ea30d602d9e040061030000000000000001000000020000002ea30d60769e040061030000000000000001000000010000002ea30d60a47206006d030000000000000001000000020000002ea30d60007306006d030000000000000001000000010000002ea30d6072a8090069030000000000000001000000020000002ea30d60bfa8090069030000000000000001000000010000002ea30d6066170d000d030000000000000001000000020000002ea30d60c8170d000a030000000000000004000000020000002ea30d60d91f0d001b5b346c030000000000000005000000020000002ea30d60b5200d00726f6f740a030000000000000004000000020000002ea30d6026210d001b5b346803000000000000000f000000020000002ea30d60c5210d00726f6f74407365727665723a7e2320030000000000000001000000010000002fa30d602926030065030000000000000001000000020000002fa30d607f28030065030000000000000001000000010000002fa30d60ffaf060078030000000000000001000000020000002fa30d6057b0060078030000000000000001000000010000002fa30d602576080069030000000000000001000000020000002fa30d606d76080069030000000000000001000000010000002fa30d60f7960b0074030000000000000001000000020000002fa30d60a8970b0074030000000000000001000000010000002fa30d6060300f000d030000000000000001000000020000002fa30d60cd300f000a030000000000000004000000020000002fa30d6060350f001b5b346c020000000000000000000000000000002fa30d604c370f00",
                "endTime": "2021-02-03T17:38:28.708987+0800",
                "session": "83f0561e8b18",
                "version": "SSH-2.0-OpenSSH_8.3p1 Debian-1",
                "commands": [
                    "ls",
                    "whoami",
                    "exit"
                ],
                "hostPort": 22,
                "loggedin": [
                    "root",
                    "cherry"
                ],
                "peerPort": 40900,
                "protocol": "ssh",
                "startTime": "2021-02-03T17:38:20.455924+0800",
                "credentials": [],
                "unknownCommands": []
            }
        }

        session_logs_test_json =  {
            "token": "49a0445c-738c-4176-9588-4236676e9d39",
            "honeynode_name": "HoneyNode-1-Cowrie",
            "source_ip": "192.168.148.128",
            "source_port": 40900,
            "destination_ip": "192.168.148.167",
            "destination_port": 22,
            "commands": ["ls", "whoami", "exit"],
            "logged_in": ["root", "cherry"],
            "start_time":"2021-02-03 17:38:20",
            "end_time": "2021-02-03 17:38:28",
            "session": "83f0561e8b18",
            "urls": [],
            "credentials": [],
            "hashes": [],
            "version": "SSH-2.0-OpenSSH_8.3p1 Debian-1",
            "unknown_commands": []
        }

        nids_logs_test_json =  {
            "nids_type": "snort",
            "date": "2021-02-03 17:37:59",
            "token": "49a0445c-738c-4176-9588-4236676e9d39",
            "honeynode_name": "HoneyNode-1-Cowrie",
            "source_ip": "192.168.148.128",
            "source_port": 52669,
            "destination_ip": "192.168.148.167",
            "destination_port": 443,
            "priority": 0,
            "classification": 0,
            "signature": "Connection to HTTPS port 443",
            "raw_logs": {
                "id": 10999,
                "tos": 0,
                "ttl": 44,
                "iplen": 45056,
                "proto": "TCP",
                "dgmlen": 44,
                "ethdst": "00:0C:29:59:3F:74",
                "ethlen": "0x3C",
                "ethsrc": "00:0C:29:0E:80:41",
                "header": "1:2525045:1",
                "sensor": "49a0445c-738c-4176-9588-4236676e9d39",
                "tcpack": "0x0",
                "tcplen": 24,
                "tcpseq": "0xEFDC955A",
                "tcpwin": "0x4000000",
                "ethtype": "0x800",
                "priority": 0,
                "tcpflags": "******S*",
                "signature": "Connection to HTTPS port 443",
                "source_ip": "192.168.148.128",
                "timestamp": "2021/02/03 17:37:59.124040",
                "source_port": 52669,
                "classification": 0,
                "destination_ip": "192.168.148.167",
                "destination_port": 443
            }
        }

        existing_user_test_json =  {
            "id": 3,
            "email": "admin_1@example.com",
            "name": "admin_1",
            "password": "sha256$ab5Rf5o4$c5669dcab78e0bc436923b2ef5f144a8cb9662721b53d54f7234e58cdb47613a",
        }

        new_user_test_json =  {
            "email": "admin_3@example.com",
            "name": "admin_3",
            "password": "sha256$ab78f12o4$c5669dcab78e0bc436923b2ef5f144a8cb9662721b53d54f7234e58cdb47613a",
        }

        brute_force_log_test_json = {
            "token": "49a0445c-738c-4176-9588-4236676e9d39",
            "source_ip": "192.168.148.128",
            "start_time":"2021-02-03 17:38:20",
            "end_time": "2021-02-03 17:38:28",
            "credentials": []
        }


        create_node_test_json = {"honeynode_name": "HoneyNode-2-Drupot-test-create", "ip_addr": "192.168.148.200", "subnet_mask": "255.255.255.0", "honeypot_type": "drupot-test-create", "nids_type": "snort-test-create", "no_of_attacks": 0, "date_deployed": now.strftime('%Y-%m-%d %H:%M:%S'), "heartbeat_status": "False", "token": "51552ecf-g54c-4f6c-b97e-8506d3333a63", "last_heard": now.strftime('%Y-%m-%d %H:%M:%S')}
        update_node_test_json = {"honeynode_name": "HoneyNode-2-Drupot-test-update", "ip_addr": "192.168.148.200", "subnet_mask": "255.255.255.0", "honeypot_type": "drupot-test-update", "nids_type": "snort-test", "no_of_attacks": 0, "date_deployed": "2021-01-24 17:44:34", "heartbeat_status": "False", "token": "51552ecf-g54c-4f6c-b97e-8506d3333a63", "last_heard": "2021-01-30 21:08:15"}
        update_node_heartbeat_status_test_json = {"honeynode_name": "HoneyNode-2-Drupot-test-update", "ip_addr": "192.168.148.200", "subnet_mask": "255.255.255.0", "honeypot_type": "drupot-test-update", "nids_type": "snort-test", "no_of_attacks": 0, "date_deployed": "2021-01-24 17:44:34", "heartbeat_status": "True", "token": "51552ecf-g54c-4f6c-b97e-8506d3333a63", "last_heard": "2021-01-30 21:08:15"}
        
        retrieve_node_token = '49a0445c-738c-4176-9588-4236676e9d39'
        update_token = '51552ecf-g54c-4f6c-b97e-8506d3333a63'


        general_log_id_list = [4, 5]
        snort_log_id_list = [30573, 30574, 30575, 30576, 30578]
        session_log_id_list = [17, 19]
        vt_log_id_list = [90, 92]
        general_logs_start_date, general_logs_end_date = "2021-02-03 17:38:28", "2021-02-03 17:38:56"
        nid_logs_start_date, nid_logs_end_date = "2021-02-03 17:37:59", "2021-02-03 17:38:20"

        output1 = self.retrieve_all_active_nodes()
        output2 = self.retrieve_all_nodes()
        output3 = self.retrieve_all_general_logs()
        output4 = self.retrieve_all_virus_total_logs()
        output5 = self.retrieve_all_nids_logs()
        output6 = self.retrieve_all_session_logs()
        output7 = self.retrieve_all_nodes_for_heartbeat()
        output8 = self.retrieve_node(retrieve_node_token)
        output9 = self.create_node(create_node_test_json)
        output10 = self.update_node(update_node_test_json, update_token)
        # output11 = self.update_node_heartbeat_status(update_node_heartbeat_status_test_json, update_token)
        output12 = self.delete_node(update_token)
        output13 = self.insert_vt_log(vt_log_test_json)
        output14 = self.insert_vt_log_file_path(vt_log_file_path_test_json)
        output15 = self.insert_general_log(general_logs_test_json)
        output16 = self.insert_snort_log(nids_logs_test_json)
        output17 = self.insert_session_log(session_logs_test_json)
        output18 = self.update_bruteforce_log(brute_force_log_test_json)
        output19 = self.delete_general_logs_by_id(general_log_id_list)
        output20 = self.delete_snort_logs_by_id(snort_log_id_list)
        output21 = self.delete_session_logs_by_id(session_log_id_list)
        output22 = self.delete_vt_logs_by_id(vt_log_id_list)
        output23 = self.retrieve_all_general_logs_last_24_hours()
        output24 = self.retrieve_all_nids_logs_last_24_hours()
        output25 = self.retrieve_all_general_logs_date_range(general_logs_start_date, general_logs_end_date)
        output26 = self.retrieve_all_nids_logs_date_range(nid_logs_start_date, nid_logs_end_date)
        output27 = self.check_user_exists(existing_user_test_json["name"])
        output28 = self.update_password(existing_user_test_json["password"], existing_user_test_json["email"])
        output29 = self.insert_user(new_user_test_json['email'], new_user_test_json['name'], new_user_test_json['password'])

        print(output1)
        print('----------------------------------------------')
        print(output2)
        print('----------------------------------------------')
        print(output3)
        print('----------------------------------------------')
        print(output4)
        print('----------------------------------------------')
        print(output5)
        print('----------------------------------------------')
        print(output6)
        print('----------------------------------------------')
        print(output7)
        print('----------------------------------------------')
        print(output8)
        print('----------------------------------------------')
        print(output9)
        print('----------------------------------------------')
        print(output10)
        # print('----------------------------------------------')
        # print(output11)
        print('----------------------------------------------')
        print(output12)
        print('----------------------------------------------')
        print(output13)
        print('----------------------------------------------')
        print(output14)
        print('----------------------------------------------')
        print(output15)
        print('----------------------------------------------')
        print(output16)
        print('----------------------------------------------')
        print(output17)
        print('----------------------------------------------')
        print(output18)
        print('----------------------------------------------')
        print(output19)
        print('----------------------------------------------')
        print(output20)
        print('----------------------------------------------')
        print(output21)
        print('----------------------------------------------')
        print(output22)
        print('----------------------------------------------')
        print(output23)
        print('----------------------------------------------')
        print(output24)
        print('----------------------------------------------')
        print(output25)
        print('----------------------------------------------')
        print(output26)
        print('----------------------------------------------')
        print(output27)
        print('----------------------------------------------')
        print(output28)
        print('----------------------------------------------')
        print(output29)
        print('----------------------------------------------')
        print

app = Flask(__name__,
            static_url_path='', 
            static_folder='static',
            template_folder='templates')
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'
import os,yaml
from HpfeedsDB import *
from gevent.pywsgi import WSGIServer
basedir = os.path.abspath(os.path.dirname(__file__))

# Configure DB
db = yaml.load(open(os.path.join(basedir, 'db.yaml')), Loader=yaml.SafeLoader)
app.config['MYSQL_HOST'] = db['mysql_host']
app.config['MYSQL_USER'] = db['mysql_user']
app.config['MYSQL_PASSWORD'] = db['mysql_password']
app.config['MYSQL_DB'] = db['mysql_db']
app.config['HPFEEDS_DATABASE_PATH'] = os.path.join(basedir, 'sqlite.db')

# run hpfeeds broker, this will also create the sqlite.db file in the current dir if it doesn't exist
# hpfeeds_broker_process = subprocess.Popen(["hpfeeds-broker", "-e", "tcp:port=10000"], stdout=subprocess.PIPE, cwd=basedir)

# Initialize mysql connection
mysql_connection=mysql.connector.connect(host=db['mysql_host'],
            database=db['mysql_db'],
            user=db['mysql_user'],
            password=db['mysql_password'])

# Initialise Database
db_access = DbAccess(app, mysql_connection)
hpfeeds_db = HPfeedsDB(app.config['HPFEEDS_DATABASE_PATH'])
http_server = WSGIServer(('0.0.0.0', 5000), app)
 
db_access.print_test_results()

