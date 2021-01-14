import watchdog.events 
import watchdog.observers 
import time
import requests
import json
import base64
import hashlib
from datetime import datetime
from configparser import ConfigParser
import os
from pathlib import Path


DIONAEA_BINARY_FOLDER_PATH = r"/opt/dionaea/var/lib/dionaea/binaries"
DIONAEA_FTP_FOLDER_PATH = r"/opt/dionaea/var/lib/dionaea/ftp/root"
HONEY_AGENT_CONFIG_PATH	= r"/opt/honeyagent/honeyagent.conf"

config = ConfigParser()
config.read(HONEY_AGENT_CONFIG_PATH)
TOKEN = config['HONEYNODE']['TOKEN']
WEB_SERVER_IP = config['WEB-SERVER']['SERVER_IP']
WEB_SERVER_PORT = config['WEB-SERVER']['PORT']
API_ENDPOINT_URL = "http://{0}:{1}/api/v1/dionaea-binary-upload".format(WEB_SERVER_IP, WEB_SERVER_PORT)


def md5(fname):
    hash_md5 = hashlib.md5()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()
  
  
class Handler(watchdog.events.PatternMatchingEventHandler): 
    def __init__(self, pattern): 
        # Set the patterns for PatternMatchingEventHandler
        self.pattern = pattern
        watchdog.events.PatternMatchingEventHandler.__init__(self, patterns=self.pattern, 
                                                             ignore_directories=True, case_sensitive=False) 
  
    def on_created(self, event):
        if not "httpupload" in event.src_path:
            print("Watchdog received created event - % s" % event.src_path)

            with open(event.src_path, 'rb') as malware_file:
                malware_file_base64 = base64.b64encode(malware_file.read())

            malware_file_base64_string = malware_file_base64.decode('utf-8')

            data = {
                    'file': malware_file_base64_string, 
                    'token': TOKEN, 
                    'time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"), 
                    'md5': md5(event.src_path)
                }

            try:
                headers = {'content-type': 'application/json'}
                r = requests.post(API_ENDPOINT_URL, data=json.dumps(data), headers=headers)
                print(r.text)

            finally:
                malware_file.close()
                parent_path = str(Path(event.src_path).parent)
                file_list = [f for f in os.listdir(parent_path)]
                for f in file_list:
                    os.remove(os.path.join(parent_path, f))
  
  
if __name__ == "__main__": 
    try: 
       event_handler = Handler(['*'])
       observer = watchdog.observers.Observer() 
       observer.schedule(event_handler, path=DIONAEA_BINARY_FOLDER_PATH, recursive=True)
       observer.schedule(event_handler, path=DIONAEA_FTP_FOLDER_PATH, recursive=True) 
       observer.start() 
    except KeyboardInterrupt: 
        observer.stop() 
    observer.join() 
