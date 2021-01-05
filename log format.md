# Honeypot Log Formats

## Cowrie

### Session logs
```json
{
  "peerIP": "192.168.148.146", 
  "commands": ["ifconfig", "ls", "whoami", "cat /etc/passwd", "ls", "hello", "idk", "exit"], 
  "loggedin": ["root", "password"], 
  "protocol": "ssh", 
  "startTime": "2020-11-19T07:01:31.752063Z", 
  "ttylog": "010000000000000000000000000000004e18b65f48d50b0003000000000000001e010........", 
  "hostIP": "192.168.148.148", 
  "peerPort": 43250, 
  "session": "df81514de4f2", 
  "urls": [], 
  "hostPort": 22, 
  "credentials": [], 
  "hashes": [], 
  "endTime": "2020-11-19T07:02:24.197533Z", 
  "version": "\'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1\'", 
  "unknownCommands": ["hello", "idk"]
}
```
<br>

### SSH bruteforce log
#### bruteforce command used 
```bash
sudo hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://192.168.148.146 -t 4
```
```json
{
   "peerIP":"192.168.148.128",
   "commands":[
      
   ],
   "loggedin":"None",
   "protocol":"ssh",
   "startTime":"2020-12-24T14:31:30.187541Z",
   "ttylog":"None",
   "hostIP":"192.168.148.150",
   "peerPort":39610,
   "session":"350f7cf9ca02",
   "urls":[
      
   ],
   "hostPort":22,
   "credentials":[
      [
         "root",
         "password"
      ],
      [
         "root",
         "rockyou"
      ],
      [
         "root",
         "daniel"
      ],
      [
         "root",
         "jessica"
      ],
      [
         "root",
         "qwerty"
      ],
      [
         "root",
         "michelle"
      ],
      [
         "root",
         "password1"
      ],
      [
         "root",
         "butterfly"
      ],
      [
         "root",
         "liverpool"
      ],
      [
         "root",
         "123123"
      ],
      [
         "root",
         "carlos"
      ],
      [
         "root",
         "1234567890"
      ],
      [
         "root",
         "loveyou"
      ],
      [
         "root",
         "angels"
      ],
      [
         "root",
         "hello"
      ],
      [
         "root",
         "charlie"
      ],
      [
         "root",
         "lovers"
      ],
      [
         "root",
         "666666"
      ],
      [
         "root",
         "matthew"
      ],
      [
         "root",
         "family"
      ],
      [
         "root",
         "whatever"
      ]
   ],
   "hashes":[
      
   ],
   "endTime":"2020-12-24T14:31:51.443015Z",
   "version":"'SSH-2.0-libssh_0.9.3'",
   "unknownCommands":[
      
   ]
}
```

## Snort
```json
{
   "sensor": "snort", 
   "iplen": 45056, 
   "proto": "TCP", 
   "timestamp": "2020/11/19 14:52:14.608069", 
   "signature": "ET SCAN Suspicious inbound to mySQL port 3306", 
   "header": "1:2010937:3", "ttl": 53, 
   "ethlen": "0x3C", 
   "ethtype": "0x800", 
   "destination_port": 3306, 
   "tcpack": "0x0", 
   "classification": 3, 
   "priority": 2, 
   "source_port": 54160, 
   "id": 4633, 
   "source_ip": "192.168.148.146", 
   "destination_ip": "192.168.148.148", 
   "tos": 0, "dgmlen": 44, 
   "ethdst": "00:0C:29:3B:AF:4B", 
   "ethsrc": "00:0C:29:1C:81:D5", 
   "tcpseq": "0x4FAD5D2E", 
   "tcpflags": "******S*", 
   "tcpwin": "0x4000000", 
   "tcplen": 24
}
```
<br>

## Elastichoney

```json
{
   "source":"192.168.148.146",
   "@timestamp":"2020-11-20T23:16:09.481527978+08:00",
   "url":"192.168.148.149:9200/_search?pretty",
   "method":"POST",
   "form":"pretty=&%7B%0A%09%09%09%22script_fields%22%3A+%7B%0A%09%09%09%09%22myscript%22%3A+%7B%0A%09%09%09%09%09%22script%22%3A+%22java.lang.Math.class.forName%28%5C%22java.lang.Runtime%5C%22%29.getRuntime%28%29.exec%28%5C%22whoami%5C%22%29.getText%28%29%22%0A%09%09%09%09%7D%0A%09%09%09%7D%0A%09%09%7D=",
   "payload":"",
   "payloadCommand":"",
   "payloadResource":"",
   "payloadMd5":"",
   "payloadBinary":"",
   "headers":{
      "user_agent":"curl/7.68.0",
      "host":"192.168.148.149:9200",
      "content_type":"application/x-www-form-urlencoded",
      "accept_language":""
   },
   "type":"attack",
   "honeypot":"218.212.205.87"
}
```
<br>


## Wordpot
```json
{
   "username":"admin",
   "plugin":"badlogin",
   "url":"http://localhost/wp-login.php",
   "source_ip":"127.0.0.1",
   "user_agent":"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:79.0) Gecko/20100101 Firefox/79.0",
   "source_port":41622,
   "password":"admin",
   "dest_ip":"0.0.0.0",
   "dest_port":"80"
}
```
<br>


## Drupot

```json
{
   "protocol":"HTTP/1.1",
   "app":"agave",
   "agave_app":"Drupot",
   "channel":"agave.events",
   "sensor":"8016308d-2a4c-11eb-8395-000c29aace21",
   "dest_port":80,
   "dest_ip":"218.212.205.87",
   "src_port":38478,
   "src_ip":"127.0.0.1",
   "signature":"",
   "prev_seen":false,
   "request_json":{
      "Method":"GET",
      "URL":{
         "Scheme":"",
         "Opaque":"",
         "User":null,
         "Host":"",
         "Path":"/search/node",
         "RawPath":"",
         "ForceQuery":false,
         "RawQuery":"keys=test",
         "Fragment":"",
         "RawFragment":""
      },
      "Proto":"HTTP/1.1",
      "ProtoMajor":1,
      "ProtoMinor":1,
      "Header":{
         "Accept":[
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"
         ],
         "Accept-Encoding":[
            "gzip, deflate"
         ],
         "Accept-Language":[
            "en-US,en;q=0.5"
         ],
         "Connection":[
            "keep-alive"
         ],
         "Referer":[
            "http://localhost/"
         ],
         "Upgrade-Insecure-Requests":[
            "1"
         ],
         "User-Agent":[
            "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:82.0) Gecko/20100101 Firefox/82.0"
         ]
      },
      "Body":"",
      "TransferEncoding":null,
      "Host":"localhost",
      "PostForm":{
         
      }
   },
   "agave_client_version":"v0.1.2"
}
```
<br>


## Shockpot
```json
{
   "timestamp":"2020-11-20 23:35:28.594395",
   "path":"/cgi-bin/vulnerable",
   "command_data":"None",
   "dest_port":"80",
   "dest_host":"115.66.174.103",
   "url":"http://localhost/cgi-bin/vulnerable",
   "source_ip":"127.0.0.1",
   "headers":[
      [
         "Accept",
         "*/*"
      ],
      [
         "Host",
         "localhost"
      ],
      [
         "User-Agent",
         "() { :; }; echo; echo; /bin/bash -c \\'echo \"<html><body><h1>DEFACED</h1></body></html>\" > /var/www/index.html\\'"
      ],
      [
         "Content-Type",
         "text/plain"
      ],
      [
         "Content-Length",
         ""
      ]
   ],
   "is_shellshock":True,
   "command":"None",
   "query_string":"",
   "method":"GET"
}
```
<br>


## Sticky Elephant
### Connection logs (When attacker makes a connection to the database)
```json
{
   "source_ip":"192.168.148.146",
   "dest_ip":"192.168.148.149",
   "source_port":"55744",
   "dest_port":"5432",
   "raw":"[0, 0, 0, 74, 0, 3, 0, 0, 117, 115, 101, 114, 0, 100, 101, 118, 0, 100, 97, 116, 97, 98, 97, 115, 101, 0, 100, 101, 118, 0, 97, 112, 112, 108, 105, 99, 97, 116, 105, 111, 110, 95, 110, 97, 109, 101, 0, 112, 115, 113, 108, 0, 99, 108, 105, 101, 110, 116, 95, 101, 110, 99, 111, 100, 105, 110, 103, 0, 85, 84, 70, 56, 0, 0]",
   "user":"dev",
   "database":"dev",
   "application_name":"psql",
   "client_encoding":"UTF8",
   "password":"dev"
}
```

### Database query log (when attacker performs a database query after loggin in)
```json
{
   "source_ip":"192.168.148.146",
   "dest_ip":"192.168.148.149",
   "source_port":"55714",
   "dest_port":"5432",
   "raw":"[81, 0, 0, 1, 77, 83, 69, 76, 69, 67, 84, 32, 100, 46, 100, 97, 116, 110, 97, 109, 101, 32, 97, 115, 32, 34, 78, 97, 109, 101, 34, 44, 10, 32, 32, 32, 32, 32, 32, 32, 112, 103, 95, 99, 97, 116, 97, 108, 111, 103, 46, 112, 103, 95, 103, 101, 116, 95, 117, 115, 101, 114, 98, 121, 105, 100, 40, 100, 46, 100, 97, 116, 100, 98, 97, 41, 32, 97, 115, 32, 34, 79, 119, 110, 101, 114, 34, 44, 10, 32, 32, 32, 32, 32, 32, 32, 112, 103, 95, 99, 97, 116, 97, 108, 111, 103, 46, 112, 103, 95, 101, 110, 99, 111, 100, 105, 110, 103, 95, 116, 111, 95, 99, 104, 97, 114, 40, 100, 46, 101, 110, 99, 111, 100, 105, 110, 103, 41, 32, 97, 115, 32, 34, 69, 110, 99, 111, 100, 105, 110, 103, 34, 44, 10, 32, 32, 32, 32, 32, 32, 32, 100, 46, 100, 97, 116, 99, 111, 108, 108, 97, 116, 101, 32, 97, 115, 32, 34, 67, 111, 108, 108, 97, 116, 101, 34, 44, 10, 32, 32, 32, 32, 32, 32, 32, 100, 46, 100, 97, 116, 99, 116, 121, 112, 101, 32, 97, 115, 32, 34, 67, 116, 121, 112, 101, 34, 44, 10, 32, 32, 32, 32, 32, 32, 32, 112, 103, 95, 99, 97, 116, 97, 108, 111, 103, 46, 97, 114, 114, 97, 121, 95, 116, 111, 95, 115, 116, 114, 105, 110, 103, 40, 100, 46, 100, 97, 116, 97, 99, 108, 44, 32, 69, 39, 92, 110, 39, 41, 32, 65, 83, 32, 34, 65, 99, 99, 101, 115, 115, 32, 112, 114, 105, 118, 105, 108, 101, 103, 101, 115, 34, 10, 70, 82, 79, 77, 32, 112, 103, 95, 99, 97, 116, 97, 108, 111, 103, 46, 112, 103, 95, 100, 97, 116, 97, 98, 97, 115, 101, 32, 100, 10, 79, 82, 68, 69, 82, 32, 66, 89, 32, 49, 59, 0]",
   "query":"QUERY: \\'SELECT d.datname as \"Name\",\n       pg_catalog.pg_get_userbyid(d.datdba) as \"Owner\",\n       pg_catalog.pg_encoding_to_char(d.encoding) as \"Encoding\",\n       d.datcollate as \"Collate\",\n       d.datctype as \"Ctype\",\n       pg_catalog.array_to_string(d.datacl, E\\'\\n\\') AS \"Access privileges\"\nFROM pg_catalog.pg_database d\nORDER BY 1;\\'"
}
```

## Dionaea
### Connection logs
```json
{
   "connection_type":"accept",
   "connection_transport":"tcp",
   "local_port":445,
   "connection_protocol":"smbd",
   "remote_host":"192.168.148.128",
   "remote_port":36407,
   "remote_hostname":"",
   "local_host":"192.168.148.150"
}
```