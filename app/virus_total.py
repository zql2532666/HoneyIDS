"""
Authon: Derek, Thein Than Zaw
"""

"""

{
    'response_code': 0, 
    'resource': 'a016ca19343494fda64f32323bdb3d27', 
    'verbose_msg': 'The requested resource is not among the finished, queued or pending scans'
}

{
 'response_code': 1,
 'verbose_msg': 'Scan finished, scan information embedded in this object',
 'resource': '99017f6eebbac24f351415dd410d522d',
 'scan_id': '52d3df0ed60c46f336c131bf2ca454f73bafdc4b04dfa2aea80746f5ba9e6d1c-1273894724',
 'md5': '99017f6eebbac24f351415dd410d522d',
 'sha1': '4d1740485713a2ab3a4f5822a01f645fe8387f92',
 'sha256': '52d3df0ed60c46f336c131bf2ca454f73bafdc4b04dfa2aea80746f5ba9e6d1c',
 'scan_date': '2010-05-15 03:38:44',
 'permalink': 'https://www.virustotal.com/file/52d3df0ed60c46f336c131bf2ca454f73bafdc4b04dfa2aea80746f5ba9e6d1c/analysis/1273894724/',
 'positives': 40,
 'total': 40,
 'scans': {
   'nProtect': {
     'detected': true, 
     'version': '2010-05-14.01', 
     'result': 'Trojan.Generic.3611249', 
     'update': '20100514'
   },
   'CAT-QuickHeal': {
     'detected': true, 
     'version': '10.00', 
     'result': 'Trojan.VB.acgy', 
     'update': '20100514'
   },
   'McAfee': {
     'detected': true, 
     'version': '5.400.0.1158', 
     'result': 'Generic.dx!rkx', 
     'update': '20100515'
   },
   'TheHacker': {
     'detected': true, 
     'version': '6.5.2.0.280', 
     'result': 'Trojan/VB.gen', 
     'update': '20100514'
   },   
   'VirusBuster': {
    'detected': true,
     'version': '5.0.27.0',
     'result': 'Trojan.VB.JFDE',
     'update': '20100514'
   }
 }
}

"""

import requests, argparse, os, time, json, hashlib
API_KEY='a4285326b887ff18976ba19661911b61d4833cf4943238413f957c19f0770d6d'
# REQUEST FUNCTION
def vt_request(hash,key=API_KEY) :
	parameters = {"apikey": key, "resource": hash}
	url = requests.get("https://www.virustotal.com/vtapi/v2/file/report", params=parameters)
	json_response = url.json()
	# response = int(json_response.get("response_code"))
	# print(json_response)
	# print("\n\n")
	return json_response
	
	# DOES THE HASH EXISTS IN VT DATABASE?
	# if response == 0:
	# 	print(hash + ": UNKNOWN")

	# # DOES THE HASH EXISTS IN VT DATABASE?
	# elif response == 1:
	# 	positives = int(json_response.get("positives"))
	# 	if positives >= 3:
	# 		print(hash + ": MALICIOUS")
	# 	else:
	# 		print(hash + ": NOT MALICIOUS")
	# else:
	# 	print(hash + ": CAN NOT BE SEARCHED")

# def md5(fname):
#     hash_md5 = hashlib.md5()
#     with open(fname, "rb") as f:
#         for chunk in iter(lambda: f.read(4096), b""):
#             hash_md5.update(chunk)
#     return hash_md5.hexdigest()

# def main():
# 	hash = md5("sample_87.exe")
# 	vt_request(hash)

# if __name__ == "__main__":
# 	main()