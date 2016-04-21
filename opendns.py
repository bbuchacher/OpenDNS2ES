#!/usr/bin/python 

# Open DNS to Elastic Search
# Development Version 0.1 

import requests
import urllib
import math 
import uuid
import json 
import calendar
import random
from datetime import datetime, timedelta
from elasticsearch import Elasticsearch
from elasticsearch import helpers


# Time Variables  
current_time = calendar.timegm(datetime.utcnow().timetuple()) 
one_day_ago = calendar.timegm((datetime.utcnow() - timedelta(days=1)).timetuple())
one_hour_ago = calendar.timegm((datetime.utcnow() - timedelta(hours=1)).timetuple())
one_minute_ago = calendar.timegm((datetime.utcnow() - timedelta(minutes=1)).timetuple())


# Debug Burp
proxies = {
	"http" : "http://localhost:8080",
	"https" : "https://localhost:8080"
}

#Variables 
username = ''
password = ''
organizations_id = '' #Get this by looking at the URL Structure of your search activity ex https://dashboard2.opendns.com/v3/organizations/1234567/reports/activitysearch?offset=0&limit=50&filters={"filterNoisyDomains":true,"start":1440054000,"end":1440140519,"stopTimestamp":1440140519000,"categories":[56],"handlingCode":[-1]}&&outputFormat=jsonHttpStatusOverride&api-session=M7Su0Fn4wlNmwZH18XLH947O9_o&_=144014046143
search_limit = 500 # 1-500 

#Set some headers here 
headers = {
'User-Agent' : 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:39.0) Gecko/20100101 Firefox/39.0',
'Referer' : 'https://login.opendns.com/',
'Accept' : 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
'Accept-Language' : 'en-US,en;q=0.5'
}


def send_to_es(json_item):
	opendns_data = []

	# initialize a connection to multiple hosts if needed
	es = Elasticsearch(host="192.168.1.144")
	
	
	data = {
	"_index": "opendns",
	"_type": "logs",
	"_id" : ''.join(random.choice('0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ') for i in range(64)),
	"@timestamp" : datetime.utcnow(),
	"origin" : json_item['origin'],
	"domain" : json_item['domain'],
	"handlingCode" : json_item['handling'],
	"queryType" : json_item['queryType'],
	"blockCategories" : json_item['blockCategories'],
	"remoteIp" : json_item['remoteIp'],
	"clientIp" : json_item['clientIp'],
	"originType" : json_item['originType'],
	"originId" : json_item['originId'],
	"categories" : json_item['categories']
	}
	#print data
	
	opendns_data.append(data) 

	if (len(opendns_data) % 10000 == 0):
		helpers.bulk(es, opendns_data,timeout=120)
		opendns_data = []
	if len(opendns_data) > 0:
		helpers.bulk(es, opendns_data)

def parse_handling_codes(json_item):
	parsed_handling_codes = []
	if json_item['handling'] == 2049:
		parsed_code = "Allowed"
		parsed_handling_codes.append(parsed_code)
	if json_item['handling'] == 2048:
		parsed_code = "Blocked"
		parsed_handling_codes.append(parsed_code)
	if json_item['handling'] == 13:
		parsed_code = "Proxy"
		parsed_handling_codes.append(parsed_code)
	if json_item['handling'] == 15:
		parsed_code = "Allowed: Domain List"
		parsed_handling_codes.append(parsed_code)
	if json_item['handling'] == 0:
		parsed_code = "Blocked: Domain List"
		parsed_handling_codes.append(parsed_code)
	if json_item['handling'] == [0,15]:
		parsed_code = "Allowed & Blocked: Domain List"
		parsed_handling_codes.append(parsed_code)
	json_item["handling"] = parsed_handling_codes
	send_to_es(json_item)
	print json_item

def parse_categoies(json_item):
	parsed_categories = []
	for category in json_item['categories']:
		if category == 72:
			parsed_category = "Acadmeic_Fraud"
			parsed_categories.append(parsed_category)
		if category == 58:
			parsed_category = "Adult_Themes"
			parsed_categories.append(parsed_category)
		if category == 1:
			parsed_category = "Adware"
			parsed_categories.append(parsed_category)
		if category == 2:
			parsed_category = "Alcohol"
			parsed_categories.append(parsed_category)
		if category == 76:
			parsed_category = "Anime_Manga_Webcomic"
			parsed_categories.append(parsed_category)
		if category == 3:
			parsed_category = "Auctions"
			parsed_categories.append(parsed_category)
		if category == 70:
			parsed_category = "Automotive"
			parsed_categories.append(parsed_category)
		if category == 4:
			parsed_category = "Blogs"
			parsed_categories.append(parsed_category)
		if category == 56:
			parsed_category = "Business_Services"
			parsed_categories.append(parsed_category)
		if category == 5:
			parsed_category = "Chat"
			parsed_categories.append(parsed_category)
		if category == 6:
			parsed_category = "Classifieds"
			parsed_categories.append(parsed_category)
		if category == 7:
			parsed_category = "Dating"
			parsed_categories.append(parsed_category)
		if category == 8:
			parsed_category = "Drugs"
			parsed_categories.append(parsed_category)
		if category == 9:
			parsed_category = "Ecommerce_Shopping"
			parsed_categories.append(parsed_category)
		if category == 52:
			parsed_category = "Education_Institutions"
			parsed_categories.append(parsed_category)
		if category == 10:
			parsed_category = "File_Storage"
			parsed_categories.append(parsed_category)
		if category == 55:
			parsed_category = "Financial_Institutions"
			parsed_categories.append(parsed_category)
		if category == 67:
			parsed_category = "Forums_Message_Boards"
			parsed_categories.append(parsed_category)
		if category == 11:
			parsed_category = "Gambling"
			parsed_categories.append(parsed_category)
		if category == 12:
			parsed_category = "Games"
			parsed_categories.append(parsed_category)
		if category == 74:
			parsed_category = "German_Youth_Protection"
			parsed_categories.append(parsed_category)
		if category == 49:
			parsed_category = "Government"
			parsed_categories.append(parsed_category)
		if category == 13:
			parsed_category = "Hate_Discrimination"
			parsed_categories.append(parsed_category)
		if category == 14:
			parsed_category = "Health_and_Fitness"
			parsed_categories.append(parsed_category)
		if category == 15:
			parsed_category = "Humor"
			parsed_categories.append(parsed_category)
		if category == 16:
			parsed_category = "Instant_Messaging"
			parsed_categories.append(parsed_category)
		if category == 126:
			parsed_category = "Internet_Watch_Foundation"
			parsed_categories.append(parsed_category)
		if category == 17:
			parsed_category = "Jobs_Employment"
			parsed_categories.append(parsed_category)
		if category == 60:
			parsed_category = "Lingerie_Bikini"
			parsed_categories.append(parsed_category)
		if category == 19:
			parsed_category = 'Movies'
			parsed_categories.append(parsed_category)
		if category == 50:
			parsed_category = "Music"
			parsed_categories.append(parsed_category)
		if category == 33:
			parsed_category = "News_Media"
			parsed_categories.append(parsed_category)
		if category == 69:
			parsed_category = "Non_Profits"
			parsed_categories.append(parsed_category)
		if category == 63:
			parsed_category = "Nudity"
			parsed_categories.append(parsed_category)
		if category == 20:
			parsed_category = "P2P_File_Sharing"
			parsed_categories.append(parsed_category)
		if category == 57:
			parsed_category = "Parked_Domains"
			parsed_categories.append(parsed_category)
		if category == 48:
			parsed_category = "Photo_Sharing"
			parsed_categories.append(parsed_category)
		if category == 71:
			parsed_category = "Podcasts"
			parsed_categories.append(parsed_category)
		if category == 66:
			parsed_category = "Politics"
			parsed_categories.append(parsed_category)
		if category == 64:
			parsed_category = "Pornography"
			parsed_categories.append(parsed_category)
		if category == 21:
			parsed_category = "Portals"
			parsed_categories.append(parsed_category)
		if category == 61:
			parsed_category = "Proxy_Anonymizer"
			parsed_categories.append(parsed_category)
		if category == 22:
			parsed_category = "Radio"
			parsed_categories.append(parsed_category)
		if category == 65:
			parsed_category = "Religious"
			parsed_categories.append(parsed_category)
		if category == 54:
			parsed_category = "Research_Reference"
			parsed_categories.append(parsed_category)
		if category == 23:
			parsed_category = "Search_Engines"
			parsed_categories.append(parsed_category)
		if category == 62:
			parsed_category = "Sexuality"
			parsed_categories.append(parsed_category)
		if category == 24:
			parsed_category = "Social_Networking"
			parsed_categories.append(parsed_category)
		if category == 47:
			parsed_category = "Software_Technology"
			parsed_categories.append(parsed_category)
		if category == 51:
			parsed_category = "Sports"
			parsed_categories.append(parsed_category)
		if category == 59:
			parsed_category = "Tasteless"
			parsed_categories.append(parsed_category)
		if category == 34:
			parsed_category = "Television"
			parsed_categories.append(parsed_category)
		if category == 73:
			parsed_category = "Tobacco"
			parsed_categories.append(parsed_category)
		if category == 68:
			parsed_category = "Travel"
			parsed_categories.append(parsed_category)
		if category == 26:
			parsed_category = "Video_Sharing"
			parsed_categories.append(parsed_category)
		if category == 27:
			parsed_category = "Visual_Search_Engines"
			parsed_categories.append(parsed_category)
		if category == 28:
			parsed_category = "Weapons"
			parsed_categories.append(parsed_category)
		if category == 77:
			parsed_category = "Web_Spam"
			parsed_categories.append(parsed_category)
		if category == 94:
			parsed_category = "Malware"
			parsed_categories.append(parsed_category)
		if category == 96:
			parsed_category = "Malware"
			parsed_categories.append(parsed_category)
		if category == 100:
			parsed_category = "Suspicious_Response"
			parsed_categories.append(parsed_category)
		if category == 83:
			parsed_category = "Drive-by_Downloads_Exploits"
			parsed_categories.append(parsed_category)
		if category == 85:
			parsed_category = "Dynamic_DNS"
			parsed_categories.append(parsed_category)
		if category == 87:
			parsed_category = "Mobile_Threats"
			parsed_categories.append(parsed_category)
		if category == 90:
			parsed_category = "Botnet"
			parsed_categories.append(parsed_category)
		if category == 92:
			parsed_category = "Botnet"
			parsed_categories.append(parsed_category)
		if category == 98:
			parsed_category = "Phishing"
			parsed_categories.append(parsed_category)
		if category == 89:
			parsed_category = "High_risk_Sites_and_Locations"
			parsed_categories.append(parsed_category)
	json_item["categories"] = parsed_categories
	parse_handling_codes(json_item)
	
def login():
	#Start the session
	s = requests.Session()

	# Grab Form token from login page.
	r = s.get("https://login.opendns.com", headers=headers)
	a = 'name="formtoken" value="'
	b = '/>'

	formToken = r.text.split(a)[1].split(b)[0].split('"')[0]

	#Setup our Login Data

	login_data = {
		"username" : username,
		"password" : password,
		"formtoken" : formToken,
		"return_to" : "https://dashboard2.opendns.com",
		"loginToken": uuid.uuid4() #16 Byte UUID 

		}

	#Login
	d = s.post("https://login.opendns.com", data=login_data, headers=headers)
	
	#Check to make sure Login worked 
	if "Logging you in" in d.text: 
		print("[*] Login Successful... ")
		return s 
	else: 
		print("[!] Something is wrong... Login Failed..")


def search_opendns(categories,handlingCode):
	s = login()

	#format categories as list
	list_categories = []
	list_categories.append(categories)
	

	#Grab API Key
	r = s.get("https://dashboard2.opendns.com/o/1824685/#/reports")
	a = '"api-session":"'
	b = '","'
	try: 
		apiToken = r.text.split(a)[1].split(b)[0]
	except Exception as e: 
		print "[!] Something went wrong.. \n" + str(e)

	#Build Search Criteria
	search_criteria = {
	'filterNoisyDomains':'true',
	'start': one_minute_ago,
	'end': current_time,
	'categories': list_categories,
	'handlingCode': handlingCode
	}

	print "Searching for category = " + str(categories) + " and handlingcode = " + str(handlingCode)
	#Build Search URL 
	search_URL = 'https://api.opendns.com/v3/organizations/' + str(organizations_id) + "/reports/activitysearch?offset=0&limit=" + str(search_limit) + "&filters=" + json.dumps(search_criteria) + '&&outputFormat=jsonHttpStatusOverride&api-session=' + str(apiToken) 
	print search_URL
	r = s.get(search_URL, headers=headers)
	#print r.text

	# Parse all the things 
	parsed_json_response = json.loads(r.text)
	print "[*] Found "+ str(len(parsed_json_response['data'])) + " results"

	for i in parsed_json_response['data']:
		parse_categoies(i)
		
		
		
available_categories = ['72','58','1','2','76','3','70','4','56','5','6','7','8','9','52','10','55','67','11','12','74','49','13','14','15','16','126','17','60','19','50','33','69','63','20','57','48','71','66','64','21','61','22','65','54','23','62','24','47','51','59','34','73','68','26','27','28','77','29','94','96','100','83','85','87','90','92','98','89']
test_cat = [19]
handlingCodes = [-1]

for i in available_categories:
	search_opendns(i,-1)
