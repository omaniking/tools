import requests as req
import json,time, sys
# import aapi as welcome

ip_file = sys.argv[1]
output_file = ip_file.strip('.') + ".output"
json_file = ip_file.strip('.')+".json"
firewall_file = ip_file.strip('.') +".firewall"
dictionries_file = ip_file.strip('.')+".dictionaries"


#declaring empty dictionaries 
ip_dic=[]
ip_rate_dic = {}
ip_contry_dic = {}


print (" Starting iPVoidCheckBlacklistedIP tool 1.0 \n\n")

print ("The below details show the response for each request to the apivoid site:\n")
with open (ip_file,'r') as ip_file:
	for ip in ip_file:
		
		url = "https://endpoint.apivoid.com/iprep/v1/pay-as-you-go/?key=[yourkeyHere]="+ ip

		respnse = req.get (url)
		rjson = respnse.json()
		print (str(rjson)+"\n")

		#write the json file for the checked ip into the json file
		with open (json_file,'a') as json_f:
			json_f.write(respnse.content)
			json_f.write("\n")

		#declaring the ip, rate, contry from the json file and put them in one json file
		jip = str(rjson['data']['report']['ip'])
		jblacklist_rate = str(rjson['data']['report']['blacklists']['detection_rate'])
		jcontry = str(rjson['data']['report']['information']['country_name'])
		#result = jblacklist_rate+ "\t"+jip + "\t" +jcontry



		#write the ip's into ip dictionary for letter use
		ip_dic.append(jip)
		
		#write the key (ip) and the value(contry) into contry dictionary for later use
		contry= {jip:jcontry}
		ip_contry_dic.update(contry)
		
		#write the rate of each ip into another dictionary
		rate={jip:jblacklist_rate}
		ip_rate_dic.update(rate)
		
#save the dictionaries file
with open (dictionries_file, 'a') as dict:
	dict.write('\n')
	dict.write(str(ip_dic)+"\n")
	dict.write(str(ip_contry_dic)+"\n")
	dict.write(str(ip_rate_dic)+"\n")

print ("\n\nThe below results show the ip address, abuse rate, and from which contry:\n")
#THe list of ips with rate and contry
for ip_key in ip_dic:
	#delare the variable to get the value from the dictionaries
	the_ip=ip_key
	the_contry=ip_contry_dic[ip_key]
	the_rate=ip_rate_dic[ip_key]
	result = the_ip + "\t" + the_rate + "\t" + the_contry
	
	#Dictionaries to add them to the query
	if the_rate.strip("%") < "10":
		query1 = "delete security address-book global address "+the_ip+ " "+the_ip+"/32"
		query2 = "delete security address-book global address-set NDCSZ-Block-List_1 address "+the_ip

		#write them in one file 
		with open (firewall_file,'a') as firewall_f:
			firewall_f.write(the_ip+"\n")
			firewall_f.write(query1+"\n")
			firewall_f.write(query2+"\n\n")




	#Printing the result of all togather
	print (result)
	
	#write the output into the output file for all the results
	with open(output_file, 'a') as output:
		output.write(result)
		output.write("\n")

credits_remained = str(rjson['credits_remained'])
print ("\n\nThe remains credit from the api is :" + credits_remained)	

print ("\n\nThe reasult of this proces is saved under the below names:\n1.The response of each request "+json_file + "\n2. The ips, rate, and the contry in "+output_file+"\n3. The firewall queries are in "+firewall_file+"\n4. the dictionaries to reuse it for the future are in " +dictionries_file+"\n\n")
print ("           Copyright (c) 2019. All Rights Reservied\n")
print("                     Coded by omaniking")

