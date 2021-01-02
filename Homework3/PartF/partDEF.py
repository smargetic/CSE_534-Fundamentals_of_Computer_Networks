import dpkt
import copy
import math
import matplotlib.pyplot as plt
import pandas as pd
import generalFile
import sys
import binascii
from dnslib import *
import socket
import struct
import ipaddress
import struct

flows = []
packets = []

# youtubeDomains = 
# ["ns-tld1.charlestonroadregistry.com", "ns-tld5.charlestonroadregistry.com", "ns-tld2.charlestonroadregistry.com",
#                 "ns-tld3.charlestonroadregistry.com", "ns-tld4.charlestonroadregistry.com", 
youtubeDomains = ["youtu.be", "youtube.com", ".youtube", "youtube", "youtube-nocookie.com", 
                "youtube.com.tr", "ytimg.com", ".googlevideo.com", "m.youtube.com", ".youtube", #after here
                ".youtube.com.br", ".youtube.co.nz", "youtube.de", ".youtube.es", ".youtube.googleapis.com",
                ".youtubei.googleapis.com", ".youtube.it", ".youtube.nl", ".youtube-nocookie.com",
                ".youtube.ru", ".video-stats.l.google.com", ".ytimg.l.google.com", ".rewind.youtube",
                ".blog.youtube",
                # "ns1.google.com", "ns2.google.com", "ns3.google.com", "ns4.google.com"
                ]

vimeoDomains = ["vimeo", "vimeo.com", "vimeostatus.com", "vimeo-staging.com", "jonathanbritnell.com",
                "developer.vimeo.com", "join.vimeo.com", "vimeostatus.com", "status.vimeo.com", "api.vimeo.com",
                "www.vimeo.com", "dev.vimeo.com", "secure.vimeo.com", "directory.vimeo.com", "movie1.hibuna.info",
                "vimeo-staging2.com", "developers.vimeo.com", "search.vimeo.com", "vimeo.waca.associates",
                "mail.jonathanbritnell.com", "vimeo.fr", "ftp.jonathanbritnell.com", "video.bhplayhouse.com",
                "vimeobusiness.com", "goods.vimeo.com", "tv.vimeo.com", "autosuggest.vimeo.com", "www.vimeoondemand.com",
                "error.vimeo.com", "www.vimeobusiness.com", "vimeoondemand.com", "video.schoolofrock.com"]

dailyMotionDomains = ["dailymotion", "dailymotion.com", "press.dailymotion.com", "faq.dailymotion.com",
                    "dmcdn.net", "dailymotion.in", "dailymotion.pl", "dailymotion.co", "dailymotion.net",
                    "dailymotion.fr", "www.dailymotion.com", "dmwww.geo.dmcdn.net.", "dmwww.api-aws.dailymotion.com."]

    
truth1 = 0

#find the ip addresses from a given service that are connected (Part D)
def findIpAddresses():
    serviceType = ""
    listOfIpAddr = []
    listOfUsedIpAddr = []

    #resolve the dns packet to find IP addr
    for i in range(0,len(packets)):
        #DOUBLE CHECK IF 53 FOR ALL
        if((packets[i]["SOURCE"]==53) or (packets[i]["DESTINATION"]==53)):
            buffer = DNSBuffer(packets[i]["PAYLOAD DNS"]) #packs and unpacks in struct form
            header = DNSHeader.parse(buffer)
            record = DNSRecord.parse(packets[i]["PAYLOAD DNS"])

            tempQuestion = str(record.q).split(" ")
            tempQuestion[0] = tempQuestion[0].replace(";", "")
            serviceFound = 0
            if((serviceType=="") or (serviceType=="Youtube")): #youtube packet
                for j in range(0,len(youtubeDomains)): #check if answer in list of domains
                    if(youtubeDomains[j] in tempQuestion[0]):
                        serviceType = "Youtube"
                        serviceFound = 1
            if((serviceType=="") or (serviceType=="DailyMotion")): #daily motion packet
                for j in range(0,len(dailyMotionDomains)): #check if answer in list of domains
                    if(dailyMotionDomains[j] in tempQuestion[0]):
                        serviceType = "DailyMotion"
                        serviceFound = 1
            if((serviceType=="") or (serviceType=="Vimeo")): #vimeo packet
                for j in range(0,len(vimeoDomains)): #check if answer in list of domains
                    if(vimeoDomains[j] in tempQuestion[0]):
                        serviceType = "Vimeo"
                        serviceFound = 1            
            #add provided ip addr to list
            if((header.a > 0) and (serviceFound!=0)): #if there are any answers, we know the ip addr was provided
                temp = str(record.get_a).split("\n")
                for items in temp:
                    items = items.replace(">", "")
                    items = items.replace("'", "")
                    #add cname to list of domains we want to look at
                    if("CNAME" in items):
                        temp2 = items.split("=")
                        if(serviceType=="Youtube"):
                            youtubeDomains.append(temp2[-1])
                        elif(serviceType=="DailyMotion"):
                            dailyMotionDomains.append(temp2[-1])
                        else:
                            vimeoDomains.append(temp2[-1])
                    if ("rtype=A" in items):
                        temp2 = items.split("=")
                        listOfIpAddr.append(temp2[-1])

    #see if ip addr was actually connected to
    for i in range(0,len(packets)):
        for j in range(0,len(listOfIpAddr)):
            if((packets[i]["SOURCE IP"]==listOfIpAddr[j]) or (packets[i]["DEST IP"]==listOfIpAddr[j])):
                if(listOfIpAddr[j] not in listOfUsedIpAddr):
                    listOfUsedIpAddr.append(listOfIpAddr[j])

    return serviceType, listOfUsedIpAddr

#print service used and ip addr connected to from service
def printServiceTypeAndUsedIp(serviceType, listOfUsedIpAddr):
    print("\nThe video streaming service was: " + serviceType)
    print("The IP addresses used from this streaming service were:")
    for i in range(0,len(listOfUsedIpAddr)):
        print("\t" + listOfUsedIpAddr[i])

#generate network counters (part E)
def youtubeNetworkCounter(listOfUsedIpAddr):
    localDeviceIP = "192.168.5.10"
    ipDic = {}

    #create dictionary for each ip address used
    for i in range(0,len(listOfUsedIpAddr)):
        tempDic = {"OUT COUNT": 0, "IN COUNT": 0, "OUT BYTES": 0, "IN BYTES": 0} 
        ipDic[listOfUsedIpAddr[i]] = tempDic

    #for each ip, get in and out count and in and out num bytes
    for i in range(0,len(packets)):
        for j in range(0,len(listOfUsedIpAddr)):
            if((packets[i]["SOURCE IP"]==listOfUsedIpAddr[j]) and (packets[i]["DEST IP"]==localDeviceIP)):
                ipDic[listOfUsedIpAddr[j]]["OUT COUNT"] = ipDic[listOfUsedIpAddr[j]]["OUT COUNT"] + 1
                ipDic[listOfUsedIpAddr[j]]["OUT BYTES"] = ipDic[listOfUsedIpAddr[j]]["OUT BYTES"] + packets[i]["SIZE"]
            elif((packets[i]["DEST IP"]==listOfUsedIpAddr[j]) and (packets[i]["SOURCE IP"]==localDeviceIP)):
                ipDic[listOfUsedIpAddr[j]]["IN COUNT"] = ipDic[listOfUsedIpAddr[j]]["IN COUNT"] + 1
                ipDic[listOfUsedIpAddr[j]]["IN BYTES"] = ipDic[listOfUsedIpAddr[j]]["IN BYTES"] + packets[i]["SIZE"]
    
    #total values among all ips
    tempDic = {"TOTAL OUT COUNT": 0, "TOTAL IN COUNT": 0, "TOTAL OUT BYTES": 0, "TOTAL IN BYTES": 0}
    for items in ipDic.values():
        tempDic["TOTAL OUT COUNT"] = items["OUT COUNT"] + tempDic["TOTAL OUT COUNT"] 
        tempDic["TOTAL IN COUNT"]  = items["IN COUNT"] + tempDic["TOTAL IN COUNT"]
        tempDic["TOTAL OUT BYTES"] = items["OUT BYTES"] + tempDic["TOTAL OUT BYTES"]
        tempDic["TOTAL IN BYTES"] = items["IN BYTES"] + tempDic["TOTAL IN BYTES"]
    
    tempDic["TOTAL PACKETS EXCHANGED"] = tempDic["TOTAL OUT COUNT"] + tempDic["TOTAL IN COUNT"]
    tempDic["TOTAL BYTES EXCHANGED"] = tempDic["TOTAL OUT BYTES"] + tempDic["TOTAL IN BYTES"]

    ipDic["TOTAL"] = tempDic

    return ipDic

#print network counter info
def printYoutubeNetworkCounter(ipDic):
    for items in ipDic.keys():
        if(items!="TOTAL"):
            print("\nYoutube server " + items + ":")
        else:
            print("\n" + items + ":")
        for items2 in ipDic[items].keys():
            print("\t" + items2 + ": " + str(ipDic[items][items2]))
    print("\n***IN is considered from local IP to Youtube server")
    print("***OUT is considered from Youtube server to local IP")

#find video segments, their time and size (part F)
def videoSegmentDownloads(listOfUsedIpAddr, ipDic):
    localDeviceIP = "192.168.5.10"

    ipVideoSegDic = {}
    #I go through each ip address and search for video seg
    for i in range(0,len(listOfUsedIpAddr)):
        ipVideoSegDic[listOfUsedIpAddr[i]] = {"SOURCE FLAG": 0, "VIDEO SEG": [], "VIDEO SEG DIC": {}}
        for j in range(0,len(packets)):
            #if the upstream packet has a payload greater than 0, its a request for a seg
            if((packets[j]["SOURCE IP"]==localDeviceIP) and (packets[j]["DEST IP"]==listOfUsedIpAddr[i])):
                if(packets[j]["PAYLOAD LENGTH"]>0):
                    ipVideoSegDic[listOfUsedIpAddr[i]]["SOURCE FLAG"] = 1
            #if the downstream packet has a payload greater than 0 = seg
            elif((packets[j]["DEST IP"]==localDeviceIP) and (packets[j]["SOURCE IP"]==listOfUsedIpAddr[i])):
                if(packets[j]["PAYLOAD LENGTH"]>0):                
                    if(ipVideoSegDic[listOfUsedIpAddr[i]]["SOURCE FLAG"] == 1):
                        ipVideoSegDic[listOfUsedIpAddr[i]]["SOURCE FLAG"] = 0
                        ipVideoSegDic[listOfUsedIpAddr[i]]["VIDEO SEG"].append([packets[j]["TIME"], packets[j]["PAYLOAD LENGTH"]])
                    else:
                        #segments are in bursts, so should be added to previous existing until new request
                        ipVideoSegDic[listOfUsedIpAddr[i]]["VIDEO SEG"][-1][1] = ipVideoSegDic[listOfUsedIpAddr[i]]["VIDEO SEG"][-1][1] + packets[j]["PAYLOAD LENGTH"]
                
    return ipVideoSegDic

#prints video segments found and their bytes
def printVideoSegments(ipVideoSegDic):
    print("\nYoutube Video Segments:")
    for items in ipVideoSegDic.keys():
        print("\nIP Address " + items + ":")
        for i in range(0,len(ipVideoSegDic[items]["VIDEO SEG"])):
            print("TIME: " + str(ipVideoSegDic[items]["VIDEO SEG"][i][0]) + "\tSIZE: " + str(dicOfPorts[items]["VIDEO SEG"][i][1]))



while(truth1 ==0):
    fileName = input("\nPlease provide the name of the pcap file you would like to read (ex. laptop_wifi_youtube.pcap):\n")
    try:
        pkts =  dpkt.pcap.Reader(open(fileName,'rb')).readpkts()
        truth1 = 1
    except FileNotFoundError:
        print("\nThe file name you provided was incorrect, please try again!")
packets = generalFile.getPacketsInReadableForm(pkts)
flows = generalFile.setUpFlow(packets)


flag = 0
while(flag==0):
    print("\nWhat information would you like? [1/2/3/4]")
    print("\t1) Find IP Addresses and Service")
    print("\t2) Calculate Youtube Network Counters")
    print("\t3) Retrieve Video Segment Time and Size for Youtube")
    print("\t4) Exit")

    answer = input("").replace(" ", "")
    # answer = "3"
    if(answer=="1"):
        serviceType, listOfUsedIpAddr = findIpAddresses()
        printServiceTypeAndUsedIp(serviceType, listOfUsedIpAddr)
    elif(answer=="2"):
        #make sure youtube file?
        serviceType, listOfUsedIpAddr = findIpAddresses()
        #use service type to throw error?
        ipDic = youtubeNetworkCounter(listOfUsedIpAddr)
        printYoutubeNetworkCounter(ipDic)
    elif(answer=="3"):
        serviceType, listOfUsedIpAddr = findIpAddresses()
        #use service type to throw error?
        ipDic = youtubeNetworkCounter(listOfUsedIpAddr)
        dicOfPorts = videoSegmentDownloads(listOfUsedIpAddr, ipDic)
        printVideoSegments(dicOfPorts)
    elif(answer=="4"):
        flag = 1
    else:
        print("Wrong input, please try again.")

    if(answer!="4"):
        answer2 = input("\nContinue? [Y/N]\t").replace(" ", "")
        if((answer2!="Y") and (answer2!="y") and (answer2!="YES")):
            flag =1

        # fileName = "http_1080.pcap"
        ## fileName = "laptop_wifi_youtube.pcap"
        # fileName = "laptop_wifi_youtube.pcap" #USED FOR YOUTUBE
        # fileName = "laptop_wifi_dailymotion.pcap"
        # fileName = "laptop_wifi_vimeo2.pcap"
        # fileName = "laptop_wifi_vimeo.pcap"