import dpkt
import copy
import math
import matplotlib.pyplot as plt
import pandas as pd
import generalFile
import sys

flows = []
packets = []

def httpRequestResponse():
    httpRequestResponseList4All = []

    for i in range(0,len(flows)):
        httpRequestResponseList = []

        getList = []
        sequenceDic = {}
        for items in flows[i]: 
            tempPayload = str(items["PAYLOAD"])
            if("GET" in tempPayload):
                getList.append(items)
            else:
                sequenceDic[items["SEQUENCE"]] = items

        #seperates the request by itself
        for items in getList:
            tempPayload = str(items["PAYLOAD"])
            trueEnd = ""
            if(tempPayload.find("Connection")>tempPayload.find("HTTP")):
                trueEnd = tempPayload.find("Connection")
            else:
                trueEnd = tempPayload.find("HTTP")

            request = tempPayload[tempPayload.find("GET"):trueEnd]
            httpRequestResponseList.append(request)

        #get sequence and ack values
        tempList = []
        for items in getList:
            flag = 0        
            seq = sequenceDic[getList[0]["ACK"]]["SEQUENCE"]

            while(flag == 0):
                if(sequenceDic[seq]["FLAG SEP"][0]!=1):
                    tempList.append(sequenceDic[seq])
                    seq = sequenceDic[seq]["PAYLOAD LENGTH"] + seq
                    if(seq not in sequenceDic.keys()):
                        flag = 1
                else:
                    flag = 1

        httpRequestResponseList.append(tempList)
        if(httpRequestResponseList[0]!=[]):
            httpRequestResponseList4All.append(httpRequestResponseList)
    
    return httpRequestResponseList4All

def printHttpRequestResponse(httpRequestResponseList):
    for i in range(0,len(httpRequestResponseList)):
        print("\nRequest: " + str(httpRequestResponseList[i][0]))
        print("Response:")
        for j in range(0,len(httpRequestResponseList[i][1])):
            source = str(httpRequestResponseList[i][1][j]["SOURCE"])
            dest = str(httpRequestResponseList[i][1][j]["DESTINATION"])
            seq = str(httpRequestResponseList[i][1][j]["SEQUENCE"])
            ack = str(httpRequestResponseList[i][1][j]["ACK"])
            print("< " + source+ ", " + dest + ", " + seq + ", " + ack + ">")

def httpProtocolBeingUsed():
    dataDic = {}
    total = 0
    websiteDataCount = 0
    tlsKeyCount =0
    for i in range(0,len(flows)):
        #get length of data
        data = 0
        dest = flows[i][0]["DESTINATION"]
        for j in range(0,len(flows[i])):
            if flows[i][j]["SOURCE"]==dest:
                data = flows[i][j]["PAYLOAD LENGTH"] + data
        
        if(data>3500): #for only ssl key
            websiteDataCount = websiteDataCount+1 #if greater, not for ssl key only
        else:
            tlsKeyCount = tlsKeyCount +1

        dataDic[flows[i][0]["SOURCE"]] = data
        total = total + data

    dataDic["TOTAL"] = total
    dataDic["WEBSITE COUNT"] =  websiteDataCount
    dataDic["TLS COUNT"] = tlsKeyCount
    return dataDic

def printHttpProtocolBeingUsed(dataDic):
    print("\nNumber of Bytes of Data Sent From Server to Client")
    for i in dataDic.keys():
        if(type(i)!=str):
            print("\tDestination Port " + str(i) + ": " + str(dataDic[i]) + " bytes")
        if(i=="TOTAL"):
            print("\tTOTAL: " + str(dataDic[i]) + " bytes" )
    
    print("\nNumber of Connections that Server Opened: " + str(dataDic["WEBSITE COUNT"]))
    print("Number of Connections for TLS key exchange: " + str(dataDic["TLS COUNT"]))

    if(dataDic["TLS COUNT"]>1):
        print("Therefore, HTTP 1.0 was used because it establishes TCP connections for requests.")
    elif(dataDic["WEBSITE COUNT"]>1):
        print("Therefore, HTTP 1.1 was used because it uses parallel TCP connections.")
    else:
        print("Therefore, HTTP 2.0 was used because it uses only one TCP connection.")

def loadTimePacketCountBytes():
    count = 0
    data = 0 
    maxTime =-sys.maxsize
    minTime = sys.maxsize
    for i in range(0,len(flows)):
        dest = flows[i][0]["DESTINATION"]
        startTime = flows[i][0]["TIME"]
        endTime = 0
        pktbelow = flows[i][0]
        for j in range(0,len(flows[i])):
            #get time lasp
            if((flows[i][j]["TIME"]-pktbelow["TIME"])<2.0):
                pktbelow = flows[i][j]
                endTime = flows[i][j]["TIME"]
            #get number of pakets and number of bytes
            if flows[i][j]["SOURCE"]==dest:
                count = count +1
                data = flows[i][j]["PAYLOAD LENGTH"] + data

        if(startTime<minTime):
            minTime = startTime
        
        if(endTime>maxTime):
            maxTime = endTime

    timeDifference = maxTime - minTime
    dic = {"TIME": timeDifference, "BYTES": data, "PACKET COUNT": count}
    return dic

def printloadTimePacketCountBytes(dic, httpProtocolDataDic):
    total = httpProtocolDataDic["WEBSITE COUNT"] + httpProtocolDataDic["TLS COUNT"]
    print("\nNumber of Connections: "+ str(total))
    print("Number of Packets: "+ str(dic["PACKET COUNT"]))
    print("Number of Bytes: "+ str(dic["BYTES"]))
    print("Load Time: " + str(dic["TIME"]))    
    
truth1 = 0

while(truth1 ==0):
    fileName = input("\nPlease provide the name of the pcap file you would like to read (ex. http_1080.pcap):\n")
    try:
        # fileName = "http_1080.pcap"
        pkts =  dpkt.pcap.Reader(open(fileName,'rb')).readpkts()
        truth1 = 1
    except FileNotFoundError:
        print("\nThe file name you provided was incorrect, please try again!")
packets = generalFile.getPacketsInReadableForm(pkts)
flows = generalFile.setUpFlow(packets)

flag = 0

while(flag==0):
    print("\nWhat information would you like? [1/2/3/4]")
    print("\t1) Reassembled unique HTTP Request/Response")
    print("\t2) HTTP Protocol Being Used")
    print("\t3) Load Time, Number of Packets, and Bytes")
    print("\t4) Exit")

    answer = input("").replace(" ", "")

    if(answer=="1"):
        httpRequestResponseList = httpRequestResponse()
        printHttpRequestResponse(httpRequestResponseList)
    elif(answer=="2"):
        dataDic = httpProtocolBeingUsed()
        printHttpProtocolBeingUsed(dataDic)
    elif(answer=="3"):
        dic = loadTimePacketCountBytes()
        httpProtocolDataDic = httpProtocolBeingUsed()
        printloadTimePacketCountBytes(dic, httpProtocolDataDic)
    elif(answer=="4"):
        flag = 1
    else:
        print("Wrong input, please try again.")

    if(answer!="4"):
        answer2 = input("\nContinue? [Y/N]\t").replace(" ", "")
        if((answer2!="Y") and (answer2!="y") and (answer2!="YES")):
            flag =1



#http_1080.pcap