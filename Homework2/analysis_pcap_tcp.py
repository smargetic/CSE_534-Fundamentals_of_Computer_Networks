import dpkt
import copy
import math
import matplotlib.pyplot as plt
import pandas as pd
import generalFile

packets = []
flows = []

class tcpConnectionUnsuccessful(Exception):
    pass

class error(Exception):
    pass

class packetLostFirst2Transactions(Exception):
    pass


#confirm that 3 way hanshake happened
def confirm3wayhandshake():
    countArray = []
    for i in range(0,len(flows)):
        count = 0
        found = 0
        sequence = 0
        #tcp initiated, ack =0 and syn flag set
        for j in range(0,len(flows[i])):
            if((flows[i][j]["ACK"]==0)and (flows[i][j]["FLAG SEP"]==[0,1,0,0,0,0])):
                count = j +1
                found =1
                sequence = flows[i][j]["SEQUENCE"] + 1
                break    
        if(found ==0):
            raise tcpConnectionUnsuccessful

        ackNumber =0
        found =0
        #syn ack responce
        for j in range(count, len(flows[i])): #flags - fin, syn, rst, psh, ack, urg
            if((flows[i][j]["FLAG SEP"]==[0,1,0,0,1,0]) and (sequence==flows[i][j]["ACK"])):
                ackNumber = flows[i][j]["ACK"]
                found =1
                count = j +1
                break  
        if(found ==0):
            raise tcpConnectionUnsuccessful

        found = 0
        #ack response
        for j in range(count, len(flows[i])):
            if((flows[i][j]["SEQUENCE"]==ackNumber)and (flows[i][j]["FLAG SEP"]==[0,0,0,0,1,0])):
                found =1
                count = j +1
                break
        if(found ==0):
            raise tcpConnectionUnsuccessful
        
        countArray.append(count)
    return countArray

def find2TransactionsAfterTCPSetup():
    listOfTransactions = [] 
    # in form [[[source1-->dest,dest-->source1],[source1-->dest,dest-->source]],[[source2-->dest,dest-->source2],[..]]]
    countArray = confirm3wayhandshake()
    for i in range(0,len(flows)):
        temp = []
        found1 = 0
        found2 = 0

        #first 2 packets sent
        temp.append([flows[i][countArray[i]]])
        temp.append([flows[i][countArray[i]+1]])
        #look for corresponding ack packets
        for j in range(countArray[i], len(flows[i])):
            if(flows[i][j]["ACK"]==(temp[0][0]["SEQUENCE"]+temp[0][0]["PAYLOAD LENGTH"])):
                temp[0].append(flows[i][j])
                found1 =1

        for j in range(countArray[i], len(flows[i])):
            if(flows[i][j]["ACK"]==(temp[1][0]["SEQUENCE"]+temp[1][0]["PAYLOAD LENGTH"])):
                temp[1].append(flows[i][j])
                found2 = 1
        
        if((found1==0)or (found2==0)):
            raise packetLostFirst2Transactions
  
        listOfTransactions.append(temp)
    
    return listOfTransactions            

#print sequence number, ack number, window size for first 2 transactions for each source
def print2TransactionsAfterTCPSetupInfo(listOfTransactions):
    for i in range(0,len(listOfTransactions)):
        print("\nSource Port " + str(listOfTransactions[i][0][0]["SOURCE"]) + ":")
        for j in range(0, len(listOfTransactions[i])):
            temp = j+1
            print("\nTransaction " + str(temp) + ":")
            for m in range(0,len(listOfTransactions[i][j])):
                if(m==0):
                    print("Sender:")
                else:
                    print("\nReceiver:")
                print("\tSequence Number: " + str(listOfTransactions[i][j][m]["SEQUENCE"]))
                print("\tAck Number: " + str(listOfTransactions[i][j][m]["ACK"]))
                print("\tWindow Size: " + str(listOfTransactions[i][j][m]["WINDOW"]))

def throughput():
    throughputList = []
    for i in range(0,len(flows)):
        #total time
        startTime = flows[i][0]["TIME"]
        endTime = flows[i][-1]["TIME"]
        timeDif = (endTime - startTime)*1000000

        #total size of info
        totalSize = 0
        for j in range(0,len(flows[i])):
            totalSize = flows[i][j]["SIZE"] + totalSize
        totalSize = totalSize * 8.0

        throughputAmt = totalSize/timeDif
        throughputList.append([flows[i][0]["SOURCE"], throughputAmt])
    return throughputList

#throughput info
def printThroughput(throughputList):
    for i in range(0, len(throughputList)):
        print("\nSource Port " + str(throughputList[i][0]) + ":")
        print("Throughput: {:.5}".format((throughputList[i][1])) + " Mbps")

def lossRate():
    lossRateList = []
    for i in range(0,len(flows)):
        #look for retransmission
        sourcePort = flows[i][0]["SOURCE"]
        sequenceDic = {}
        numberOfPackets = 0
        for j in range(0,len(flows[i])):
            if(flows[i][j]["SOURCE"]==sourcePort):
                numberOfPackets = numberOfPackets +1
                if(flows[i][j]["SEQUENCE"] in sequenceDic):
                    sequenceDic[flows[i][j]["SEQUENCE"]] = sequenceDic[flows[i][j]["SEQUENCE"]] +1
                else:
                    sequenceDic[flows[i][j]["SEQUENCE"]] = 1
        

        count = 0
        for item in sequenceDic.values():
            if(item>1):
                dif = item - 1
                count = count + dif

        lossRateList.append([sourcePort, numberOfPackets, (count-1)])
    return lossRateList

#print loss rate info
def printLossRate(lossRateList):
    for i in range(0, len(lossRateList)):
        print("\nSource Port " + str(lossRateList[i][0]) + ":")
        print("\tTotal Number of Packets: " + str(lossRateList[i][1]))
        print("\tNumber of Lost Packets: " + str(lossRateList[i][2]))

        rateOfLoss = lossRateList[i][2]/lossRateList[i][1]
        if(rateOfLoss ==0.0):
            print("\tRate of Loss: 0.0")
        else:
            print("\tRate of Loss: {:.5}".format(rateOfLoss))           

def rtt():
    throughputList = throughput()
    lossRateList = lossRate()
    returnValues = []

    for i in range(0,len(flows)):
        #seperate sent and recieved packets and look for duplicates (retransmission)
        sentPort = flows[i][0]["SOURCE"]
        sentDic = {}
        recievedDic = {}
        for j in range(0,len(flows[i])):
            if(sentPort==flows[i][j]["SOURCE"]):
                if(flows[i][j]["SEQUENCE"] in sentDic):
                    sentDic[flows[i][j]["SEQUENCE"]]["COUNT"] = sentDic[flows[i][j]["SEQUENCE"]]["COUNT"] + 1
                else:
                    tempDic = {"COUNT": 1, "PACKET": flows[i][j]}
                    sentDic[flows[i][j]["SEQUENCE"]] = tempDic
            else:
                if(flows[i][j]["SEQUENCE"] in recievedDic):
                    recievedDic[flows[i][j]["SEQUENCE"]]["COUNT"]  = recievedDic[flows[i][j]["SEQUENCE"]]["COUNT"] + 1
                else:                 
                    tempDic = {"COUNT": 1, "PACKET": flows[i][j]}
                    recievedDic[flows[i][j]["ACK"]] = tempDic

        #remove retransmitted packets because they are lost
        listToPopSent = []
        for items in sentDic.values():
            if (items["COUNT"]>1):
                listToPopSent.append(items["PACKET"]["SEQUENCE"])

        for j in range(0,len(listToPopSent)):
            sentDic.pop(listToPopSent[j])

        #for each packet, time between sent and recieved
        count = 0
        time = 0
        for items in recievedDic.values():
            sequence = items["PACKET"]["ACK"] - 1448
            if(sequence in sentDic):
                count = count + 1
                time = (items["PACKET"]["TIME"] - sentDic[sequence]["PACKET"]["TIME"]) + time

        #math
        rtt = time/count

        num = 1460*math.sqrt(3/2)*8
        rateOfLoss = lossRateList[i][2]/lossRateList[i][1]
        denom = math.sqrt(rateOfLoss)*rtt
        theoreticalThroughput = -10
        try:
            theoreticalThroughput = (num/denom)/1000000
        except ZeroDivisionError:
            pass

        returnValues.append([lossRateList[i][0], rtt, throughputList[i][1], theoreticalThroughput])

    return returnValues

#print out rtt info
def printRtt(returnValues):
    for i in range(0,len(returnValues)):
        print("\nSource Port " + str(returnValues[i][0]) + ":")
        print("\tRTT: {:.5}".format(returnValues[i][1]) + " seconds")
        print("\tExperimental Throughput: {:.5}".format(returnValues[i][2]) + " Mbps")
        if(returnValues[i][3]>=0):
            print("\tTheoretical Throughput: {:.5}".format(returnValues[i][3]) + " Mbps")
        else:
            print("\tTheoretical Throughput: infinity")

def findFirst10CongestionWindows():
    list10CongestionWindow = []
    indexes = confirm3wayhandshake()
    returnValues = rtt()
    for i in range(0,len(flows)):
        #calculate the bins as a continuous addition of rtt
        bins = []
        for j in range(0,11):
            temp = round(returnValues[i][1], 2)
            bins.append(temp*j)

        #count how many packets get sent within that period of time
        times = []
        counts = []
        for j in range(0,len(bins)-1):
            counts.append(0)
        source = flows[i][0]["SOURCE"]
        initTime = flows[i][0]["TIME"]

        for j in range(indexes[i], len(flows[i])):
            if(flows[i][j]["SOURCE"]== source):
                tempTime = flows[i][j]["TIME"]- initTime
                times.append(tempTime)
                for m in range(1,len(bins)):
                    if(tempTime<bins[m]):
                        counts[m-1] = counts[m-1]+1
                        break
        #histograms will appear
        plt.hist(times, bins = bins , histtype='bar', ec='black')
        plt.xlabel('Time')
        plt.ylabel('Number of Packets sent')
        tempStr = "Source Port " + str(source)
        plt.title(tempStr)
        plt.xticks(bins)

        plt.show()

        #for window size
        for i in range(0,len(counts)):
            counts[i] = counts[i]*1448

        growth = []
        for i in range(1,len(counts)):
            if(counts[i-1]!=0):
                growth.append(counts[i]/counts[i-1])

        dic = {"SOURCE": source, "10": counts, "GROWTH": growth}
        list10CongestionWindow.append(dic)
    return list10CongestionWindow

#print info from 10 conjestions windows for each source
def print10CongestionWindow(list10CongestionWindow):
    for i in range(0,len(list10CongestionWindow)):
        print("\nSource Port: " + str(list10CongestionWindow[i]["SOURCE"]))
        print("\tFirst 10 Congestion Window Sizes: "+ str(list10CongestionWindow[i]["10"]))
        print("\tGrowth Factors After First Non-Zero Congestion Window: [", end = "")
        for j in range(0,len(list10CongestionWindow[i]["GROWTH"])-1):
            print("{:.3}, ".format(list10CongestionWindow[i]["GROWTH"][j]), end=" ")
        print("{:.3}]".format(list10CongestionWindow[i]["GROWTH"][-1]))

def numberRetransmissionTimeout():
    info = []

    for i in range(0,len(flows)):
        sentDic = []
        receivedDic = []

        sentDicHelper = []
        receivedDicHelper = []

        retransSent = []
        retransReceived = []

        source = flows[i][0]["SOURCE"]
        #get retransmitted packets and acks for these
        for j in range(0,len(flows[i])):
            #sender
            if(flows[i][j]["SOURCE"]==source):
                if(flows[i][j]["SEQUENCE"] in sentDicHelper):
                    found = 0
                    for m in range(0,len(retransSent)):
                        if(retransSent[m]["SEQUENCE"]==flows[i][j]["SEQUENCE"]):
                            found = 1
                            retransSent[m]["COUNT"] = retransSent[m]["COUNT"] +1
                            retransSent[m]["PACKETS"].append(flows[i][j])
                    if(found==0):
                        packet1 = sentDic[sentDicHelper.index(flows[i][j]["SEQUENCE"])]["PACKET"]
                        dic = {"SEQUENCE" : flows[i][j]["SEQUENCE"], "COUNT": 2, "PACKETS" :[packet1, flows[i][j]]}
                        retransSent.append(dic)
                else:
                    dic = {"SEQUENCE": flows[i][j]["SEQUENCE"], "PACKET": flows[i][j]}
                    sentDic.append(dic)
                    sentDicHelper.append(flows[i][j]["SEQUENCE"])
            #receiver
            else:
                if(flows[i][j]["ACK"] in receivedDicHelper):
                    found = 0
                    for m in range(0,len(retransReceived)):
                        if((retransReceived[m]["ACK"]==flows[i][j]["ACK"]) and (retransReceived[m]["SEQUENCE"]==flows[i][j]["SEQUENCE"])):
                            found = 1
                            retransReceived[m]["COUNT"] = retransReceived[m]["COUNT"] +1
                            retransReceived[m]["PACKETS"].append(flows[i][j])
                    if(found==0):
                        packet1 = receivedDic[receivedDicHelper.index(flows[i][j]["ACK"])]["PACKET"]
                        dic = {"SEQUENCE": flows[i][j]["SEQUENCE"], "ACK" : flows[i][j]["ACK"], "COUNT": 2, "PACKETS" :[packet1, flows[i][j]]}
                        retransReceived.append(dic)   
                else:
                    dic = {"ACK": flows[i][j]["ACK"], "PACKET": flows[i][j]}
                    receivedDic.append(dic)
                    receivedDicHelper.append(flows[i][j]["ACK"])
        

        #count number of acks between retranmission
        count = 0
        for j in range(0,len(retransSent)):
            for m in range(0,len(retransReceived)):
                if(retransReceived[m]["ACK"]==retransSent[j]["SEQUENCE"]):
                    temp =0
                    for item in retransReceived[m]["PACKETS"]:
                        if((item["TIME"]>retransSent[j]["PACKETS"][0]["TIME"])and (item["TIME"]<retransSent[j]["PACKETS"][1]["TIME"])):
                            temp = temp+1
                            if(temp>=3):
                                count = count +1
                                break
        
        tempDic = {"SOURCE": source, "ALL": (len(retransSent)-1), "TIMEOUT": (len(retransSent)-count-1), "TDA": count}
        info.append(tempDic)

    return info

def printNumberRetransmissionTimeout(info):
    for i in range(0,len(info)):
        print("Source Port " + str(info[i]["SOURCE"]) + ":")
        print("\tTotal Number of Retransmissions: " + str(info[i]["ALL"]))
        print("\tNumber Due to Triple Dup Acks: " + str(info[i]["TDA"]))
        print("\tNumber Due to Timeouts: " + str(info[i]["TIMEOUT"]))

truth1 = 0
while(truth1 ==0):
    fileName = input("\nPlease provide the name of the pcap file you would like to read (ex. assignment2.pcap):\n")
    # fileName = "assignment2.pcap"
    try:
        pkts =  dpkt.pcap.Reader(open(fileName,'rb')).readpkts()
        truth1 = 1
    except FileNotFoundError:
        print("\nThe file name you provided was incorrect, please try again!")
packets = generalFile.getPacketsInReadableForm(pkts)
flows = generalFile.setUpFlow(packets)
truth = 0
while(truth==0):
    try:
        print("\nWhat information would you like? [1/2/3/4/5/6/7/8]")
        print("\t1) Number of flows")
        print("\t2) Sequence number, Ack number, and Receive Window size for first 2 trasactions after TCP setup is done")
        print("\t3) Throughput")
        print("\t4) Loss Rate")
        print("\t5) Average RTT")
        print("\t6) First 10 Conjestion Window Sizes")
        print("\t7) Number of Retransmission Due to Triple Duplicate Ack and Due to Timeout")
        print("\t8) Exit")

        answer = input("").replace(" ", "")

        if(answer =="1"):
            generalFile.printFlows(flows)
        elif(answer =="2"):
            listOfTransactions = find2TransactionsAfterTCPSetup()
            print2TransactionsAfterTCPSetupInfo(listOfTransactions)
        elif(answer == "3"):
            throughputList = throughput()
            printThroughput(throughputList)
        elif(answer == "4"):
            lossRateList = lossRate()
            printLossRate(lossRateList)
        elif(answer == "5"):
            returnValues = rtt()
            printRtt(returnValues)
        elif(answer == "6"):
            list10CongestionWindow = findFirst10CongestionWindows()
            print10CongestionWindow(list10CongestionWindow)
        elif(answer == "7"):   
            info = numberRetransmissionTimeout()
            printNumberRetransmissionTimeout(info)
        elif(answer=="8"):
            truth = 1
        else:
            print("Wrong input, please try again.")

        if(answer!="8"):
            answer2 = input("\nContinue? [Y/N]\t").replace(" ", "")
            if((answer2!="Y") and (answer2!="y") and (answer2!="YES")):
                truth =1

    except tcpConnectionUnsuccessful:
        print("\nTcp Error, please try again.")
    except packetLostFirst2Transactions:
        print("\nOne of the first two packets sent were lost, please try again with a different input.")
    # except FileNotFoundError:
    #     print("The file name you provided was incorrect, please try again!")