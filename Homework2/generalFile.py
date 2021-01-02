import copy

#gets packets in dictionary format
def getPacketsInReadableForm(pkts): #not sure if i should make this into an object later
    packets = []

    for packet in pkts:
        sourcePort = int.from_bytes(packet[1][34:36], byteorder='big')
        destinationPort = int.from_bytes(packet[1][36:38], byteorder='big')
        sequenceNumber = int.from_bytes(packet[1][38:42], byteorder='big')
        ack = int.from_bytes(packet[1][42:46], byteorder='big')
        lengthOfHead = 4*(int.from_bytes(packet[1][46:47], byteorder='big')>>4)
        
        #flags - fin, syn, rst, psh, ack, urg
        flag = int.from_bytes(packet[1][47:48], byteorder='big')
        tempFlag = copy.deepcopy(flag)
        arrayOfFlags = [(tempFlag&1)]
        for i in range(0,5):
            tempFlag = tempFlag >>1
            arrayOfFlags.append((tempFlag&1))

        window = int.from_bytes(packet[1][48:50], byteorder='big')
        checkSum = int.from_bytes(packet[1][50:52], byteorder='big')
        urgentPointer = int.from_bytes(packet[1][52:54], byteorder='big')
        payload = packet[1][(34+lengthOfHead):]
        payloadLength = len(packet[1][(34+lengthOfHead):])
        
        scale = 1<<(int.from_bytes(packet[1][73:74], byteorder='big'))

        dic = {"TIME": packet[0], "INFO": packet[1], "SIZE": len(packet[1]), "SOURCE": sourcePort, 
        "DESTINATION": destinationPort, "SEQUENCE": sequenceNumber, "ACK": ack, 
        "HEAD LENGTH": lengthOfHead, "FLAG": flag, "FLAG SEP": arrayOfFlags, "WINDOW": window, 
        "CHECKSUM": checkSum, "URGENTPOINTER": urgentPointer, "PAYLOAD": payload, "PAYLOAD LENGTH": payloadLength, "SCALE": scale}

        packets.append(dic)
    return packets

def setUpFlow(packets):
    # global flows
    flows = []

    for items in packets:
        if flows == []:
            flows.append([items])
        else:
            found = 0
            for i in range(0,len(flows)):
                truth1 = (items["SOURCE"] == flows[i][0]["SOURCE"])or(items["SOURCE"] == flows[i][0]["DESTINATION"])
                truth2 = (items["DESTINATION"] == flows[i][0]["SOURCE"])or(items["DESTINATION"] == flows[i][0]["DESTINATION"])
                if(truth1 and truth2):
                    found =1
                    flows[i].append(items)
            if(found==0):
                flows.append([items])

    return flows

def printFlows(flows):
    print("\nThe flows start at ports: ", end="")
    for i in range(0,len(flows)-1):
        print(str(flows[i][0]["SOURCE"])+ ", ", end="")
    print("and " + str(flows[len(flows)-1][0]["SOURCE"]) + ".")
    print("There are " + str(len(flows)) + " flows.\n")