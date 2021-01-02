import copy
import socket
import struct
import binascii
import ipaddress


#gets packets in dictionary format
def getPacketsInReadableForm(pkts): #not sure if i should make this into an object later
    packets = []

    for packet in pkts:
        sourcePort = int.from_bytes(packet[1][34:36], byteorder='big')
        destinationPort = int.from_bytes(packet[1][36:38], byteorder='big')
        sequenceNumber = int.from_bytes(packet[1][38:42], byteorder='big')
        ack = int.from_bytes(packet[1][42:46], byteorder='big')
        lengthOfHead = 4*(int.from_bytes(packet[1][46:47], byteorder='big')>>4)
        # lengthOfHeadDNS = int.from_bytes(packet[1][16:17], byteorder='big')
        lengthOfHeadDNS = 2*(int.from_bytes(packet[1][14:15], byteorder='big')>>4)
        lengthOfUDPHead = 0
        
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

        payloadDNS = packet[1][(34+lengthOfHeadDNS):]
        payloadLengthDNS = len(packet[1][(34+lengthOfHeadDNS+lengthOfUDPHead):])

        ipAddSource = 0
        ipAddDest = 0

        try:
            # bytesIpSource = binascii.hexlify(packets[i]["INFO"][26:30])
            # addLongSource = int(bytesIpSource, 16)
            # ipAddSource = socket.inet_ntoa(struct.pack(">L", addLongSource))

            # ipAddSourceDNS = str(ipaddress.ip_address(packets[i]["INFO"][26:30]))
            # ipAddDestDNS = str(ipaddress.ip_address(packets[i]["INFO"][30:34]))
            ipAddSource = str(ipaddress.ip_address(packet[1][26:30]))
            ipAddDest = str(ipaddress.ip_address(packet[1][30:34]))

            # #works
            # ipAddSource = str(socket.inet_ntoa(packet[1][26:30]))
            # ipAddDest = str(socket.inet_ntoa(packet[1][30:34]))


            # bytesIpDest = binascii.hexlify(packets[i]["INFO"][30:34])
            # addLongDest = int(bytesIpDest, 16)
            # ipAddDest = socket.inet_ntoa(struct.pack(">L", addLongDest))
        except IndexError:
            pass

        
        
        scale = 1<<(int.from_bytes(packet[1][73:74], byteorder='big'))

        dic = {"TIME": packet[0], "INFO": packet[1], "SIZE": len(packet[1]), "SOURCE": sourcePort, 
        "DESTINATION": destinationPort, "SEQUENCE": sequenceNumber, "ACK": ack, 
        "HEAD LENGTH": lengthOfHead, "FLAG": flag, "FLAG SEP": arrayOfFlags, "WINDOW": window, 
        "CHECKSUM": checkSum, "URGENTPOINTER": urgentPointer, "PAYLOAD": payload, "PAYLOAD LENGTH": payloadLength, "SCALE": scale,
        "DNS HEAD LENGTH": lengthOfHeadDNS, "PAYLOAD DNS": payloadDNS, "PAYLOAD LENGTH DNS": payloadLengthDNS,
        "SOURCE IP": ipAddSource, "DEST IP": ipAddDest}

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