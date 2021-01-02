from pip._vendor.distlib.compat import raw_input
import dns.query
import dns.resolver
import dns.message
import sys
import time
from datetime import datetime
import re
import copy

#list of root servers 
rootServers = ["198.41.0.4","199.9.14.201","192.33.4.12", "199.7.91.13", "192.203.230.10", 
                "192.5.5.241", "192.112.36.4", "198.97.190.5", "192.58.128.30", "193.0.14.129", 
                "199.7.83.42", "202.12.27.33"]

queryTypes = ["A", "NS", "MX"]

daysOfWeek = ["Mon", "Tues", "Wed", "Thurs", "Fri", "Sat", "Sun"]
months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]

rootServerFound = ""
msgSize =0
globalIP = ""
globalCNAME = 0

#errors
class errorMessageFormat(Exception):
    pass
    
class errorMessageInput(Exception):
    pass

class errorMessageNoWorkingRootServer(Exception):
    pass

class errorMessageWebsiteDoesNotExist(Exception):
    pass

class errorMessageWebsiteRootServerProblem(Exception):
    pass

#dns print messages
def printQuestion(website, queryType):
    string = ""
    if(website[-1]!="."):
        string = "\nQUESTION SECTION:\n" + website + ".\t\t" + "IN\t" + queryType
    else:
        string = "\nQUESTION SECTION:\n" + website + "\t\t" + "IN\t" + queryType
    
    print(string)
    return len(string)

def printAnswer(website, queryType, ipAddress):
    string = ""

    if(website[-1]!="."):
        string = "\nANSWER SECTION:\n" + website + ".\t\t" + "IN\t" + queryType + "\t\t" + ipAddress + "\n"
    else:
        string = "\nANSWER SECTION:\n" + website + "\t\t" + "IN\t" + queryType + "\t\t" + ipAddress + "\n"

    print(string)
    return len(string)

def printAdditionalInfo(startTime, dateTime, msgSize):
    weekday = dateTime.weekday()
    endTime = time.time()  
    timeElapsed = int(round((endTime - startTime)*1000))

    print("\nQuery time: " + str(timeElapsed) + " msec")
    print("WHEN: " + daysOfWeek[weekday] + " " + months[dateTime.month -1] + " "+ str(dateTime.day)+ " "
    + str(dateTime.hour) + ":"+ str(dateTime.minute)+":"+ str(dateTime.second) +" " + str(dateTime.year))
    print("MSG SIZE rcvd: " + str(msgSize) + "\n")

def printAuthority(website):
    print("\nAUTHORITY SECTION:")



#iterate dns request untill answer is resolved
#when answer is resolved, will directly call the print function
def iterateQuery(website, ipAddress, queryType, startTime, dateTime, msgSize, rootServerFound, orgWebsite, DNSSec=False):
    answer = dns.message.make_query(website, queryType)
    response = answer
    while(response==answer):
        try:
            response = dns.query.udp(answer, ipAddress, 4) #RAISE ERROR IF LONGER
        except dns.exception.Timeout:
            pass

    #seperate the various sections
    answerdns = response.answer
    additionaldns = response.additional
    authoritydns = response.authority

    global globalIP
    global globalCNAME
    #if there is something present in the answer section
    if(answerdns != []):
        for lines in answerdns:

            #NOT SURE IF I SHOULD REITERATE UNTIL I FIND ANSWER FLAG BEFORE SEARCHING THROUGH CNAME
            answerSplit = lines.to_text()
            answerSplit = answerSplit.split(" ")

            #I have found the answer
            if((answerSplit[3]=="A") or (answerSplit[3]=="MX") or (answerSplit[3]=="NS")):
                #if the answer was the address of the NS, I must ask again with the actual domain desired
                temp = answerSplit[4].split("\n")[0]
                flag = 0
                if(answerSplit[3]!="A"):
                    #to get the full answer for MX and NS
                    for i in range(5, len(answerSplit)):
                        temp2 = answerSplit[i].split("\n")[0]
                        if(len(temp2)>1):
                            flag = 1
                        if(temp2[len(temp2)-1].isnumeric()==False):
                            temp2 = temp2.replace("IN", "")
                            temp = temp + " " + temp2
                            if(flag ==1):
                                break
  
                if(website!=orgWebsite):
                    if(DNSSec==True):
                        globalIP = temp
                    elif(globalCNAME==0):
                        iterateQuery(orgWebsite, temp, queryType, startTime, dateTime, msgSize, rootServerFound, orgWebsite, DNSSec)
                    else:
                        msgSize = msgSize + printAnswer(website, queryType, temp)
                        printAdditionalInfo(startTime, dateTime, msgSize)
                else:
                    if(DNSSec==False):
                        msgSize = msgSize + printAnswer(website, queryType, temp)
                        printAdditionalInfo(startTime, dateTime, msgSize)
                    else:
                        globalIP = temp
                break

            #reiterate until answer is found         
            elif (answerSplit[3]=="CNAME"):
                globalCNAME = 1
                if queryType=="NS":
                    temp = answerSplit[4].split("\n")[0]
                    if(DNSSec==False):
                        msgSize = msgSize + printAnswer(website, queryType, temp)
                        printAdditionalInfo(startTime, dateTime, msgSize)
                    else:
                       globalIP = temp
                else:
                    iterateQuery(answerSplit[4], rootServerFound, queryType, startTime, dateTime, msgSize, rootServerFound, orgWebsite, DNSSec)  
                break

    elif(additionaldns != []):
        for lines in additionaldns: #CHANGE
            #additional section has an ip addrs that will use in iterative function
            additionalSplit = lines.to_text()
            additionalSplit = additionalSplit.split(" ")
            additionalSplit[4] = additionalSplit[4].split("\n")[0]
            if(additionalSplit[3]=="A"):
                iterateQuery(website, additionalSplit[4], queryType, startTime, dateTime, msgSize, rootServerFound, orgWebsite, DNSSec)
                break
            elif ((additionalSplit[3]=="CNAME")or(additionalSplit[3]=="NS")): #just added
                iterateQuery(additionalSplit[4], rootServerFound, queryType, startTime, dateTime, msgSize, rootServerFound, orgWebsite, DNSSec)  
                break           
    elif(authoritydns !=[]):
        #authority is the last place the answer can be
        for item in authoritydns:
            temp = item.to_text().split(" ")
            temp[4] = temp[4].split("\n")[0]
            if((temp[3]=="NS")or(temp[3]=="CNAME")):
                iterateQuery(temp[4], rootServerFound, queryType, startTime, dateTime, msgSize, rootServerFound, orgWebsite, DNSSec)
                break
            elif(temp[3]=="A"):
                iterateQuery(website, temp[4], queryType, startTime, dateTime, msgSize, rootServerFound, orgWebsite, DNSSec)
                break
            elif(temp[3]=="SOA"):
                if(website != orgWebsite):
                    if(DNSSec==False):
                        iterateQuery(orgWebsite, ipAddress, queryType, startTime, dateTime, msgSize, rootServerFound, orgWebsite, DNSSec)
                    else:
                        globalIP = ipAddress
                        break
                else:
                    if(DNSSec==False):
                        text = ""
                        for i in range(5, len(temp)):
                            text = text + temp[i] + " "
                        msgSize = msgSize + printAnswer(website, "SOA", text)
                        printAdditionalInfo(startTime, dateTime, msgSize)
                        break



#finds working root server and proceeds to iterate query
def findWorkingRootServer(website, queryType, DNSSec = False):
    startTime = time.time()
    dateTime = datetime.now()

    answer = dns.message.make_query(website, queryType)
    rootServerFound = ""
    while(rootServerFound==""):
        for i in range(0, len(rootServers)):
            try:
                dns.query.udp(answer, rootServers[i], 4)
                rootServerFound = rootServers[i]
                break
            except dns.exception.Timeout:
                pass
            except IOError:
                pass
    iterateQuery(website, rootServerFound, queryType, startTime, dateTime, msgSize, rootServerFound, website, DNSSec)


#DNNSEC************************************************************************************

#errors
class errorMessageVerificationFailed(Exception):
    pass

class errorMessageDNNSecNotSupported(Exception):
    pass

#when verified
def printDNNSECVerified(ipAddress, queryType):
    if(queryType!= "MX"):
        ipAddress = ipAddress.split("\n")[0]
    print("\nDNNSEC configured.\n" + ipAddress + " is the verified answer.")


# def iterateDNNSecQuery(website, websitePart, queryType, ipAddr):
def rootServerDNNSECValidate(website, queryType):
    #trust anchors obtained from github code: https://github.com/iana-org/get-trust-anchor
    #also obtainable from: http://data.iana.org/root-anchors/root-anchors.xml
    #can use either trust anchor for verification, I used the first
    trustAnchor = "20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"
    #obtainable from: https://www.afrinic.net/blog/265-dnssec-new-root-zone-ksk-appears-on-the-dns
    anchor = "257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+e oZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU="
    
    #algorithm corresponding obtained from: https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml
    algorithm = "SHA256"

    #I request the DS record and DNSKEY from the root
    answer = dns.message.make_query(website, queryType, want_dnssec=True)
    answer2 =dns.message.make_query(".", "DNSKEY", want_dnssec=True)
    
    response = answer
    response2 = answer2

    rootIP = ""
    #I wait until I get a response from the root
    while(response == answer):
        for i in range(0, len(rootServers)):
            try:
                response = dns.query.udp(answer, rootServers[i], 4)
                response2 = dns.query.udp(answer2, rootServers[i],4)
                rootIP = rootServers[i]
                break
            except dns.exception.Timeout:
                pass
            except IOError:
                pass   

    #I verify that the KSK provided is the same as the trust anchor
    rrsigDNSKey = ""
    DNSKey = ""
    name = ""
    dsValTrust = ""

    for lines in response2.answer:
        lineSplit = lines.to_text().split(" ")
        if(lineSplit[3]!="RRSIG"):
            # if(ipAddr == ""):
            for i in lines.items:
                temp = i.to_text()
                if("257" in temp):
                    dsValTrust = dns.dnssec.make_ds(".", i, algorithm).to_text().upper()
            if (dsValTrust != trustAnchor):
                raise errorMessageVerificationFailed
            name = lines.name
            DNSKey = lines
     
        else:
            rrsigDNSKey = lines

    dicDNSKey = {name: DNSKey}
    
    #I validate the DNSKEY with it's RRSIG
    try:
        dns.dnssec.validate(DNSKey, rrsigDNSKey, dicDNSKey)
    except dns.dnssec.ValidationFailure:
        raise errorMessageVerificationFailed


    #I get DS value and corresponding RRSIG value
    rrsigDS = ""
    dsVal = ""
    for lines in response.authority:
        temp = lines.to_text().split(" ")
        if(temp[3]=="DS"):
            dsVal = lines
            nameDic = lines.name
        elif(temp[3]=="RRSIG"):
            rrsigDS = lines

    dicDS = {name: DNSKey}
    #I validate the DS record with it's RRSIG
    try:
        dns.dnssec.validate(dsVal, rrsigDS, dicDS)
    except dns.dnssec.ValidationFailure:
        raise errorMessageVerificationFailed

    #to be passed on for verification
    dicValues = {"DS": dsVal, "RRSIG": rrsigDS, "NAME": nameDic}

    #obtain next ip
    if(response.additional !=[]):
        for items in response.additional:
            itemsTemp = items.to_text().split(" ")
            if(itemsTemp[3]=="A"):
                return itemsTemp[4], dicValues, rootIP
    return "", dicValues

#recursively check for dnnsec verification until answer is found
#when answer is found, will directly print answer
def iterateDNNSecQuery(website, websitePart, queryType, ipAddr, dicValues, orgWebsite, rootServerFound, flag, rootDicValues):
    #I expand the website part (ex. website part = com. and will become verisign.com.)
    if(websitePart!=""):
        if((website[-1]!=".")and (flag==0)):
            website = website +"."

    if(website!=orgWebsite):
        if(websitePart!=""):

            websiteSplit = website.split(".")
            websitePartSplit = websitePart.split(".")
            websiteSplit.pop()
            newWebsitePart = ""

            if(websitePartSplit[0]==""):
                websitePartSplit = []

            for i in range(1,len(websitePartSplit)):
                if(websitePartSplit[-i]==""):
                    websitePartSplit.pop()
            
            for i in range(1,(len(websitePartSplit)+2)):
                newWebsitePart = websiteSplit[-i] + "." + newWebsitePart
            websitePart = newWebsitePart
        else:
            websitePart = "."

    #org is weird and needs to be addressed seperately
    if(websitePart=="org."):
        website, websitePart, ipAddr, dicValues, rootServerFound =dnssecOrg(website,queryType, ipAddr, dicValues, rootServerFound, rootDicValues)

    #I query for dnskey and ds records
    answer = dns.message.make_query(website, queryType, want_dnssec=True)
    answer2 =dns.message.make_query(websitePart, "DNSKEY", want_dnssec=True) #255 = ANY

    response = dns.query.udp(answer, ipAddr, 4)
    response2 = dns.query.udp(answer2, ipAddr,4)


    #I validate the DNSKEY with it's RRSIG and obtain public key signing key
    rrsigDNSKey = ""
    DNSKey = ""
    name = ""
    dsVal = ""
    pubKSK = ""
    if(response2.answer!=[]):
        for lines in response2.answer:
            lineSplit = lines.to_text().split(" ")
            if(lineSplit[3]!="RRSIG"):
                for items in lines.items:
                    temp = items.to_text()
                    if("257" in temp):
                        pubKSK = items
                name = lines.name
                DNSKey = lines 
            else:
                rrsigDNSKey = lines

        dicDNSKey = {name: DNSKey}

        try:
            dns.dnssec.validate(DNSKey, rrsigDNSKey, dicDNSKey)
        except dns.dnssec.ValidationFailure:
            raise errorMessageVerificationFailed 
    else:
        raise errorMessageDNNSecNotSupported

    #I validate the zone by performing a has on the pubksk and compare to the parent
    algorithms = ["SHA256", "SHA1"]
    ds256 = dns.dnssec.make_ds(dicValues["NAME"], pubKSK, algorithms[0]).to_text().upper().strip()
    ds1 = dns.dnssec.make_ds(dicValues["NAME"], pubKSK, algorithms[1]).to_text().upper().strip()
    
    #compare to parent
    if((ds256 not in dicValues["DS"].to_text().upper()) and (ds1 not in dicValues["DS"].to_text().upper())):
        raise errorMessageVerificationFailed
    
    nameDic = ""
    rrsigDS = ""
    authorityFlag = 0
    answerFlag = 0
    if(response.answer!=[]):
        answerFlag =1
        answerList = []

        for lines in response.answer:
            answerList.append(lines)

        for lines in response.answer:
            answerSplit = lines.to_text()
            answerSplit = answerSplit.split(" ")

            #I have found the answer
            if((answerSplit[3]=="A") or (answerSplit[3]=="MX") or (answerSplit[3]=="NS")):
                #validate records
                rrsigA = ""
                for item in answerList:
                    itemSplit = item.to_text().split(" ")
                    if("RRSIG" in itemSplit[3]):
                        rrsigA = item
                
                dicDS = {lines.name: DNSKey}
                #I validate the DS record with it's RRSIG
                try:
                    dns.dnssec.validate(lines, rrsigA, dicDS)
                except dns.dnssec.ValidationFailure:
                    raise errorMessageVerificationFailed
                
                #if the answer was the address of the NS, I must ask again with the actual domain desired
                temp = answerSplit[4].split("\n")[0]
                tempOrgWebsite = orgWebsite
                if(tempOrgWebsite[-1]!="."):
                    tempOrgWebsite = tempOrgWebsite + "."
                if(website!=tempOrgWebsite):
                    iterateDNNSecQuery(orgWebsite, websitePart, queryType, ipAddr, dicValues, orgWebsite, rootServerFound, 1, rootDicValues)
                    break
                else:
                    #Just for proper formatting of the answer (later can change to seperate function)
                    count = len(answerSplit)
                    for i in range(0, count):
                        if("\n" in answerSplit[i]):
                            temp = answerSplit[i].split("\n")
                            answerSplit.pop(i)
                            for m in range(0, len(temp)):
                                answerSplit.insert(i+m,temp[m])
                            count = count+1

                    ipAddrAnswer = answerSplit[4]
                    if(len(answerSplit)>4):
                        first = answerSplit[0]
                        for m in range(5, len(answerSplit)):
                            if(first ==answerSplit[m]): 
                                break
                            else:
                                ipAddrAnswer = ipAddrAnswer + " " +  answerSplit[m]

                    printDNNSECVerified(ipAddrAnswer, queryType)
                    break
       
            elif (answerSplit[3]=="CNAME"):
                iterateDNNSecQuery(answerSplit[4], websitePart, queryType, ipAddr, dicValues, orgWebsite, rootServerFound,0, rootDicValues)
                break
    #DS record only exists if answer is not present (aka, there is another path to follow)
    #DS record always exists in authority section
    elif(response.authority!=[]):
        authorityFlag = 1
        dsRecordPresent = 0
        for lines in response.authority:
            temp = lines.to_text().split(" ")
            if(temp[3]=="DS"):
                dsVal = lines
                nameDic = lines.name
                dsRecordPresent = 1
            elif(temp[3]=="RRSIG"):
                rrsigDS = lines
        if(dsRecordPresent==1):
            dicDS = {name: DNSKey}
            #I validate the DS record with it's RRSIG
            try:
                dns.dnssec.validate(dsVal, rrsigDS, dicDS)
            except dns.dnssec.ValidationFailure:
                raise errorMessageVerificationFailed
        else:
            raise errorMessageDNNSecNotSupported

    #I get the Ip to be used again
    if((response.additional!=[])and (answerFlag==0)):
        dicValues = {"DS": dsVal, "RRSIG": rrsigDS, "NAME": nameDic}
        for lines in response.additional:
            #additional section has an ip addrs that will use in iterative function
            additionalSplit = lines.to_text()
            additionalSplit = additionalSplit.split(" ")
            additionalSplit[4] = additionalSplit[4].split("\n")[0]
            if(additionalSplit[3]=="A"):
                iterateDNNSecQuery(website, websitePart, queryType, additionalSplit[4], dicValues, orgWebsite, rootServerFound, 0, rootDicValues)
                break
            elif ((additionalSplit[3]=="CNAME")or(additionalSplit[3]=="NS")): #just added
                iterateDNNSecQuery(additionalSplit[4], ".", queryType, rootServerFound, rootDicValues, orgWebsite, rootServerFound, 0, rootDicValues)
                break  
    elif((response.authority !=[])and(answerFlag==0)):
        for item in response.authority:
            temp = item.to_text().split(" ")
            temp[4] = temp[4].split("\n")[0]
            if((temp[3]=="NS")or(temp[3]=="CNAME")):
                iterateDNNSecQuery(temp[4], ".", queryType, rootServerFound, rootDicValues, orgWebsite, rootServerFound, 0, rootDicValues)
                break
            elif(temp[3]=="A"):
                iterateDNNSecQuery(website, websitePart, queryType, temp[4], dicValues, orgWebsite, rootServerFound, 0, rootDicValues)
                break
            elif(temp[3]=="SOA"):
                if(website != orgWebsite):
                    iterateDNNSecQuery(orgWebsite, websitePart, queryType, ipAddr, dicValues, orgWebsite, rootServerFound, 0, rootDicValues)             
                else:
                    text = ""
                    for i in range(5, len(temp)):
                        text = text + temp[i] + " "
                    printDNNSECVerified(text, "SOA")
                    break



def dnssecOrg(website, queryType, ipAddr, dicValues, rootIP, rootDicValues):
    #algorithms for hashing
    algorithm1 = "SHA256"
    algorithm2 = "SHA1"
    #I query for dnskey and ds records
    answer = dns.message.make_query(website, queryType, want_dnssec=True)
    answer2 =dns.message.make_query("org.", "RRSIG", want_dnssec=False) #255 = ANY
    answer3 = dns.message.make_query("org.", "DNSKEY", want_dnssec=False)
    
    #ds record
    response = dns.query.udp(answer, ipAddr, 4)
    
    #rrsig
    arrayOfRSSIG = []
    arrayOfRSSIG2 = []
    temprrsig = ""

    while(len(arrayOfRSSIG)==0):
        response2 = dns.query.udp(answer2, ipAddr,4)
        for lines in response2.answer:
            arrayOfRSSIG.append(lines)
            for items in lines:
                temprrsig = items


    while (len(arrayOfRSSIG2)<2):
        response2 = dns.query.udp(answer2, ipAddr,4)
        if(response2.answer!=[]):
            for lines in response2.answer:
                for items in lines:
                    if(arrayOfRSSIG2 == []):
                        arrayOfRSSIG2.append(items)
                    else:
                        if (items != arrayOfRSSIG2[0]):
                            arrayOfRSSIG2.append(items)

    
    
    #dnskey
    response3 = dns.query.udp(answer3, ipAddr,4)
    while(response3.answer==[]):
        response3 = dns.query.udp(answer3,ipAddr)

    name = ""
    dnskey = ""
    if(len(response3.answer[0])==2):
        dnskey = response3.answer[0]

    timeStart = time.time()               

    #I get four unique dnskey values
    while(len(dnskey)<4):
        timeNow = time.time()
        if((timeNow-timeStart)>1):
            dnskey = ""
            timeStart = time.time()
        answer3 = dns.message.make_query("org.", "DNSKEY", want_dnssec=False)
        response3 = dns.query.udp(answer3, ipAddr)
        if((response3.answer!=[])and(len(response3.answer[0])==2)):
            flag =0
            if(dnskey!=""):
                for i in range(0,len(dnskey)):
                    for m in range(0,len(response3.answer[0])):
                        if(response3.answer[0][m]==dnskey[i]):
                            flag=1
            if(flag==0):
                if(dnskey==""):
                    dnskey = response3.answer[0]
                else:
                    try:
                        dnskey.union_update(response3.answer[0])
                        name = response3.answer[0].name
                    except:
                        pass  

    number1 = ""
    val = ""
    dnskey1 = ""
    dnskey2 = ""
    while(len(dnskey1)<2):
        answer3 = dns.message.make_query("org.", "DNSKEY", want_dnssec=False)
        response3 = dns.query.udp(answer3, ipAddr)
        if(response3.answer!=[]):
            count = 0
            for items in response3.answer[0]:
                temp = items.to_text().split(" ")
                if(count ==0):
                    number1 = temp[2] 
                    val = temp[0]
                    count = 1
                else:
                    if(temp[2]==number1):
                        if(temp[0]!=val):
                            dnskey1 = response3.answer[0]
    
    while(len(dnskey2)<2):
        tempNum = ""
        answer3 = dns.message.make_query("org.", "DNSKEY", want_dnssec=False)
        response3 = dns.query.udp(answer3, ipAddr)
        if(response3.answer!=[]):
            count = 0
            for items in response3.answer[0]:
                temp = items.to_text().split(" ")
                if(count ==0):
                    tempNum = temp[2] 
                    val = temp[0]
                    count = 1
                else:
                    if(temp[2]!=number1):
                        if(temp[2]==tempNum):
                            if(temp[0]!=val):
                                dnskey2 = response3.answer[0]                  
    #join them
    dnskey1.union_update(dnskey2)
    try:
        dic = {name: dnskey}
        dns.dnssec.validate(dnskey, temprrsig, dic)
    except:
        pass


    #I validate the ds record
    dsRecordPresent =0
    nameDic = ""
    dsVal = ""
    rrsigDS = ""
    for lines in response.authority:
        temp = lines.to_text().split(" ")
        if(temp[3]=="DS"):
            dsVal = lines
            nameDic = lines.name
            dsRecordPresent = 1
        elif(temp[3]=="RRSIG"):
            rrsigDS = lines
    if(dsRecordPresent==1):
        dicDS = {name: dnskey}

        #I validate the DS record with it's RRSIG
        try:
            dns.dnssec.validate(dsVal, rrsigDS, dicDS)
        except dns.dnssec.ValidationFailure:
            raise errorMessageVerificationFailed
    else:
        raise errorMessageDNNSecNotSupported
    
    dicValuesNew = {"DS": dsVal, "RRSIG": rrsigDS, "NAME": nameDic}
    #verify zone
    array2store =[]
    for items in dnskey:
        temp = items.to_text().split(" ")
        if(temp[0]!="257"):
            array2store.append(items)

    for i in range(0,len(array2store)):
        dnskey.remove(array2store[i])

    ds256 = []
    ds1 = []
    for items in dnskey:
        ds256.append(dns.dnssec.make_ds(dicValues["NAME"], items, algorithm1))
        ds1.append(dns.dnssec.make_ds(dicValues["NAME"], items, algorithm2))

    found = 0
    for i in range(0,len(ds256)):
        for m in range(0, len(dicValues["DS"])):
            if((ds256[i].to_text()==dicValues["DS"][m].to_text())or (ds1[i].to_text()==dicValues["DS"][m].to_text())):
                found =1
    if(found ==0):
        raise errorMessageVerificationFailed


    websiteOriginal = website
    #obtain ns or ip to return
    if(response.additional!=[]):
        for lines in response.additional:
            #additional section has an ip addrs that will use in iterative function
            additionalSplit = lines.to_text()
            additionalSplit = additionalSplit.split(" ")
            additionalSplit[4] = additionalSplit[4].split("\n")[0]
            if(additionalSplit[3]=="A"):
                ipAddr = additionalSplit[4]
                break
            elif ((additionalSplit[3]=="CNAME")or(additionalSplit[3]=="NS")):
                website= additionalSplit[4]
                temp = website.split(".")
                websitePart = temp[-2]+ "."
                ipAddr, dicValues, rootIP = rootServerDNNSECValidate(website, queryType)
                iterateQuery(website, ipAddr,queryType, time.time(),datetime.now(), 0, rootIP, website, True)

                ipAddr = globalIP
                while(ipAddr==""):  
                    ipAddr = globalIP
                break  
    elif(response.authority !=[]):
        for item in response.authority:
            temp = item.to_text().split(" ")
            temp[4] = temp[4].split("\n")[0]
            if((temp[3]=="NS")or(temp[3]=="CNAME")):
                website = temp[4]
                temp = website.split(".")
                websitePart = temp[-2]+ "."
                ipAddr, dicValues, rootIP = rootServerDNNSECValidate(website, queryType)
                iterateQuery(website, ipAddr,queryType, time.time(),datetime.now(), 0, rootIP, websiteOriginal, True)
                
                ipAddr = globalIP
                while(ipAddr==""):  
                    ipAddr = globalIP 
            elif(temp[3]=="A"):
                ipAddr = temp[4]
                break

    return websiteOriginal, websiteOriginal, ipAddr, dicValuesNew, rootIP
            

#read in arguments and see if valid
#valid arguments come in the form "./mydig website query" or  "./mydig website query +dnssec"
#query is limited to "A", "MX", and "NS"

#TEMPORARY

# userInput = raw_input("").split(" ")
userInput = sys.argv
# print(sys.argv)
try:
    if(len(userInput)==4):
        if(userInput[3]!="+dnssec"):
            raise errorMessageInput
    elif(len(userInput)!=3):
        raise errorMessageFormat

    if(userInput[2] not in queryTypes):
        raise errorMessageInput
    if(userInput[0] != "./mydig"):
        raise errorMessageInput
    if(len(userInput[1])>253):
        raise errorMessageInput
        
    #validate domain name
    match = re.match(r'[a-zA-Z0-9][-\.a-zA-Z0-9]*',userInput[2])

    if(not match):
        raise errorMessageInput
        
    #remove http in any form
    userInput[1] = userInput[1].replace("http://", "")
    userInput[1] = userInput[1].replace("Http://", "")
    userInput[1] = userInput[1].replace("HTTP://", "")
    #remove any trailing slashes
    if(userInput[1][-1]=="/"):
        userInput[1] = userInput[1][:(len(userInput[1])-1)]
    if(len(userInput)!=4):
        findWorkingRootServer(userInput[1], userInput[2])
    else:
        ipAddr, dicValues, rootIP = rootServerDNNSECValidate(userInput[1], userInput[2])
        iterateQuery(userInput[1], rootIP, userInput[2], time.time(), datetime.now(), 0, rootIP, userInput[1], DNSSec=True)
        #without www.
        userInput[1] = userInput[1].replace("www.", "")
        ipAddr, dicValues, rootIP = rootServerDNNSECValidate(userInput[1], userInput[2])
        globalCNAME = 0
        if(globalIP!=""):
            globalIP = ""
            iterateDNNSecQuery(userInput[1], ".", userInput[2], ipAddr, dicValues, userInput[1], rootIP, 0, dicValues)
        else:
            print("\nSorry, there is not a solution to your query.")

                
except errorMessageFormat:
    print("\nError: Incorrect format, please try again.\n")
except errorMessageInput:
    print("\nError: Incorrect input, please try again.\n")
except errorMessageNoWorkingRootServer:
    print("\nError: Root server problem, please try again later.\n")
except errorMessageVerificationFailed:
    print("\nDNSSec verification failed")
except errorMessageDNNSecNotSupported:
    print("\nDNSSEC not supported")

        


    







