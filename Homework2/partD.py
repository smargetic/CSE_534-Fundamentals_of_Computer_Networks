import numpy as np
import matplotlib.pyplot as plt

def multiplicativeIncreaseAdditiveDecrease():
    x = 12
    y = 13

    listOfXY = [[x],[y]]
    for i in range(0,20):
        x = listOfXY[0][-1]
        y = listOfXY[1][-1]
        if((x+y)<50): #multiplicative
            x = x*2.5
            y = y*2.5
        else: #subtraction
            x = x-10
            y = y-10
        if((x>0)and(y>0)):
            listOfXY[0].append(x)
            listOfXY[1].append(y)

    return listOfXY


def multiplicativeIncreaseMultiplicativeDecrease():
    x = 5
    y = 13

    listOfXY = [[x],[y]]
    for i in range(0,20):
        x = listOfXY[0][-1]
        y = listOfXY[1][-1]
        if((x+y)<50): #multiplicative increase
            x = x*5
            y = y*5
        else: #division --> multiplicative decrease
            x = x/4.5
            y = y/4.5
        if((x>0)and(y>0)):
            listOfXY[0].append(x)
            listOfXY[1].append(y)
    
    return listOfXY

def additiveIncreaseAdditiveDecrease():
    x = 4
    y = 15

    listOfXY = [[x],[y]]
    for i in range(0,40):
        x = listOfXY[0][-1]
        y = listOfXY[1][-1]
        if((x+y)<50): #additive increase
            x = x + 30
            y = y + 30
        else: #additive decrease
            x = x - 7
            y = y - 7
        if((x>0)and(y>0)):
            listOfXY[0].append(x)
            listOfXY[1].append(y)
    
    return listOfXY


def makeGraph(listOfXY, graphTitle):
    plt.plot([0,100],[0,100], color="black")
    plt.plot([0,100],[100,0], color="black")
    plt.plot(listOfXY[0],listOfXY[1], color="blue", marker = "o", alpha=.5)
    if(graphTitle=="MIAD"):
        plt.title("Multiplicative Increase, Additive Decrease")
    elif(graphTitle=="MIMD"):
        plt.title("Multiplicative Increase, Multiplicative Decrease")
    else:
        plt.title("Additive Increase, Additive Decrease")
    plt.xlabel("Connection 1 Throughput")
    plt.ylabel("Connection 2 Throughput")
    plt.show()


truth = 0
while(truth==0):
    print("\nWhat graph would you like? [1/2/3/4]")
    print("\t1) Multiplicative Increase Additive Decrease")
    print("\t2) Multiplicative Increase Multiplicative Decrease")
    print("\t3) Additive Increase, Additive Decrease")
    print("\t4) Exit")

    answer = input("").replace(" ", "")

    if(answer =="1"):
        listOfXY = multiplicativeIncreaseAdditiveDecrease()
        makeGraph(listOfXY, "MIAD")
    elif(answer =="2"):
        listOfXY = multiplicativeIncreaseMultiplicativeDecrease()
        makeGraph(listOfXY, "MIMD")
    elif(answer == "3"):
        listOfXY = additiveIncreaseAdditiveDecrease()
        makeGraph(listOfXY, "AIAD")
    elif(answer == "4"):
        truth = 1
    else:
        print("Wrong input, please try again.")

    if(answer!="4"):
        answer2 = input("\nContinue? [Y/N]\t").replace(" ", "")
        if((answer2!="Y") and (answer2!="y") and (answer2!="YES")):
            truth =1
