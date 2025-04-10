
def readFile():
    file = open("lab8.txt", "r")     
    print("the values in the file are")
    print(file.read())
    file.close()

#readFile()
def returnList():
    file = open("lab8.txt", "r")
    ourList = []
    for line in file:
        #print line
        line = line.replace("\n","")
        ourList.append(line.split(","))
    return ourList
#print(returnList())

def sumList():
      listOfNum=returnList()
    #print(listOfNum)
      total = 0   
      for i in range(len(listOfNum)):
            for j in range(len(listOfNum)):        
               #print(listOfNum[i][j])
                total = total + int(listOfNum[i][j])
      print("total sum",total)
      return total

file = open("sumresult.txt","w")
file.write("Sum of all number of text is:" +str(sumList()))
file.close()
                       
