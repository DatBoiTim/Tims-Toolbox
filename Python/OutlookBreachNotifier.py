# Requires win32com python library
# Take CSVs and automates sending breach notifications, best used in conjunction with HIBP
# CSV formatting should be: ..., given name, email, breach name, breach time\n
# I personally use this in conjunction with PwnedCheck to process notifications of emails on my orgs domain being involved in a breach via HIBP
# This is not personally required, but yields decent results
import re # Regular Expression for Email Address Finding
import csv # CSV Handling
import win32com.client # Needed for Outlook Email

emailregex="^[\w.-]+@[\w.-]+\.\w+$"
emailregex=re.compile(emailregex)

def checkregex(regex, string):
    m=regex.search(str(string))
    return m

def findemailinrow(iterant):
    i=0
    while i < len(iterant):
        m=checkregex(emailregex, iterant[i])
        if m:
            returntuple=(i, iterant[i])
            return returntuple

try:
    outlook=win32com.client.Dispatch('Outlook.Application')
    mailitem=0x0
except:
    print("Cannot link to outlook")

file=""
while True:
    file=input("Input CSV: ")
    try:
        test=open(file)
    except:
        print("Cannot find csv")
        continue
    break

emailSubject="IT Alert: Your Company Email Address was involved in {0}'s databreach"

with open(file) as inputfile:
    reader=csv.reader(inputfile, delimiter=',', dialect='excel', quotechar='"')
    for row in reader:
        #Vars
        relevantinfoindex=findemailinrow(row) #Tuple (rowEmailIndex, email)
        email=relevantinfoindex[1]
        givenname=row[relevantinfoindex[0]-1]
        breach=row[relevantinfoindex[0]+1]
        breachwhen=row[relevantinfoindex[0]+2]
        #Email Construction
        breachnotif=outlook.CreateItem(mailitem)
        breachnotif.Subject=emailSubject.format(breach)