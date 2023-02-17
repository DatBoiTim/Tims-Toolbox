# Requires win32com python library
# Take CSVs and automates sending breach notifications, best used in conjunction with HIBP
# CSV formatting should be: ..., given name, email, breach name, ...\n
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

mailsubject = ""
mailbody = ""

def modifymail(mailobj, subject, emailaddr, name, body):
    print("""What do you want to fix?\n
    1. Email Address
    2. Subject
    3. Body
    (Type quit to Return to Display)
    """)
    emailmodin = input("Option: ")
    if emailmodin.lower() == "email address"| 1:
        mailobj.To=input("Enter email address: ")
    elif emailmodin.lower() == "subject" | 2:
        mailsubject=input("Manually Enter the Email Subject Line:\n")
    elif emailmodin.lower == "body" | 3:
        mailbody=input("Manually Enter the Email Body:\n")

    elif emailmodin.lower() == 'quit':
        return

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

company=input("Enter Company Name for Email Sign Off: ")

mailsubject="IT Alert: Your Company Email Address was involved in {0}'s databreach"
mailbody="""Hello {0},\n\n
As a courtesy, we are alerting you that an account associated with your company email has been found in {1}'s databreach. To ensure you\
maintain control of your {1} account, please reset the password immediately using {1}'s password reset tool.\n\n
If you had used the password for your {1} account for any of your company accounts, please change your password immediately.\
 For assistance with resetting your password please contact the helpdesk.

Regards,
The {2} Information Security Team
"""

with open(file) as inputfile:
    initialpreview=True
    manset=False
    reader=csv.reader(inputfile, delimiter=',', dialect='excel', quotechar='"')
    for row in reader:
        #Vars
        relevantinfoindex=findemailinrow(row) #Tuple (rowEmailIndex, email)
        email=relevantinfoindex[1]
        givenname=row[relevantinfoindex[0]-1]
        breach=row[relevantinfoindex[0]+1]
        #Email Construction
        breachnotif=outlook.CreateItem(mailitem)
        breachnotif.To=email
        if not manset:
            breachnotif.Subject=mailsubject.format(breach)
            breachnotif.Body=mailbody.format(givenname, breach, company)
        else:
            breachnotif.Subject=mailsubject
            breachnotif.Body=mailbody
        if initialpreview:
            while True:
                breachnotif.Display()
                sendcheck=input("Send Emails?(Y/n) ")
                if sendcheck.lower() == 'y':
                    initialpreview=False
                    break
                elif sendcheck.lower() == 'n':
                    modifymail(breachnotif, breachnotif.Subject, breachnotif.To, givenname, breachnotif.Body)
                    manset=True
                else:
                    print("Invalid input")
        breachnotif.Send()

inputfile.close()