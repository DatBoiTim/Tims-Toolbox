# Use LDAP to Query Active Directory for UAC Flag of any emails found in a CSV of accounts affected by a breach
# Enabled accounts are exported to a CSV
# CLI Friendly
# Requires LDAP3, PyASN
# Written By Austin J. aka DatBoiTim
# 2/16/2023 Python 3.11

import csv #I/O Library for .csv files
import re #Regex Library to process .csv data
import argparse #Allows for cmd execution
import ssl # Secure Connection
from getpass import getpass # Obscures Password input
from ldap3 import Server, Connection, ALL, NTLM, ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES # LDAP Connection Stuff
from ldap3 import Tls # LDAP Secure Connection

loop='y'
secondrun=False
file=""
breachregexstring=""
outputname=""
verbose=False
serv=""
base=""

def checkregex(regex, string):
    m=regex.search(str(string))
    return m

#CLI Args
parser=argparse.ArgumentParser(description="""Checks CSV files from HaveIBeenPwned for enabled ActiveDirectory Accounts and outputs enabled account names to a separate CSV
\n syntax should be: PwnedCheck "serv" "filename.extension" "regexexpression" "outputname" -v=True """)
parser.add_argument("serv", type=str, help="Enter the Directory Server ex: test.sample.org")
parser.add_argument("file", type=str, help="Enter the name of a file in this directory, must be a .csv file. Argument must include the file extension")
parser.add_argument("breachregexstring", type=str, help="Enter a regex expression to find the breach in the CSV file")
parser.add_argument("output", type=str, help="A string to help distinguish what file to output to")
parser.add_argument("-v", "--verbose", type=bool, help="Prints Debug Information")

#Parse Arguments
try:
    args=parser.parse_args()
    serv=args.serv
    file=args.file
    breachregexstring=args.breachregexstring
    breachregex=re.compile(str(breachregexstring))
    outputname=args.outputname
    verbose=args.verbose
except:
    print("Some args were not provided, please provide information when asked")

#Pre-File Setup
authed = False
while not authed:
    if not serv:
        serv=input("Enter Directory Server: ")
    serv=Server(serv, use_ssl=True, get_info=all)
    user=input("Enter AD Username: ")
    pswd=""
    pswd=getpass()
    try:
        con=Connection(serv, user, pswd, authentication=NTLM, auto_bind=True) # Accesses Server as a known Active Directory User, In case that's a requirement to view UAC Flags in Your environment
        con.open()
        con.bind()
    except:
        print("Invalid Credentials")
        redoserv = input("Redo Server(Y/n)? ")
        if redoserv == 'y' or redoserv == 'Y':
            serv=input("Enter Directory Server: ")
        continue # Re-Auth
    authed=True
if verbose:
    print(con)
    print(con.extend.standard.who_am_i())

#Automate Creating Query Base
ldapbaseformat="DC={0}"
while '.' in serv:
    dotindex=serv.find('.')
    servportion=serv[0:dotindex]
    serv=serv[dotindex+1:len(serv)]
    base=base+ldapbaseformat.format(servportion)+','
base=base+ldapbaseformat.format(serv)

while (loop=='y') or (loop=='Y'):
    if not file or secondrun==True:
        while True:
            file=input("Enter Name of CSV: ")
            test
            try:
                test = open(file)
            except:
                print("Cannot find",file)
                continue
            else:
                test.close()
                break
    if not breachregexstring or secondrun==True:
        while True:
            breachregexstring=str(input("Enter Breach Regex Expression: "))
            try:
                breachregex=re.compile(breachregexstring)
            except:
                print("Invalid Regular Expression")
                continue
            break
    if not outputname or secondrun==True:
        outputname=input("Enter the Name of the Breach being checked: ")
    #Opens a CSV to read from, and creates/wipes the contents of an output file
    with open(file, newline='') as inputfile, open(outputname+"EnabledADAccounts.csv", "w", newline='')as outputfile:
        pwnreader=csv.reader(inputfile, delimiter=',', dialect='excel', quotechar='"')
        pwnwriter=csv.writer(outputfile, delimiter=',', quotechar='|', quoting=csv.QUOTE_MINIMAL)
        for row in pwnreader:
            username=row[0]
            usernameend=username.find('@')
            username=username[0:usernameend]
            if verbose:
                print(username)
            breach=row[1]
            if checkregex(breachregex, str(breach)):
                accountsearchfilter='(&(objectclass=person)(sAMAccountName={}))'
                con.search(base, accountsearchfilter.format(username), attributes=['userAccountControl', 'mail'])
                try:
                    entry = con.entries[0]
                    uac = entry["userAccountControl"]
                    email = entry["mail"]
                    if verbose:
                        print(uac)
                    if uac != "514":
                        pwnwriter.writerow([username, email, outputname])
                        if verbose:
                            print("hit; username:", username, "was a victim of the", outputname, "breach")       
                except:
                    if verbose:
                        print("Negaitve Info for", username)
                    continue
    while (loop!='y') or (loop!='Y') or (loop!='n') or (loop!='N'):
        loop=input("Run Script Again? (y/n) ")
        if loop=='y' or loop=='Y':
            secondrun=True
            inputfile.close()
            outputfile.close()
            break
        elif loop=='n' or loop=='N':
            print("Quitting...")
            break
        else:
            print("Invalid Input")

con.unbind()
inputfile.close()
outputfile.close()
