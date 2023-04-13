# Use LDAP to Query Active Directory for UAC Flag of any emails found in a CSV of accounts affected by a breach
# Enabled accounts are exported to a CSV
# Containerized
# Requires LDAP3, PyASN
# Written By Austin J. aka DatBoiTim
# 2/16/2023 Python 3.11

import csv # I/O Library for .csv files
import re # Regex Library to process .csv data
import ssl # Secure Connection
from ldap3 import Server, Connection, ALL, NTLM, ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES # LDAP Connection Stuff
from ldap3 import Tls # LDAP Secure Connection
import socket # Communicate Over UDP

reauth=False
changebase=False
requestcheck=False
shutdown=False

code = ""
file=""
breachregexstring=""
outputname=""
serv=""
user=""
pswd=""
ldapbaseformat="DC={0}"
base=""
verbose=False

ldapserverobject=""
searchbase=""

def checkregex(regex, string):
    m=regex.search(str(string))
    return m

def servervarset(server,username,pw):
    serv=server
    user=username
    pswd=pw

def serverconfig(verbose):
    ldapserver=Server(serv, use_ssl=True, get_info=all)
    try:
        con=Connection(ldapserver, user, pswd, authentication=NTLM, auto_bind=True) # Accesses Server as a known Active Directory User, In case that's a requirement to view UAC Flags in Your environment
        con.open()
        con.bind()
    except:
        print("Invalid Credentials")
    else:
        return con
    if verbose:
        print(con)
        print(con.extend.standard.who_am_i())

    while '.' in serv:
        dotindex=serv.find('.')
        servportion=serv[0:dotindex]
        serv=serv[dotindex+1:len(serv)]
        searchbase=base+ldapbaseformat.format(servportion)+','
    searchbase=base+ldapbaseformat.format(serv)
    return searchbase

def processcheck(verbose):
    try:
        test=open(file)
    except:
        print("Cannot find",file)
    else:
        test.close()
    try:
        breachregex=re.compile(breachregexstring)
    except:
        print("Invalid Regular Expression")
    if not outputname:
            print("Error, no output")
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
                ldapserverobject.search(base, accountsearchfilter.format(username), attributes=['userAccountControl', 'mail'])
                try:
                    entry=ldapserverobject.entries[0]
                    uac=entry["userAccountControl"]
                    email=entry["mail"]
                    if verbose:
                        print(uac)
                    if uac != "514": #Flags to Check Against are typed as a string because entry["userAccountControl"] returns a string.
                        pwnwriter.writerow([username, email, outputname])
                        if verbose:
                            print("hit; username:", username, "was a victim of the", outputname, "breach")       
                except:
                    if verbose:
                        print("Negaitve Info for", username)
                    continue
    inputfile.close()
    outputfile.close()


#Parses a Message from the Socket, as a String Delineated by
#Message = {Code,Args}
#Code determines action to take:
# -101 Reauth | Takes Args: Server,Username,Password,Verbose
# -102 RequestCheck | Takes Args: File,BreachRegexString,OutputName,Verbose
# -103 Shutdown | Takes Args: NaN
def parsemessage(message):
    i=0
    message=message[2:len(message)-1]
    print(message)
    while " " in message:
        sep=message.find(" ")
        data=message[0:sep]
        match i:
            case 0:
                code=data
            case 1:
                arg0=data
            case 2:
                arg1=data
            case 3:
                arg2=data
            case 4:
                arg3=data
            case _:
                return False
        message=message[sep+1:len(message)]
        i+=1
    match code:
        case "101":
            serv=arg0
            user=arg1
            pswd=arg2
            try:
                if arg3:
                    verbose=True
            except:
                verbose=False
            reauth=True
        case "102":
            file=arg0
            breachregexstring=arg1
            outputname=arg2
            try:
                if arg3:
                    verbose=True
            except:
                verbose=False
            requestcheck=True
        case "103":
            shutdown=True
            print("Shutting Down...")
            return code
        case _:
            print("Error Parsing Message")

#Server Setup
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as ssock:
    ssock.bind(('127.0.0.1', 6450))
    while not code == "103":
        sockmessage, addr = ssock.recvfrom(1024)
        code=parsemessage(str(sockmessage))
        if reauth:
            ldapserverobject=serverconfig(verbose)
            reauth=False
            continue
        elif requestcheck:
            processcheck(verbose)
            requestcheck=False
            continue
        else:
            continue
try:
    ldapserverobject.unbind()
except:
    print("No LDAP Server was configured")
ssock.close()