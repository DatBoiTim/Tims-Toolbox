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

ldapbaseformat="DC={0}"
base=""

ldapserverobject=""
searchbase=""

def checkregex(regex, string):
    m=regex.search(str(string))
    return m

def servervarset(server,username,pw):
    serv=server
    user=username
    pswd=pw

def serverconfig(serv,user,pswd,verbose,socket,addr):
    ldapserver=Server(serv, use_ssl=True, get_info=all)
    try:
        con=Connection(ldapserver, user, pswd, authentication=NTLM, auto_bind=True) # Accesses Server as a known Active Directory User, In case that's a requirement to view UAC Flags in Your environment
        con.open()
        con.bind()
    except:
        socket.sendto("Invalid Credentials",addr)
    else:
        global ldapserverobject
        ldapserverobject=con
    if verbose:
        socket.sendto(con,addr)
        socket.sendto(con.extend.standard.who_am_i(), addr)

    global base
    base=""
    while '.' in serv:
        dotindex=serv.find('.')
        servportion=serv[0:dotindex]
        serv=serv[dotindex+1:len(serv)]
        base=base+ldapbaseformat.format(servportion)+','
    base=base+ldapbaseformat.format(serv)
    socket.sendto("Process Completed", addr)

def processcheck(file,breachregexstring,outputname,verbose,socket,addr):
    try:
        test=open(file)
    except:
        socket.sendto("Cannot find "+file, addr)
    else:
        test.close()
    try:
        breachregex=re.compile(breachregexstring)
    except:
        socket.sendto("Invalid Regular Expression", addr)
    if not outputname:
            socket.sendto("Error, no output", addr)
    #Opens a CSV to read from, and creates/wipes the contents of an output file
    with open(file, newline='') as inputfile, open(outputname+"EnabledADAccounts.csv", "w", newline='')as outputfile:
        pwnreader=csv.reader(inputfile, delimiter=',', dialect='excel', quotechar='"')
        pwnwriter=csv.writer(outputfile, delimiter=',', quotechar='|', quoting=csv.QUOTE_MINIMAL)
        for row in pwnreader:
            username=row[0]
            usernameend=username.find('@')
            username=username[0:usernameend]
            if verbose:
                socket.sendto(username,addr)
            breach=row[1]
            if checkregex(breachregex, str(breach)):
                accountsearchfilter='(&(objectclass=person)(sAMAccountName={}))'
                ldapserverobject.search(base, accountsearchfilter.format(username), attributes=['userAccountControl', 'mail'])
                try:
                    entry=ldapserverobject.entries[0]
                    uac=entry["userAccountControl"]
                    email=entry["mail"]
                    if verbose:
                        socket.sendto(uac,addr)
                    if uac != "514": #Flags to Check Against are typed as a string because entry["userAccountControl"] returns a string.
                        pwnwriter.writerow([username, email, outputname]) 
                except:
                    if verbose:
                        socket.sendto("Negaitve Info for "+username, addr)
                    continue
    inputfile.close()
    outputfile.close()
    socket.sendto("Process Completed")


#Parses a Message from the Socket, as a String Delineated by
#Message = {Code,Args}
#Code determines action to take:
# -101 Reauth | Takes Args: Server,Username,Password,Verbose
# -102 RequestCheck | Takes Args: File,BreachRegexString,OutputName,Verbose
# -103 Shutdown | Takes Args: NaN
def parsemessage(message, socket, addr, server):
    i=0
    message=message[2:len(message)-1]
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
            serverconfig(serv,user,pswd,verbose,socket,addr)
        case "102":
            file=arg0
            breachregexstring=arg1
            outputname=arg2
            try:
                if arg3:
                    verbose=True
            except:
                verbose=False
            processcheck(file,breachregexstring,outputname,verbose,socket,addr)
        case "103":
            shutdown=True
            try:
                server.unbind()
            except:
                print("No LDAP Server was configured")
            socket.sendto("Shutting Down...", addr)
            socket.close()
            exit()
        case _:
            print("Error Parsing Message")

#Server Setup
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as ssock:
    ssock.bind(('127.0.0.1', 6450))
    while True:
        sockmessage, addr = ssock.recvfrom(1024)
        parsemessage(str(sockmessage), ssock, addr, ldapserverobject)