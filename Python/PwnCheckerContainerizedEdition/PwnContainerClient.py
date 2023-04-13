import socket
from getpass import getpass

csock=socket(socket.AF_INET, socket.SOCK_DGRAM)
csock.timeout(1)
hostname=socket.gethostname()

print("Documentation is as follows:")
print("Code 101 Reconfigures What Directory Server to Authenticate and Query.")
print("Code 102 Submits Information To Check")
print("Code 103 Shutdown the Script")
code=input("Enter Code to Send to Container: ")
in0,in1,in2,in3=""
match code:
    case 101:
        in0=input("Enter the Server(Ex: spam.eggs.com): ")
        in1=input("Enter the Username to Auth with(Ex:Python/username): ")
        in2=getpass()
        while True:
            verbosein=input("Should check be verbose?(y/N) ")
            if not verbosein.lower() == 'y' or not verbosein.lower() == 'n':
                continue
            else:
                if verbosein.lower() == 'y':
                    in3=True
                else:
                    in3=False
    case 102:
        in0=input("Enter the name of a CSV file the container can access: ")
        in1=input("Enter regex to check for: ")
        in2=input("Enter breach name: ")
        while True:
            verbosein=input("Should check be verbose?(y/N) ")
            if not verbosein.lower() == 'y' or not verbosein.lower() == 'n':
                continue
            else:
                if verbosein.lower() == 'y':
                    in3=True
                else:
                    in3=False
    case 103:
        print("Shutdown Initiated...")
    case _:
        print("Invalid Code")

message = (code,in0,in1,in2,in3)

addr=input("Enter IP Address of Container: ")
addr=(addr, 12000)

while True:
    try:
        data, server = csock.recvfrom(1024)
        print(data,server)
    except TimeoutError:
        print("Request Timed Out")
    if data == "Process Completed":
        break
