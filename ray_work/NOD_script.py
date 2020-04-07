import json
import socket
import whois

import paramiko
import sys

nbytes = 4096
hostname = 'w'
port = 22
username = sys.argv[1] 
password = sys.argv[2]
command = 'python elastic.py' +" " +  username + " " + password
client = paramiko.Transport((hostname, port))
client.connect(username=username, password=password)
data = []

def connect_to_database():
    stdout_data = []
    stderr_data = []
    session = client.open_channel(kind='session')
    session.exec_command(command)
    while True:
        if session.recv_ready():
            stdout_data.append(session.recv(nbytes))
        if session.recv_stderr_ready():
            stderr_data.append(session.recv_stderr(nbytes))
        if session.exit_status_ready():
            break
    #print(stdout_data)
    session.close()
    client.close()
    
    
    #do stuff with stdout_data
    str_data = ""
    for ele in stdout_data:
        str_data += ele.decode('ascii')
    
    str_data = str_data.split("\n", 1)[1]
    str_data = str_data.replace("\'", "\"")
    data = json.loads(str_data)

def parse_query():
    Nod = [];
    for d in data['hits']['hits']:
        try:
            to_append = [d['_source']['query'], d['_source']['id.resp_h'], d['_source']['id.orig_h'], d['_source']['domain'], d['_source']['age'], 0]
        except:
            try:
                to_append = [d['_source']['query'], d['_source']['id.resp_h'], d['_source']['id.orig_h'], d['_source']['domain'], 0, 0]
            except:
                to_append = [d['_source']['query'], d['_source']['id.resp_h'], d['_source']['id.orig_h'], "domain error", 0, 0]
        Nod.append(to_append)
    return Nod

def check_mult_domains(domain):
    #print(domain[3] + ": multiple domains.")
    mult_domains = domain[3].split(',')
    #resolve multiple domains
    for md in mult_domains:
        try:
            socket.gethostbyname(md)
            #print(md + ": resolves.")
        except:
            #print(md + ": does not resolves.")
            domain[5] += 20

def resolve_single_domains(domain):
    resolves = True;
    try:
        socket.gethostbyname(domain[3])
        #print(domain[0] + ": resolves.")
    except:
        #print(domain[0] + ": does not resolves.")
        resolves = False;
        domain[5] += 20
    return resolves

def get_age(domain):
    #age of domain
    age = domain[4]/3.154e+7  # number of seconds in a year
    #print(domain[0] + ": is " + str(age) + " years old.")

    #NOTE: this will double hit an unresolved domain
    # Evil magic number division, if the age / mn <.5
    # If age < half a year, add one
    if age < .5:
        domain[5] += 1

def get_subdomain(domain):
    prefix = domain[0].split('.', 1)[0] 
    if prefix != "www":
        #print(domain[0] + ": has subdomain of " + prefix)
        domain[5] += 1
        
def check_for_bad_registrar(domain):
    #check for bad registrar
    with open('registrar_list.txt') as f:
        found = False;
        datafile = f.readlines()
    for line in datafile:
        if whois_info.registrar in line:
            #print(domain[0] + ": has a valid registrar.")
            found = True
            break;
    if found is False:
        #print(domain[0] + ": does not seem to have a valid registrar.")
        domain[5] += 1
        
def length_check(domain):
    #check length of domain
    prefix = domain[0].split('.', 1)[0]
    postfix = domain[0].split('.', 1)[1]
    # [www. lehigh, edu]
    if len(prefix) > 10:
        #print(domain[0] + ": has a prefix, " + prefix +  ", greater than 10.")
        domain[5] += 1
    if len(postfix) > 15:
        #print(domain[0] + ": has a domain, " + postfix +  ", greater than 10.")
        domain[5] += 1
    

###############################################################################

print("Please log into your lehigh w account via: python NOD_script username password.")
print()
print("You must have elastic.py in your home directory to retrieve query data.")
print()

connect_to_database()
Nod = parse_query()
score_list =[];

for domain in Nod:

    #check multiple domains


    # If the domains resolve they are scored lower than non-resolving domains -fbc
    if ',' in domain[3]:
        check_mult_domains(domain)
    
    #resolve single domains
    else:
         resolves = resolve_single_domains(domain)
        
    if resolves is True:
        #age
        # If the age is < half a year, add 1
        get_age(domain)
        #subdomain
        # if the subdomain exists is not www, add 1
        get_subdomain(domain)
        

        try:
            whois_info = whois.query(domain[0])
        except:
            whois_info = None

        # If there is whois info, check the registrar against a list
        # if they're not in the list, add 1

        # If the length of the subdomain is > 10, add 1
        # If the length of the domain is > 15, add 1
        if whois_info != None:
            check_for_bad_registrar(domain)
            length_check(domain)

        # If there is no whois info, add 1
        else:
            #print(domain[0] + ": has no registrar.")
            domain[5] += 1

    #score
    print(domain[0] + ": has a score of " + str(domain[5]))
    score_list.append(domain[0] + ": has a score of " + str(domain[5]))
    
ff = open('NOD_final_data.txt', 'w')
ff.write(score_list)
ff.close()






    

    
    



        
    
   

