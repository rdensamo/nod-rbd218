import whois
from csv import reader

path_phish = '../mal_domains/phishdomainsonly.txt'
path_maldoms = '../mal_domains/justdomains.txt'
path_zone = '../datasets/zonefile_domains_full.txt'

path_alexa2k = '../datasets/alexa_top_2k.csv'
path_alexa1m = '../datasets/alexa_top_1m.csv'


def getPhishRegs():
    with open(path_phish, "r", encoding='utf-8') as f:
        for domain_name in f:
            file = open('who_is_bulk_results_phish.txt', 'a')
            # print(domain_name.strip('\n'))
            try:
                res = whois.whois(domain_name.strip('\n'))
                reg = res.registrar
                file.write(reg + "," + domain_name)
                print(reg)
                # TODO: get creation_date and figure out how to parse it
            except:
                file.write("False" + "," + domain_name)
                pass
                print("couldn't get registrar for " + domain_name)
    file.close()


def getMalRegs():
    with open(path_maldoms, "r", encoding='utf-8') as f:
        for domain_name in f:
            file = open('who_is_bulk_results_mal.txt', 'a')
            # print(domain_name.strip('\n'))
            try:
                res = whois.whois(domain_name.strip('\n'))
                reg = res.registrar
                file.write(reg + "," + domain_name)
                print(reg)
                # TODO: get creation_date and figure out how to parse it
            except:
                file.write("False" + "," + domain_name)
                pass
                print("couldn't get registrar for " + domain_name)
    file.close()


def getZoneRegs():
    with open(path_zone, "r", encoding='utf-8') as f:
        for domain_name in f:
            file = open('who_is_bulk_results_zone.txt', 'a')
            # print(domain_name.strip('\n'))
            try:
                res = whois.whois(domain_name.strip('\n'))
                reg = res.registrar
                file.write(reg + "," + domain_name)
                print(reg)
                # TODO: get creation_date and figure out how to parse it
            except:
                file.write("False" + "," + domain_name)
                pass
                print("couldn't get registrar for " + domain_name)
    file.close()


def getAlexaRegs():
    with open(path_alexa2k, "r", encoding='utf-8') as f:
        r = reader(f)

        for domain_name in r:
            file = open('who_is_bulk_results_alexa.txt', 'a')
            # print(domain_name[1])
            try:
                res = whois.whois(domain_name[1])
                reg = res.registrar
                file.write(reg + "," + domain_name[1] + '\n')
                print(reg)
                # TODO: get creation_date and figure out how to parse it
            except:
                file.write("False" + "," + domain_name[1] + '\n')
                pass
                print("couldn't get registrar for " + domain_name[1])
    file.close()


getPhishRegs()
getMalRegs()
getZoneRegs()
getAlexaRegs()
