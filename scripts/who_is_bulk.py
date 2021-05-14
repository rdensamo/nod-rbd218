import whois
from csv import reader

path_phish = '../mal_domains/phishdomainsonly.txt'
path_maldoms = '../mal_domains/justdomains.txt'
path_zone = '../datasets/zonefile_domains_full.txt'

path_alexa2k = '../datasets/alexa_top_2k.csv'
path_alexa1m = '../datasets/alexa_top_1m.csv'

path_dnsbl = '../datasets/dnsbl.csv'


def getPhishRegs():
    print("\nwho is for phish domain registrars\n")
    with open(path_phish, "r", encoding='utf-8') as f:
        for domain_name in f:
            file = open('who_is_bulk_results_phish_all.txt', 'a')
            # print(domain_name.strip('\n'))
            try:
                res = whois.whois(domain_name.strip('\n'))
                reg = res.registrar.split(',')[0]
                file.write(reg + "," + domain_name)
                print(reg)
                # TODO: get creation_date and figure out how to parse it
            except:
                file.write("False" + "," + domain_name)
                pass
                print("couldn't get registrar for " + domain_name)
    file.close()


def getMalRegs():
    print("\nwho is for mal domain registrars\n")
    with open(path_maldoms, "r", encoding='utf-8') as f:
        for domain_name in f:
            file = open('who_is_bulk_results_mal_all.txt', 'a')
            # print(domain_name.strip('\n'))
            try:
                res = whois.whois(domain_name.strip('\n'))
                reg = res.registrar.split(',')[0]
                file.write(reg + "," + domain_name)
                print(reg)
                # TODO: get creation_date and figure out how to parse it
            except:
                file.write("False" + "," + domain_name)
                pass
                print("couldn't get registrar for " + domain_name)
    file.close()


def getZoneRegs():
    print("\nwho is for zone domain registrars\n")
    with open(path_zone, "r", encoding='utf-8') as f:
        for domain_name in f:
            file = open('who_is_bulk_results_zone.txt', 'a')
            # print(domain_name.strip('\n'))
            try:
                res = whois.whois(domain_name.strip('\n'))
                reg = res.registrar.split(',')[0]
                file.write(reg + "," + domain_name)
                print(reg)
                # TODO: get creation_date and figure out how to parse it
            except:
                file.write("False" + "," + domain_name)
                pass
                print("couldn't get registrar for " + domain_name)
    file.close()


def getAlexaRegs():
    count = 0
    print("\nwho is for alexa domain registrars\n")
    with open(path_alexa1m, "r", encoding='utf-8') as f:
        r = reader(f)

        for domain_name in r:
            file = open('who_is_bulk_results_alexa_100k.txt', 'a')
            # print(domain_name[1])
            try:
                count = count + 1
                res = whois.whois(domain_name[1])
                reg = res.registrar.split(',')[0]
                file.write(reg + "," + domain_name[1] + '\n')
                print(reg)
                # TODO: get creation_date and figure out howmo to parse it
            except:
                file.write("False" + "," + domain_name[1] + '\n')
                pass
                print("couldn't get registrar for " + domain_name[1])
            if count == 100000:
                break
    file.close()


def getDNSBL():
    print("\nwho is for DNSBL\n")
    with open(path_dnsbl, "r", encoding='utf-8') as f:
        for domain_name in f:
            file = open('who_is_bulk_results_dnsbl.txt', 'a')
            try:
                res = whois.whois(domain_name.strip('\n'))
                reg = res.registrar.split(',')[0]
                file.write(reg + "," + domain_name)
                print(reg)
            except:
                file.write("False" + "," + domain_name)
                print("couldn't get registrar for " + domain_name)
    file.close()


# getDNSBL()
# getPhishRegs()
getMalRegs()
# getZoneRegs()
# getAlexaRegs()
# path_dnsbl
