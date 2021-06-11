#Setup
1. Clone this repo and cd into it. 
2. Create a virtualenv with `virtualenv -p python3 venv`
3. Source the virtualenv `source venv/bin/activate`
4. Install the requirements via pip `pip3 install -r requirements.txt`
5. Run with python3 main.py


# Requirements for Python Weka Wrapper for Windows 
(1) Download javabridge from : https://www.lfd.uci.edu/~gohlke/pythonlibs/#javabridge (Windows Only)
(2) pip install C:\javabridge-1.0.19-cp38-cp38-win_amd64.whl (Windows Only)
(3) pip install python-weka-wrapper3==0.2.0 
![alt text](https://gogs.cc.lehigh.edu/infosec/nod/src/working/Images/Windows-Python-Weka.png?raw=true)

Note : have to pip to download and pip install this separately, 
will not work to do this from the requirements.txt file (so removed it)
Please do this portion - necessary to get wekaDecisionTree.py to work


The general direction for different systems can be found here: 
http://fracpete.github.io/python-weka-wrapper3/install.html

# Requirements for python Weka Wrapper for Linux : (Should this be direction?)
(1)

# How to run the code:
# (a) Before generating attribute sub-scores for malware, phishtank, alexatop domains
# TODO: make it so you can run score_datasets.py with argument phish, alexa, or mal

# (b) Generating attribute sub-scores malware, phishtank and alexatop domains 

# (c) Scoring Elk Domains  
Run the NOD scoring on Elk data with FinalScore.py
Multiple ways to run FinalScore.py to test with elk, phish, single domains etc.


To generate the training and testing labeled data run 
score_datasets_alexa.py for scored alexa top domains
score_datasets_mal.py for scored malware domains 
score_datasets_phish.py for scored phishtank domains 
then will need to combine and shuffle these scores to generate 

To run the code for weka decision tree : python wekaDecisionTree.py 
#About the Code: 

#About the Data : 
The data is stored under classes/data in this repository 
(1) The CSV file: 
(2) The ARFF file: (explain the arff file and the creation process )
@ATTRIBUTE attribute_0 REAL
@ATTRIBUTE attribute_1 REAL
@ATTRIBUTE attribute_2 REAL
@ATTRIBUTE attribute_3 REAL
@ATTRIBUTE attribute_4 REAL
@ATTRIBUTE attribute_5 REAL
@ATTRIBUTE attribute_6 REAL
@ATTRIBUTE attribute_7 {alexatop,malware,phishtank}


#Attributes
Class Name            Subscore Name         Subscore Type Subscore Description                                                                                                                                     Notes                                                                                                                               Flag?
AlexaTop              alexatop              bool          True if the domain appears in the Alexa top 1m list.                                                                                                                                                                                                                                         yes
DomainAge             age                   float         A value based on domaintools.com research that indicates how suspicius a domain's age is in 3 month increments.                                          Max is 3.85  the score method returns a normalized value but it uses te literal score when sent to a domain object  higher is worse
DomainToolsRegistrars domaintoolsregistrars float         Small set of scores for 20 worst-offender registrars provided by domaintools.com                                                                         Range is 6.01-11.86, registrars that are not in this list are assigned 0.6.  higher is worse
KnujOn                knujon                int           Integer value representing general registrar badness provided by knujon project.                                                                         lower is worse  default value is 0.6 but should be a larger int
LehighTypoSquat       lehigh-typosquat      bool          True if the domain contains the word "lehigh"                                                                                                                                                                                                                                                yes
MalwareDomains        malware_domain        bool          True if domain appears in malwaredomains list                                                                                                                                                                                                                                                yes
Phishtank             phishtank             bool          True if domain appears in phishtank list                                                                                                                                                                                                                                                     yes
RedCanaryEntropy      DomainNameEntropy     float         Computed entropy score for domain names                                                                                                                  Score method return value is different from what is added to domain objects.   lower is worse
Registrarprices       registrar_prices      float         Pulled from lookup table of popular registrar price information.                                                                                         registrars that are not in this list are assigned 0.6 lower is worse?
Resolver              resolves              bool          True if the domain resolves                                                                                                                              Score not set if domain doesn't resolve.  0-6  higher is worse                                                                      yes
Resolver              ttl                   int           Determines riskiness of TTL based on lookup
Resolver              bogon                 bool          True if the domain is assigned a record which points to a private or unallocated IP address range.                                                       Score not set if domain doesn't resolve.                                                                                            yes
SpamhausReg           spamhausreg           float         Small set of scores for 10 worst-offender registrars provided by spamhaus                                                                                higher is worse
SpamhausTld           SpamhausTld           float         badness score for each top level domain provided by spamhaus                                                                                             higher is worse
TldScoring            ZoneFileBrandTld      bool, float   0-1 if the domain tld is found in zonefiles true if the domain is a brand tld false if neither
ZonefileDomains       zonefile              bool                                                                                                                                                                   Not used?                                                                                                                           yes
                      lehigh-typosquat      bool          Returns true if scored domain contains 'lehigh' or a possible typo
                      AlexaLevSim_score     float         Determines riskiness based on Damerau-Levenshtein edit distance between the domain being scored and the most similar highest scoring AlexaTop 1M domain.
                      AlexaLevSim_domain    string        The most similar AlexaTop 1M domain based of the Damerau-Levenshtein edit distance
****


# Pending Tasks : 
(1) Need to create a template to convert csv to arff file, currently using a csv to arff converter and manually modifying the file to work with weka  
    - Source : https://jinja.palletsprojects.com/en/2.11.x/
(2) Need to correspond with domain name and row in arff file because domain-name and other non numerical attributes were
removed. This needs to be done so we know which domains produced the bad scores 

(3) Need to factor in the categorical and boolean attributes not used in wekaDecisionTree.py prediction result



References / Tools : 
https://www.convertcsv.com/json-to-csv.htm
https://www.convertcsv.com/csv-to-flat-file.htm
https://machinelearningmastery.com/load-csv-machine-learning-data-weka/ 

Until we have the template - this will not work additional
modifications need to be made from this arff conversion to 
work with weka for training / testing 
https://ikuz.eu/csv2arff/

# could generate table with https://www.tablesgenerator.com/text_tables
