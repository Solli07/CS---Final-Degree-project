###################################
# Import modules
#################################
from Python_code.Check_DKIM import check_dkim
from Python_code.Check_SPF_DMARC import get_DMARC_record
from Python_code.Check_SPF_DMARC import get_spf_record
from Python_code.check_syntax import check_syntax_spf
from Python_code.check_syntax import check_syntax_dmarc
import re
import csv

###################################
# Global values and variables
###################################

# CSV file to filter domains from
FILE = "majestic_million.csv"


######################################
# regex
######################################

DMARC_HARDFAIL = "\Wp=reject"
DMARC_SOFTFAIL = "\Wp=quarantine"
DMARC_NOFAIL = "\Wp=none"

SPF_H_FAIL = "\W-all"
SPF_S_FAIL = "\W~all"
SPF_P = "\W\\+all"
SPF_N = "\W\\?all"

#####################################
# Functions
#####################################



def check_domain(domain_list):
    '''
    Query provided domains for SPF records, DKIM information and DMARC records

    :param domain_list: List of domains to query
    :return: responses from the dns servers regarding SPF, DKIM and DMARC
    '''
    dns_records = []

    for domain in domain_list:
        spf = get_spf_record(domain)
        dkim = check_dkim(domain)
        dmarc = get_DMARC_record(domain)
        dns_records.append((domain, spf, dkim, dmarc))
    return dns_records


def populate_domain_list(filename):
    '''
    Filters the provided Majestic.csv file for Norwegian domains and returns a list containing only Norwegian domains
    :param filename: name of the csv file
    :return: list of Norwegian domains
    '''
    domain_list = []
    with open(FILE, 'r', encoding='utf-8') as csv_file:  # open csv file with top million domains
        csv_reader = csv.reader(csv_file, delimiter=',')
        for line in csv_reader:
            try:  # extract and append domain name to list of Norwegian domains
                if line[3] == 'no':
                    domain_list.append(str(line[2]))
            except IndexError:  # ignore malformed entries in csv file
                pass
        return domain_list

def count_spf_dkim_dmarc(dns_replies):
    '''
    This function counts occurances of SPF, DKIM, DMARC, and combinations of these or absence of them
    :param dns_replies: Output from the check_domain() function
    :return:
    '''
    count_spf = 0
    count_dkim = 0
    count_dmarc = 0
    spf_dkim = 0
    no_sec = 0
    dkim_only = 0
    for i in dns_replies:
        try:
            if i[1][0] is True:
                count_spf += 1
        except TypeError:
            pass
        try:
            if i[2][0] is True:
                #print(count_dkim)
                print(i[1]," :::: ",i[2])
                count_dkim += 1
                #print(count_dkim, "\n")
        except TypeError:
            pass
        try:
            if i[3][0] is True:
                count_dmarc += 1
        except TypeError:
            pass
        try:
            if (i[1][0] is True) and (i[2][0] is True):
                spf_dkim += 1
        except TypeError:
            pass
        try:
            #print(i[1][0],":::", i[2][0])
            if ((i[1] is None) and (i[2][0] is True)) or ((i[1][0] is False) and (i[2][0])):
                dkim_only += 1
        except TypeError:
            pass
        if (i[1] == None or i[1][0] == False) and i[2][0] is False:
            no_sec += 1
    return count_spf, count_dkim, count_dmarc, spf_dkim, no_sec, dkim_only


def syntax_stats_spf(records):
    '''
    Count number of Valid SPF records, number of  hardf-fail, soft-fail, Pass and neutral configurations, and use of include and redirect
    :param records: SPF records to analyze
    :return: nomber of observation for each of the above mentioned criteria
    '''

    valid_spf = 0
    hardfail = 0
    softfail = 0
    nofail = 0
    neutral = 0
    implicit_ntrl = 0
    redirect = 0
    include = 0
    for i in records:
        if (i[1] != None) and (i[1][0] != False):  # check if the syntax is valid or not
            #print(i[1][1])
            spfstring = i[1][1].strip('\"')
            spfcheck = check_syntax_spf(spfstring, i[0])
            if spfcheck[0] == True:
                valid_spf += 1
                hfail = re.search(SPF_H_FAIL, i[1][1])
                sfail = re.search(SPF_S_FAIL, str(i[1][1]))
                nfail = re.search(SPF_P, i[1][1])
                ntrl = re.search(SPF_N, i[1][1])
                #test = re.search(SPF_UNDEF, i[1][1])
                if hfail:
                    hardfail += 1
                if sfail:
                    softfail += 1
                if nfail:
                    nofail += 1
                if ntrl:
                    neutral += 1
                if (not hfail) and (not sfail) and (not nfail) and (not ntrl) and (not "rederect" in i[1][1]):
                    implicit_ntrl += 1
                if "redirect" in i[1][1]:
                    redirect += 1
                if "include:" in i[1][1]:
                    include += 1
            #print(i[1][1])
            #print(hardfail, softfail, neutral, nofail)
        #print(redirect)
    return valid_spf, hardfail, softfail, nofail, neutral, implicit_ntrl, redirect, include


def syntax_stats_dmarc(records):
    '''
    check DMARC records for validity and number of "reject", "quarantine" and "none" configurations for strictness
    :param records: DMARC records to analyze
    :return: number of observations for the above mentioned criteria
    '''

    valid_dmarc = 0
    hardfail = 0
    softfail = 0
    nofail = 0
    for i in records:
        if i[3][0] != False: # check if the syntax is valid or not
            dmarcstring = i[3][1].strip('\"')
            dmarccheck = check_syntax_dmarc(dmarcstring)
            if (dmarccheck[0] == True) and ("p=" in i[3][1]) and ("p= " not in i[3][1]):
                valid_dmarc += 1
                reject = re.search(DMARC_HARDFAIL, i[3][1])
                quarantine = re.search(DMARC_SOFTFAIL, i[3][1])
                ignore = re.search(DMARC_NOFAIL, i[3][1])
                if reject:
                    hardfail += 1
                if quarantine:
                    softfail += 1
                if ignore:
                    nofail += 1
    return valid_dmarc, hardfail, softfail, nofail

######################################################
# Program
######################################################


DOMAIN_LIST = populate_domain_list(FILE)  # Obtain domains to check from csv file


CHECKED = check_domain(DOMAIN_LIST[:])  # Obtain DNS records/responses for each domain


SPF_TOTAL, DKIM, DMARC_TOTAL, SPF_DKIM, NO_SECURITY, DKIM_ONLY = count_spf_dkim_dmarc(CHECKED)  # Count occurrences of SPF, DKIM and DMARC

SPF_VALID, SPF_HARDFAIL, SPF_SOFTFAIL, SPF_PASS, SPF_NEUTRAL, SPF_IMPLICIT_NTRL, SPF_REDIRECT, SPF_INCLUDE = syntax_stats_spf(CHECKED)  # Check the syntax in obtained SPF and DMARC records

DMARC_VALID, DMARC_REJECT, DMARC_QUARANTINE, DMARC_NONE = syntax_stats_dmarc(CHECKED)  # analyze the output from the syntax check, to produce data

DOMAINS_CHECKED = len(CHECKED)  # count numbers of domains that have been checked


# present the results in a easily readable maner
RESULT = f"Total number of domains checked: {DOMAINS_CHECKED} \n\n" \
         f"Total number of SPF records obtained: {SPF_TOTAL} \n" \
         f"Number of valid SPF records observed {SPF_VALID} \n" \
         f"Hardfail: {SPF_HARDFAIL}\n" \
         f"Softfail: {SPF_SOFTFAIL}\n" \
         f"Pass: {SPF_PASS}\n" \
         f"Neutral: {SPF_NEUTRAL}\n" \
         f"Implicit neutral(undefined): {SPF_IMPLICIT_NTRL}\n" \
         f"Redirect: {SPF_REDIRECT}\n"f"Include: {SPF_INCLUDE}\n\n" \
         f"DKIM observed in {DKIM} Domains \n\n" \
         f"Total Number of DMARC records obtained: {DMARC_TOTAL} \n" \
         f"Number of valid DMARC records observed {DMARC_VALID}\n" \
         f"Reject: {DMARC_REJECT}\n"f"Quarantine: {DMARC_QUARANTINE}\n" \
         f"None: {DMARC_NONE}\n\n" \
         f"Domains with both SPF and DKIM: {SPF_DKIM} \n" \
         f"Domains with DKIM only: {DKIM_ONLY}\n\n" \
         f"Domains with none of the standards: {NO_SECURITY}"


# Print the results to screen
print(RESULT)

# store the results to a file
with open("results.txt", "w") as out_file:
        out_file.write(RESULT)
