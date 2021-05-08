####################
#  import modules  #
####################
import csv

####################
#  Global values   #
####################

FILE = 'majestic_million.csv'
NO_domains = [] # list for holding domain names

####################
#  Program         #
####################

with open(FILE, 'r', encoding='utf-8') as csv_file: # open csv file with top million domains
    csv_reader = csv.reader(csv_file, delimiter=',')
    for line in csv_reader:
        try:   # extract and append domain name to list of Norwegian domains
            if line[3] == 'no':
                NO_domains.append(line[2])
        except IndexError: # ignore malformed entries in csv file
            pass

# write Norwegian domains to separate csv file
with open('no_domains.csv', 'w', newline='') as file:
    write = csv.writer(file)
    for i in NO_domains:
        write.writerow([i])

