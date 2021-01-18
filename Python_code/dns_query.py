# Import libraries
import dns.resolver

DOMAIN_NAME = ["komplett.no", "vg.no", "bladet.no"]
Domain_Name = "vg.no"


# Declare functions
def testtest(dname):
   try:
      result = dns.resolver.resolve(dname, "NS")
      for val in result:
         print('TXT Record : ', val.to_text())

   except:
      print("No record obtained for domain: " + dname)


def test_for_DMARC(dname):
   try:
      result = dns.resolver.resolve("_DMARC." + dname, "TXT")
      for val in result:
         print('TXT Record : ', val.to_text())

   except:
      print("No DMARC record obtained for domain: " + dname)


def test_for_DKIM(dname):
   try:
      result = dns.resolver.resolve(*"_domainkey." + dname, "TXT")
      for val in result:
         print('TXT Record : ', val.to_text())

   except:
      print("No DKIM record obtained for domain: " + dname)








# Execution





for i in DOMAIN_NAME:
   #test_for_DMARC(i)
   #test_for_DKIM(i)
   testtest(i)