# Import libraries
import dns.resolver

#DOMAIN_NAME = ["mastercard.no", "thelocal.no"]
DOMAIN_NAME = "online.no"


# Declare functions
def get_spf_record(dname):
   try:
      result = dns.resolver.resolve(dname, "TXT")
      for row in result:
         data = row.to_text()
         if "spf" in str(data):
            return True, data
         if "spf" not in str(data):
            pass
      return False, False
   except:
      False, False


def get_DMARC_record(dname):
   try:
      result = dns.resolver.resolve("_DMARC." + dname, "TXT")
      for val in result:
            return True, val.to_text()
   except:
      return False, False










# Execution

#print(get_DMARC_record(DOMAIN_NAME))




