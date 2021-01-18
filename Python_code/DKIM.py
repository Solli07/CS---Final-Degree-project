import dns.resolver

DOMAIN_NAME = "wsj.com"
DOMAIN_NAME = "vg.no"



def check_dkim(domain):
    try:
        resolver = dns.resolver.Resolver()
        resolver.resolve('_domainkey.' + domain, 'TXT')
        has_dkim = True
        dkim_error = 'NO Error.'
    except dns.resolver.NXDOMAIN:
        has_dkim = False
        dkim_error = 'NXDOMAIN: _domainkey.' + domain + ' [DKIM]'
    except dns.resolver.NoAnswer:
        has_dkim = True
        dkim_error = 'NoAnswer: _domainkey.' + domain + ' [DKIM]'
    except dns.exception.DNSException as dex:
        has_dkim = True
        dkim_error = 'DNSException: _domainkey.' + domain + ' [DKIM] ' + str(dex)
    except Exception as ex:
        has_dkim = True
        dkim_error = 'General Exception [DKIM] (%s)' % str(ex)
    return has_dkim, dkim_error


def main():
    pass



dkimcheck = check_dkim(DOMAIN_NAME)

print(DOMAIN_NAME + ": ", dkimcheck)