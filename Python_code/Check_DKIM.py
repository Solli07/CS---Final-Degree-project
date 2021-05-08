import dns.resolver

'''
NB!!!
 The functionality in this file is borrowed from the "My Email Communications Security Assessment (MECSA) Stand alone Tool"
 By Kambourakis, Draper and Sanches - available from the following github repository: https://github.com/mecsa/mecsa-st 
'''

def check_dkim(domain):
    '''
            Given a domain, query the DNS server for _domainkey.<domain>
            if the server does not support DKIM, the answer should be NXDOMAIN
            :param domain: Domain name tested
            :return: (boolean, String[])
                      domain has DKIM record? True:False
                      answer sent from the domain Server
            '''
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






