import spf
import re

'''
NB!!!
 The Syntax checking functionality in this file is borrowed from the "My Email Communications Security Assessment (MECSA) Stand alone Tool"
 By Kambourakis, Draper and Sanches - available from the following github repository: https://github.com/mecsa/mecsa-st 
'''

EMAILREGEX = re.compile(r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)")


def check_syntax_spf(spf_text, domain):
    '''
    Given an SPF record, it will check its syntax.

    :param spf_text: String, the SPF record to test
    :param domain: String, domain name tested
    :return:  Boolean, SPF syntax OK? True:False
              String, code returned by the check() function (250, 500,..)
              String, if failed, description of the syntax error.
    '''
    try:
        check_result, check_code, check_description = (None, None, None)
        q = spf.query(s='postmaster@%s' % domain, h=domain, i='127.0.0.1')
        check_result, check_code, check_description = q.check(spf=spf_text)
        if check_result in ["none", "permerror", "temperror"]:
            return False, check_code, check_description
        else:
            return True, check_code, check_description
    except Exception as error:
        return False, str(check_code), "SPF-Text Syntax-Error " + str(error)


def check_syntax_dmarc(raw_dmarc_str):
    '''
    Performs a syntax check on a DMARC TXT record string
    example record: v=DMARC1\; p=none\; rua=mailto:mailauth-reports@google.com
    :param raw_dmarc_str: String representing a DMARC record
    :return: Boolean - 'raw_dmarc_str' complies with DMARC Syntax? True:Falsee
             String  - warning message
             String  - error message
    '''

    def check_dmarc_report_uri(uri, tag):
        '''
        Checks if a URI (valid in rua and ruf tags) is valid
        URI takes the format of mailto:<email-address>[!<digits>[kmgt]]
        :param uri: uri to assess
        :param tag: complete rua/ruf tag
        :return: Boolean - valid URI? True:False
        '''
        if not uri.startswith("mailto:"):
            return False, "Unknown URI found in '%s' tag" % tag
        uri_value = uri[7:]
        parts = uri_value.split("!")
        if len(parts) > 2:
            return False, "Malformed URI in '%s' tag" % tag
        if not EMAILREGEX.match(parts[0]):
            return False, "Malformed email address in '%s' tag" % tag
        if len(parts) == 2:
            if len(parts[1]) == 0:
                return False, "Empty maximun size in '%s' tag" % tag
            if parts[1][-1].isdigit():
                size = parts[1]
            else:
                size = parts[1][:-1]
                if parts[1][-1] not in ["k", "m", "g", "t"]:
                    return False, "Malformed email address in '%s' tag" % tag
            if not size.isdigit():
                return False, "Malformed maximun size in '%s' tag" % tag
        return True, None

    VALID_TAGS = ["adkim", "aspf", "pct", "p", "rf", "ri", "rua", "ruf", "sp", "v"]
    dmarc_str = raw_dmarc_str.replace(' ', '')
    # Split in tag_value pairs, separated by ; and run sanity checks on the syntax
    tags = {}
    unknown_tag = False
    try:
        for tag_value in dmarc_str.split(";"):
            if len(tag_value) > 0:
                parts = tag_value.split("=")
                if len(parts) != 2:
                    dmarc_error = "Error parsing DMARC record: Invalid pair tag-value found (%s)" % dmarc_str

                    return False, None, dmarc_error
                if parts[0] not in VALID_TAGS:
                    unknown_tag = True
                if len(tags) == 0 and (parts[0] != "v" or parts[1] != "DMARC1"):
                    dmarc_error = "Error parsing DMARC record: First tag-value pair was not v=DMARC1 (%s)" % dmarc_str

                    return False, None, dmarc_error
                if parts[0] in tags:
                    dmarc_error = "Error parsing DMARC record: Duplicated tag found (%s)" % dmarc_str

                    return False, None, dmarc_error
                if len(parts[1]) == 0:
                    dmarc_error = "Error parsing DMARC record: Empty value found (%s)" % dmarc_str

                    return False, None, dmarc_error
                tags[parts[0]] = parts[1]
    except Exception as ex:
        dmarc_error = "Error parsing DMARC record: %s (%s)" % (dmarc_str, str(ex))

        return False, None, dmarc_error

    # Run specific sanity checks on each tag value
    try:
        for tag in tags:
            value = tags[tag]
            # "DEBUG: Testing syntax for DMARC tag pair: %s - %s" %(tag, value)
            if tag == "adkim" and value not in ["r", "s"]:
                dmarc_error = "Error in Sanity Check DMARC record: Unknown value for 'adkim' tag (%s)" % dmarc_str

                return False, None, dmarc_error
            elif tag == "aspf" and value not in ["r", "s"]:
                dmarc_error = "Error in Sanity Check DMARC record: Unknown value for 'aspf' tag (%s)" % dmarc_str

                return False, None, dmarc_error
            elif tag == "fo":
                parts = value.split(":")
                for part in parts:
                    if part not in ["0", "1", "d", "s"]:
                        dmarc_error = "Error in Sanity Check DMARC record: Unknown value for 'fo' tag (%s)" % dmarc_str

                        return False, None, dmarc_error
            elif tag == "p" and value not in ["none", "quarantine", "reject"]:
                dmarc_error = "Error in Sanity Check DMARC record: Unknown value for 'p' tag (%s)" % dmarc_str

                return False, None, dmarc_error
            elif tag == "pct":
                if not value.isdigit():
                    dmarc_error = "Error in Sanity Check DMARC record: Value for 'pct' tag is not an integer (%s)" % dmarc_str

                    return False, None, dmarc_error
                if int(value) > 100:
                    dmarc_error = "Error in Sanity Check DMARC record: Value for 'pct' is not in range 0-100 (%s)" % dmarc_str

                    return False, None, dmarc_error
            elif tag == "rf":
                # TODO: to be implemented
                pass
            elif tag == "ri" and not value.isdigit():
                dmarc_error = "Error in Sanity Check DMARC record: Value for 'ri' tag is not an integer (%s)" % dmarc_str

                return False, None, dmarc_error
            elif tag == "rua":
                for uri in value.split(","):
                    res, res_str = check_dmarc_report_uri(uri, tag)
                    if not res:
                        dmarc_error = "Error in Sanity Check DMARC record: (%s, %s)" % (res_str, dmarc_str)

                        return False, None, dmarc_error
            elif tag == "ruf":
                for uri in value.split(","):
                    res, res_str = check_dmarc_report_uri(uri, tag)
                    if not res:
                        dmarc_error = "Error in Sanity Check DMARC record: (%s, %s)" % (res_str, dmarc_str)

                        return False, None, dmarc_error
            elif tag == "sp" and value not in ["none", "quarantine", "reject"]:
                dmarc_error = "Error in Sanity Check DMARC record: Unknown value for 'sp' tag (%s)" % dmarc_str

                return False, None, dmarc_error
    except Exception as ex:
        dmarc_error = "Error in Sanity Check DMARC record: %s (%s)" % (str(ex), dmarc_str)

        return False, None, dmarc_error

    if unknown_tag:
        return True, "Dmarc syntax OK (Unknown Tag Found!)", None
    else:
        return True, "Dmarc syntax OK", None


