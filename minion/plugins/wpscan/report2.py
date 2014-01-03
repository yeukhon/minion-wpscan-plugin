# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import re

def split_lines(stdout):
    # we will skip the big ascii header
    lines = stdout.split("\n")
    for index, line in enumerate(lines):
        if  "| Started:" in line:
            return lines[index+1:]
    raise Exception("wpscan report does not contain proper header")

"""
def group_sections(lines):
    wp_version = None
    wp_vulns = []
    plugin_enumeration = []

    # when this flag is set to True, it signals to add lines to vuln
    append_flag = False
    r_version = re.compile("WordPress version (?P<version>\d.\d.\d)")
    r_vuln = re.compile("(?P<num>\d*) vulnerabilities identified from the version number")
    for line in lines:
q        m_version = r_version.search(line)
        m_vuln = r_vuln.search(line)
        if m_version:
            wp_version = m_version.group('version')
        elif m_vuln:
            wp_vulns = 
        if "WordPress version" in line:
            r = re.compile("[+] WordPress version (?P<version>\d.\d.\d) identified from meta generator")
"""

with open("/home/vagrant/wpscan10", "r") as f:
    stdout = f.read()

# this is some ugly regex...
r_attention = re.compile(r"\[\!\]\s(.+)\n((\s\|\s.+|\n)*)?")
attentions = r_attention.findall(stdout, re.MULTILINE)
# okay, attentions might end up something like this:
#
#[("The WordPress 'http://192.168.1.103/wordpress-3.1.3/readme.html' file exists",
#  '',
#  ''),
# ('4 vulnerabilities identified from the version number:',
#  ' |\n | * Title: wp-admin/link-manager.php Multiple Parameter SQL Injection\n | * Reference: http://secunia.com/advisories/45099\n | * Reference: http://osvdb.org/73723\n | * Reference: http://www.exploit-db.com/exploits/17465/\n | * Fixed in: 3.1.4\n |\n | * Title: XSS vulnerability in swfupload in WordPress\n | * Reference: http://seclists.org/fulldisclosure/2012/Nov/51\n |\n | * Title: XMLRPC Pingback API Internal/External Port Scanning\n | * Reference: https://github.com/FireFart/WordpressPingbackPortScanner\n |\n | * Title: WordPress XMLRPC pingback additional issues\n | * Reference: http://lab.onsec.ru/2013/01/wordpress-xmlrpc-pingback-additional.html\n\n',
#  '\n')]
#
# Yeah that shit is ugly and expensive.

r_multi_detail= re.compile(r"\s\|\s\*\s(.+)")
new_attentions = []
print attentions
for section in attentions:
    temp = []
    print section
    for line in section:
        line = line.lstrip(" |\n")
        matches = r_multi_detail.findall(line, re.MULTILINE)
        if matches:
            temp.append(matches)
        else:
            temp.append(line)
    if temp:
        temp = filter(None, temp)
        new_attentions.append(temp)

attentions_dict = {}

for attention in new_attentions:
    # single-line attention notice
    if len(attention) == 1:
        attentions_dict[attention[0]] = None
    else:
        # for multi-line notice we group individual discovery
        attentions_dict[attention[0]] = []
        details = attention[1]
    
        _ = []
        # we start by creating the first group.
        # new_group is a semaphore that signals when the next Title is
        # encountered.
        new_group = True
        for detail in details:
            if detail.startswith("Title:"):
                if new_group:
                    new_group = False
                else:
                    attentions_dict[attention[0]].append(_)
                    _ = []
                _.append(detail)
            else:
                _.append(detail)

print attentions_dict

"""
 = re.compile(r"\s\|\s\*\s(.+)")

r_infos = re.compile(r"\[\+\]\s(.+)\n((\s\|\s.+|\n)*)?")
 = re.compile(r"\s\|\s(.+)\n*?")


#lines = stdout[1:]
#print dir(lines)
#lines = split_lines(stdout)
"""
