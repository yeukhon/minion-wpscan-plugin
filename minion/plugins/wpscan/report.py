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


def is_single_statement(next_line, next_second_line):
    watch_list = ("[!]", "[+]")
    for criminal in watch_list:
        if next_line.startswith(criminal) or next_second_line.startswith(criminal):
            return True
    return False

with open("/home/vagrant/wpscan10", "r") as f:
    stdout = f.read()

# wpscan is memory expensive so let's not create lots
# of lists as we slice
all_lines = (stdout.split("\n"))

# key will be the actual statement
# value is the detail or None if it is a single statement
attentions = {}
info = {}

# first, skip the header by locate the 2nd _____
_i = all_lines.index("_______________________________________________________________",1)
starting_index = _i + 5  # skip 5 lines to skip __, \n, | URL, | Started and \n

# next we want to get the single info and attentions.
remaining_lines = all_lines[starting_index:]
for index, line in enumerate(remaining_lines):
    # if it is single line either next two line is [!] or [+]
    # some sections are broken up by \n so we need to check at least two lines!
    _next_line = remaining_lines[index+1]
    _next_second_line = remaining_lines[index+2]
    is_single = is_single_statement(_next_line, _next_second_line)
    if is_single:
        if line.startswith("[!]"):
            clean_line = line.split("[!] ")[-1]
            attentions[clean_line] = None 
        elif line.startswith("[+]"):
            clean_line = line.split("[+] ")[-1]
            info[clean_line] = None
    else:
        starting_index = index
        break   # stop here, move to the second section

# right now, the section should be multi-line [!] and [+]
# it should be identitfying the vulnerabilities from the version number
remaining_lines = remaining_lines[starting_index:]
if "identified from the version number" in remaining_lines[0]:
    clean_line = line.split("[!]")[-1].replace(":", "").strip()
    current_att_list = []
    current_vuln = {}
    reference_urls = []
    attentions[clean_line] = current_att_list

    starting_index = 2  # remember we slice again, so index starts at 0 and we skip [!] and "| " lines
    remaining_lines = remaining_lines[starting_index:]

    # every new vulnerability starts with Title
    # and each new vulnerability is a dict contains title, one or more reference
    for index, line in enumerate(remaining_lines):
        line = line.strip()
        if line.startswith("| *"):
            clean_line = line.split("| * ")[-1]
            _sline = clean_line.split(":", 1)
            header, rest_line = _sline[0], _sline[1].strip()
            if header == "Title":
                # remember to save the reference urls for the previous one
                # before zeroing out current_vuln and reference_urls
                current_vuln["Reference"] = tuple(reference_urls)

                reference_urls = []
                current_vuln = {}
                current_vuln[header] = rest_line
                current_att_list.append(current_vuln)
            else:
                if header == "Fixed in":
                    current_vuln[header] = rest_line
                else:
                    reference_urls.append(rest_line)
        elif line.startswith("[+]") or line.startswith("[!]"):
            starting_index = index
            break
import pprint
pprint.pprint(attentions)
pprint.pprint(info)
# next should be detecting the Wordpress theme in used
if "Wordpress theme in used" in remaining_lines[starting_index]:
    header = remaining_lines[starting_index].split("[+]").strip()
    header = "Wordpress theme in used"
