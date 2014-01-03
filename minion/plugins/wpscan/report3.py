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


with open("/home/vagrant/wpscan12", "r") as f:
    stdout = f.readlines()

attentions = {}
info = {}
found_attention = False
found_info = False
header = None

for index, line in enumerate(stdout):
    sline = line.strip()
    if sline.startswith("[+]"):
        if "We found the following" in sline:
            r = re.compile("(\d+)")
            num_users = int(r.findall(sline)[-1])
            header = "%d user%s discovered" % (num_users, "s"[num_users==1:])
            # first 3 lines of ascii table are for column headers
            # each user occupies two lines (the text row and the --- row)
            # we also -1 at the end due to counting
            # index is at ht [+] We found the following header
            # starting index is index+1, ending index is num_users * 2 + 3 - 1
            sindex = index + 1
            eindex = sindex + 2 + num_users * 2
            table = stdout[sindex:eindex]
            columns = "".join(table).split("|")
            # to find # of columns, just find where 1st element is a substring
            info[header] = columns
            # at the end of the report
            break
        else:
            found_info = True
            found_attention = False
            found_user_table = False
        header = sline.split("[+]")[1].strip()
        info[header] = []
        if "theme in use" in header:
            found_theme_in_use_check = True
    elif sline.startswith("[!]"):
        found_attention = True
        found_info = False
        header = sline.split("[!]")[1].strip()
        attentions[header] = []
    elif found_attention:
        if sline:
            if sline == "\n":
                found_attetion = False
            elif ": |" in sline or "<==" in sline:
                continue
            else:
                line = re.split("\|\s\**|\|\s*", sline)[-1].strip()
                if line:
                    attentions[header].append(line)
    elif found_info:
        if sline:
            if sline == "\n":
                found_info = False
            elif ": |" in sline or "<==" in sline:
                continue
            else:
                line = re.split("\|\s*", sline)[-1].strip()
                if line:
                    info[header].append(line)
"""
import pdb; pdb.set_trace()
for line in stdout:
    line = line.strip()
    if (found_attention or found_info):
        if line and line.startswith("|"):
            lines = re.split("\| *|\|\s*", line)
            line = lines[1]
            if line:
                if found_attention:
                    attentions[-1][current_att_title].append(line)
                elif found_info:
                    info[-1][current_info_title].append(line)
        else:
            found_attention = False
            found_info = False
    elif line.startswith("[!]"):
        found_info = False
        line = line.split("[!]")[1].strip()
        d = {line: []}
        current_att_title = line
        attentions.append(d)
        found_attention = True
    elif line.startswith("[+]"):
        found_attention = False
        line = line.split("[+]")[1].strip()
        current_info = {line: []}
        current_info_title = line
        info.append(current_info)
        found_info = True
    else:
        found_attention = False
        found_info = False
"""

import pprint
pprint.pprint(attentions)
pprint.pprint(info)
