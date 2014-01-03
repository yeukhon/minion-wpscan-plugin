# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import copy
import re

def split_lines(stdout):
    # we will skip the big ascii header
    lines = stdout.split("\n")
    for index, line in enumerate(lines):
        if  "| Started:" in line:
            return lines[index+1:]
    raise Exception("wpscan report does not contain proper header")

WORDPRESS = {
    "version": "",
    "is_multi_site": False,
    "is_outdated": False,
    "readme_exists": True,
    "theme": "",
    "vulnerabilities": []
}
WORDPRESS_VULN = {
    "title": "",
    "references": [],
    "fixed_since": ""
}

PLUGIN = {
    "name": "",
    "vulnerabilities": {}
}
THEME = {
    "name": "",
    "vulnerabilities": {}
}
PLUGIN_OR_THEME_VULN = {
    "title": "",
    "references": [],
    "fixed_since": ""
}

USER = {
    "id": "",
    "login": "",
    "name": "",
    "password": ""
}
# report structure looks like this https://github.com/yeukhon/minion-wpscan-plugin/issues/1

def is_single_statement(next_line, next_second_line):
    watch_list = ("[!]", "[+]")
    for criminal in watch_list:
        if next_line.startswith(criminal) or next_second_line.startswith(criminal):
            return True
    return False
def _split(line, delim):
    splits = line.split(delim, 1)
    if len(splits) == 2:
        return splits[0].strip(), splits[1].strip()
    else:
        return None, None

with open("/home/vagrant/wpscan12", "r") as f:
    stdout = f.read()


def is_readme_exists(lines):
    for line in lines:
        if "readme.html" in line:
            return True
    return False

def get_version(lines):
    for line in lines:
        if "WordPress version" in line:
            r = re.compile("\d.\d.\d")
            return r.search(line).group()
    return "unknown"

def get_wp_vuln(lines):
    wp_vuln = None
    vuln_list = []
    for line in lines:
        if "identified from the version number" in line:
            # split the whole block on " | "or " | * " starting symbol
            _lines = filter(None, re.split("\||\\s*\|\\s*\*", line))
            # the end result is _lines[0] == title and the rest groups of title,references
            for line in _lines[1:]:
                label, value = _split(line, ":")
                if label == "Title":
                    wp_vuln = copy.deepcopy(WORDPRESS_VULN)
                    wp_vuln["title"] = value
                    vuln_list.append(wp_vuln)
                elif label == "Reference":
                    wp_vuln["references"].append(value)
                elif label == "Fixed in":
                    wp_vuln["fixed_since"] = value
            break
    return vuln_list

def get_wp_theme_in_use(lines):
    for line in lines:
        if "WordPress theme in use" in line:
            r = re.compile("WordPress theme in use: (.+)")
            name = r.findall(line)[-1]
            return name
    return "unknown"

def get_plugins(lines):
    vuln_list = []
    plugin = {}
    plugin_vuln = {}
    for line in lines:
        if "No plugins found" in lines:
            return []
        elif "We found" in line and "plugins" in line:
            _lines = filter(None, re.split("\||\\s*\|\\s*\*", line))
            for line in _lines[1:]:
                label, value = _split(line, ":")
                if label == "Name":
                    plugin = copy.deepcopy(PLUGIN)
                    vuln_list.append(plugin)
                    plugin["name"] = value
                elif label == "Title":
                    plugin_vuln = copy.deepcopy(PLUGIN_OR_THEME_VULN)
                    plugin["vulnerabilities"] = plugin_vuln
                    plugin_vuln["title"] = value
                elif label == "Reference":
                    plugin_vuln["references"].append(value)
                elif label == "Fixed in":
                    plugin_vuln["fixed_since"] = value
            break
    return vuln_list

def get_themes(lines):
    vuln_list = []
    theme = {}
    theme_vuln = {}
    for line in lines:
        if "No themes found" in lines:
            return []
        elif "We found" in line and "themes" in line:
            _lines = filter(None, re.split("\||\\s*\|\\s*\*", line))
            for line in _lines[1:]:
                label, value = _split(line, ":")
                if label == "Name":
                    theme = copy.deepcopy(THEME)
                    vuln_list.append(theme)
                    theme["name"] = value
                elif label == "Title":
                    theme_vuln = copy.deepcopy(PLUGIN_OR_THEME_VULN)
                    theme["vulnerabilities"] = theme_vuln
                    theme_vuln["title"] = value
                elif label == "Reference":
                    theme_vuln["references"].append(value)
                elif label == "Fixed in":
                    theme_vuln["fixed_since"] = value
            break
    return vuln_list

def parse_ascii_table(table):
    users = []
    # split on the border divider
    _s1 = re.split("\+\-*\+", table)
    table = "".join(_s1)
    # split on the column divider
    _s2 = re.split("\|\s", table)
    # now by default without password cracking it should have 3 columns
    # but we know exactly how many by counting the items between the
    # two ----\n
    for index, line in enumerate(_s2[1:]):
        if line in _s2[0]:
            break
    
    # because the way we split end up with an extra "empty column", so
    # we must step at the actual number of column + 1
    # and the index at the point we break is exactly the number of 
    # actual column, so the total size is that +1 (plus we are zero-based)
    step_size = index + 1

    # we actuall start reading the first row from _s2[index+2:]
    _s3 = _s2[index+2:]
    for step in range(0, len(_s3), step_size):
        # -1 here in step size because we are zero-based indexing
        row = _s3[step:step+step_size-1]
        user = copy.deepcopy(USER)
        user["id"] = row[0]
        user["login"] = row[1]
        user["name"] = row[2]
        if len(row) < 4:
            user["password"] = None
        else:
            user["password"] = row[3]
        users.append(user)
    return users

def get_users(lines):
    table_line = None
    for index, line in enumerate(lines):
        if "No users found" in lines:
            return users
        elif "We found the following" in line and "user/s" in line:
            table_line = line
            break
    if table_line:
        _table_lines = table_line.split("\n")
        table = "".join(_table_lines[1:])
        return parse_ascii_table(table)
    else:
        return []       

lines = re.split("\[\+\]|\[\!\]", stdout)
import pprint

pprint.pprint(get_wp_vuln(lines))
print "version: ", get_version(lines)
print "readme: ", is_readme_exists(lines)
print "theme in use: ", get_wp_theme_in_use(lines)
print "plugins: ", pprint.pprint(get_plugins(lines))
print "themes: ", pprint.pprint(get_themes(lines))
print "users: ", pprint.pprint(get_users(lines))
