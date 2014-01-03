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
    return splits[0].strip(), splits[1].strip()

with open("/home/vagrant/wpscan10", "r") as f:
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
    return vuln_list

lines = re.split("\[\+\]|\[\!\]", stdout)
import pprint

pprint.pprint(get_wp_vuln(lines))
print "version: ", get_version(lines)
print "readme: ", is_readme_exists(lines)
