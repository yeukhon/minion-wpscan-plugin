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

lines = re.split("\[\+\]|\[\!\]", stdout)
import pprint

pprint.pprint(get_wp_vuln(lines))
print "version: ", get_version(lines)
print "readme: ", is_readme_exists(lines)
print "theme in use: ", get_wp_theme_in_use(lines)
print "plugins: ", pprint.pprint(get_plugins(lines))
print "themes: ", pprint.pprint(get_themes(lines))
