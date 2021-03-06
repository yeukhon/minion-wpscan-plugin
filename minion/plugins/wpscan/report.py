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
        elif ("We found" in line and "plugins" in line) or \
             ("plugins found" in line):
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
        user["id"] = row[0].strip()
        user["login"] = row[1].strip()
        user["name"] = row[2].strip() or None
        if len(row) < 4:
            user["password"] = None
        else:
            user["password"] = row[3].strip() or None
        users.append(user)
    return users

def get_users(lines):
    table_line = None
    # if brute force is enable, we go straight to that.
    text = "".join(lines)
    if "Starting the password brute forcer" in text:
        return get_users_from_brute_forcer(lines)
    else:
        return get_users_from_enumeration(lines)

def get_users_from_enumeration(lines):
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

def get_users_from_brute_forcer(lines):
    seen_brute_force = False
    linebreak_count = 0
    table_lines = []
    for index, line in enumerate(lines):
        if "Brute Forcing" in line:
            break
    _lines = line.split("\n")
    for index, line in enumerate(_lines):
        if "Brute Forcing" in line:
            seen_brute_force = True
        elif seen_brute_force:
            if linebreak_count == 2:
                break
            else:
                if not line:
                    linebreak_count += 1
                else:
                    table_lines += line.split("\n")
    if table_lines:
        return parse_ascii_table("\n".join(table_lines))
    else:
        return []

def dictize_report(stdout):
    r = re.compile("\033\[[0-9;]+m")
    stdout = r.sub("", stdout)
    lines = re.split("\[\+\]|\[\!\]", stdout)

    wordpress_vuln = get_wp_vuln(lines)
    version = get_version(lines)
    theme_in_use = get_wp_theme_in_use(lines)
    plugins = get_plugins(lines)
    themes = get_themes(lines)
    users = get_users(lines)
    readme_exists = is_readme_exists(lines)

    wordpress = copy.deepcopy(WORDPRESS)
    wordpress["version"] = version
    wordpress["readme_exists"] = readme_exists
    wordpress["theme"] = theme_in_use
    wordpress["vulnerabilities"] = wordpress_vuln

    report = {
        "wordpress": wordpress,
        "plugins": plugins,
        "themes": themes,
        "users": users
    }

    return report

BASIC_FURTHER_INFO = [
    {
        "URL": "http://codex.wordpress.org/Hardening_WordPress",
        "Title": "WordPress Codex - Hardening WordPress Security",
    },
    {
        "URL": "https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=wordpress",
        "Title": "Wordpress - Common Vulnerabilities and Exposures"
    }
]

FURTHER_INFO_ON_README = [
    {
        "URL": "http://wordpress.org/support/topic/readmehtml-is-security-hole",
        "Title": "WordPress Support - readme.html is security hole?"
    },
]
FURTHER_INFO_ON_README += BASIC_FURTHER_INFO

_issues = {
    "readme_exists":
        {
            "Code": "WPSCAN-0",
            "Summary": "readme.html exists",
            "Description": "The readme.html can be used to find the version of the WordPress the target is using. \
This is a low-risk security item. WordPress hacker can also find out version by looking at the meta tag or the RSS \
feed.",
            "Severity": "Low",
            "URLs": [ {"URL": None, "Extra": None} ],
            "FurtherInfo": FURTHER_INFO_ON_README
        },
    "wordpress_vulnerable":
        {
            "Code": "WPSCAN-1",
            "Summary": "{count} vulnerabilities identified for WordPress {version}",
            "Description": "Target WordPress installation is running version {version}. There are {count} vulnerabilities \
identified from this version. Each vulnerability is reported below.",
            "Severity": "High",
            "URLs": [ {"URL": None, "Extra": None} ],
            "FurtherInfo": BASIC_FURTHER_INFO
        }
}

def format_issue(issue_key, format_list):
    issue = copy.deepcopy(_issues[issue_key])
    for component in format_list:
        for component_name, kwargs in component.items():
            issue[component_name] = issue[component_name].format(**kwargs)
    return issue

def get_issues(report):
    issues = []
    version = report["wordpress"]["version"]
    wp_vuln = report["wordpress"]["vulnerabilities"]
    if wp_vuln:
        count = len(wp_vuln)
        issues.append(
            format_issue('wordpress_vulnerable',
                [{"Summary": {"count": count, "version": version}},
                 {"Description": {"count": count, "version": version}}]))
    if report["wordpress"]["readme_exists"]:
        issues.append(_issues["readme_exists"])
    return issues

def debug():
    import pprint
    with open("/home/vagrant/wpscan10", "r") as f:
        stdout = f.read()
    lines = re.split("\[\+\]|\[\!\]", stdout)
    print "wordpress: ", pprint.pprint(get_wp_vuln(lines))
    print "version: ", get_version(lines)
    print "readme: ", is_readme_exists(lines)
    print "theme in use: ", get_wp_theme_in_use(lines)
    print "plugins: ", pprint.pprint(get_plugins(lines))
    print "themes: ", pprint.pprint(get_themes(lines))
    print "users: ", pprint.pprint(get_users(lines))
