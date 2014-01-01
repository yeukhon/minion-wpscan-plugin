# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

def split_sections(stdout):
    # we will skip the big ascii header
    lines = stdout.split("\n")
    for index, line in enumerate(lines):
        if  "| Started:" in line:
            return lines[index+1:]
    raise Exception("wpscan report does not contain proper header")
