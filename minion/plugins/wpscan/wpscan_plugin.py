# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from minion.plugins.base import ExternalProcessPlugin

class WPScanPlugin(ExternalProcessPlugin):

    PLUGIN_NAME = "WPScan"
    PLUGIN_VERSION = "0.0"

    WPSCAN_NAME = "wpscan.rb"
    WPSCAN_MIN_VERSION = "v2.2r125924d"
    WPSCAN_MAX_VERSION = "v2.2r125924d"

    def do_start(self):
        self.stdout = ""
        self.stderr = ""

        # validate and construct arguments
        configs = self.configuration
        #wordlist_url, enumerate_opts = configs.get('wordlist_url'), \
        #                               configs.get('enumerate_opts')
        target = configs['target']
        commands = ["--url", target]
        #if wordlist_url:
        #    commands += ["--wordlist", word_list_url, "--threads", 20]
        #if enumerate_opts:
        #    commands += ["--enumerate", enumerate_opts]

        self.spawn("/home/vagrant/wpscan/wpscan.rb", commands)

    def do_process_stdout(self, data):
        self.stdout += data

    def do_process_stderr(self, data):
        self.stderr += data

    def do_process_ended(self, process_status):
        if self.stopping and process_status == 9:
            self.report_finish("STOPPED")
        elif process_status == 0:
            summary = "Successful wpscan session"
            description = self.stdout
            self.report_issues([
                {"Summary": summary,
                 "Description": description,
                "Severity": "Info",
                "URLs": [ {"URL": None, "Extra": None} ],
                "FurtherInfo": [ {"URL": None, "Title": None} ]
                }
            ])
            self.report_finish()
