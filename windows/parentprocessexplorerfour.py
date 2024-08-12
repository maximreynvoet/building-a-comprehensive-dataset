# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from lib.cuckoo.common.abstracts import Signature


class AntiDebug_ParentProcessExplorer_technique_four(Signature):
    name = "parent process explorer 4"
    description = "[By Maxim] Checks if the parent process is explorer.exe - technique 4"
    severity = 3
    categories = ["anti-debug"]
    authors = ["Maxim Reynvoet"]
    minimum = "0.5"

    # https://www.apriorit.com/dev-blog/367-anti-reverse-engineering-protection-techniques-to-use-before-releasing-software
    def run(self):
        get_parentprocid = False
        toolhelpsnapshot = False
        for process in self.results["behavior"]["processes"]:
            for call in process["calls"]:
                if call["api"] == "NtQueryInformationProcess" and call["arguments"][0]["value"] == "0":
                    get_parentprocid = True
                if call["api"] == "CreateToolhelp32Snapshot":
                    toolhelpsnapshot = True
        if get_parentprocid and toolhelpsnapshot:
            return True
        return False
