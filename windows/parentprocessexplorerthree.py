# Copyright (C) 2024 Maxim Reynvoet
#
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


class AntiDebug_ParentProcessExplorer_technique_three(Signature):
    name = "parent process explorer 3"
    description = "[By Maxim] checks if the parent process is explorer.exe - technique 3"
    severity = 3
    categories = ["anti-debug"]
    authors = ["Maxim Reynvoet"]
    minimum = "0.5"

    def run(self):
        """
        explorer processs ID (GetShellWindow()+GetWindowThreadProcessId()) and get the
        parent process ID (NtQueryInformationProcess() with ProcessBasicInformation as a ProcessInformationClass parameter).

        GetShellWindow, GetWindowThreadProcessId and NtQueryInformationProcess are looked for in IAT.
        If both are found, this technique is considered as evidence detected.
        """
        get_parentprocid = False
        shell_window_val = ""
        windthreadprocid = False

        for process in self.results["behavior"]["processes"]:
            for call in process["calls"]:
                if call["api"] == "NtQueryInformationProcess" and call["arguments"][0]["value"] == "0":
                    get_parentprocid = True
                if call["api"] == "GetShellWindow":
                    shell_window_val = call["return"]
                if call["api"] == "GetWindowThreadProcessId" and (call["arguments"][0]["value"] == shell_window_val):
                    windthreadprocid = True
        if get_parentprocid and windthreadprocid:
            return True
        return False
