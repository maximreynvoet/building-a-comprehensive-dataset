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


class AntiSandbox_HDDName(Signature):
    name = "HDDName"
    description = "[ByMaxim] Checks if the HDDName matches known sandbox HDD name"
    severity = 3
    categories = ["anti-sandbox"]
    authors = ["Maxim Reynvoet"]
    minimum = "0.5"

    def run(self):
        setup = False
        for process in self.results["behavior"]["processes"]:
            for call in process["calls"]:
                if call["api"] == "SetupDiGetClassDevsW":
                    setup = True
                    # if call["arguments"][0]["value"] == "": TODO: fill in
                    # return True
                elif call["api"] == "SetupDiGetDeviceRegistryPropertyW":
                    # if call["arguments"][0]["value"] == 12 and TODO: check validity
                    if setup:
                        return True
        return False
