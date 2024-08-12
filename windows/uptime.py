from lib.cuckoo.common.abstracts import Signature

class AntiSandbox_Uptime(Signature):
    name = "Uptime"
    description = "[ByMaxim] Uses NtQuerySystemInformation with SystemTimeOfDayInformation to check system uptime"
    severity = 3
    categories = ["anti-sandbox"]
    authors = ["Maxim Reynvoet"]
    minimum = "0.5"

    def run(self):
        for process in self.results["behavior"]["processes"]:
            for call in process["calls"]:
                if call["api"] == "NtQuerySystemInformation":
                    if call["arguments"][0]["value"] == "3":
                        return True
        return False
