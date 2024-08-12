from lib.cuckoo.common.abstracts import Signature


class AntiSandbox_SleepSkippingDetectionSystemTime(Signature):
    name = "SleepSkippingDetection"
    description = "[ByMaxim] Tries to detect sleepskipping - SystemTime"
    severity = 3
    categories = ["anti-sandbox"]
    authors = ["Maxim Reynvoet"]
    minimum = "0.5"

    def run(self):
        condGetSystemTime = False
        condQuerySystemInfo = False
        for process in self.results["behavior"]["processes"]:
            for call in process["calls"]:
                if call["api"] == "GetSystemTimeAsFileTime":
                    condGetSystemTime = True
                if call["api"] == "NtQuerySystemInformation":
                    if call["arguments"][0]["value"] == "3":
                        condQuerySystemInfo = True
        if condGetSystemTime and condQuerySystemInfo:
            return True
        return False
