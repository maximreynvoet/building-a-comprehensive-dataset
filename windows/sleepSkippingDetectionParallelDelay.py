from lib.cuckoo.common.abstracts import Signature


class AntiSandbox_SleepSkippingDetection(Signature):
    name = "SleepSkippingDetection"
    description = "[ByMaxim] Tries to detect sleepskipping - parallel delays"
    severity = 3
    categories = ["anti-sandbox"]
    authors = ["Maxim Reynvoet"]
    minimum = "0.5"

    def run(self):
        timer = False
        tickCount = False
        for process in self.results["behavior"]["processes"]:
            for call in process["calls"]:
                if call["api"] == "NtQueryTimer":
                    timer = True
                if call["api"] == "GetTickCount":
                    tickCount = True
                if timer and tickCount:
                    return True
        return False
