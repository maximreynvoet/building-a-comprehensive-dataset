from lib.cuckoo.common.abstracts import Signature


class AntiSandbox_GetLastInputInfo(Signature):
    name = "GetLastInputInfo"
    description = "[ByMaxim] User activity can be checked with the call to the GetLastInputInfo function"
    severity = 3
    categories = ["anti-sandbox"]
    authors = ["Maxim Reynvoet"]
    minimum = "0.5"

    def run(self):
        for process in self.results["behavior"]["processes"]:
            for call in process["calls"]:
                if call["api"] == "GetLastInputInfo":
                    return True
        return False
