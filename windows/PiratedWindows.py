from lib.cuckoo.common.abstracts import Signature

class AntiSandbox_PiratedWindows(Signature):
    name = "PiratedWindows"
    description = "[ByMaxim] Check if the local is a genuine Windows local."
    severity = 3
    categories = ["anti-sandbox"]
    authors = ["Maxim Reynvoet"]
    minimum = "0.5"

    def run(self):
    
        for process in self.results["behavior"]["processes"]:
            for call in process["calls"]:
                if call["api"] == "SLIsGenuineLocal":
                    return True
        return False
