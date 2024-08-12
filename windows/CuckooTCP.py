from lib.cuckoo.common.abstracts import Signature

class AntiSandbox_CuckooTCP(Signature):
    name = "CuckooTCP"
    description = "[ByMaxim] Enumerates TCP table, possibly to check for connection to port 2042 used by ResultServer"
    severity = 3
    categories = ["anti-sandbox"]
    authors = ["Maxim Reynvoet"]
    minimum = "0.5"

    def run(self):
        for process in self.results["behavior"]["processes"]:
            for call in process["calls"]:
                if call["api"] == "GetTcpTable":
                    return True
        return False
