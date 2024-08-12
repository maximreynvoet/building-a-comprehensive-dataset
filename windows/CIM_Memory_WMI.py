from lib.cuckoo.common.abstracts import Signature

class AntiSandbox_CIM_Memory_WMI(Signature):
    name = "CIM_Memory_WMI"
    description = "[ByMaxim] Check CIM_Memory for entries"
    severity = 3
    categories = ["anti-sandbox"]
    authors = ["Maxim Reynvoet"]
    minimum = "0.5"

    def run(self):
    
        createdInstance = False
        for process in self.results["behavior"]["processes"]:
            for call in process["calls"]:
                if call["api"] == "CoCreateInstance":
                    createdInstance = True
                
        for dump in self.results["procdump"]:
            for string in dump["strings"]:
                if string == "SELECT * FROM CIM_Memory" and createdInstance:
                    return True
        return False
