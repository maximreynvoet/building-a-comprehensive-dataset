from lib.cuckoo.common.abstracts import Signature

class AntiSandbox_Cachememory_WMI(Signature):
    name = "Cachememory_WMI"
    description = "[ByMaxim] Check Win32_CacheMemory for entries"
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
                if string == "SELECT * FROM Win32_CacheMemory" and createdInstance:
                    return True
        return False
