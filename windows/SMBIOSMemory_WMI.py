from lib.cuckoo.common.abstracts import Signature

class AntiSandbox_SMBIOSMemory_WMI(Signature):
    name = "SMBIOSMemory_WMI"
    description = "[ByMaxim] Check Win32_SMBIOSMemory for entries."
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
                
        if "procdump" in self.results:
            for dump in self.results["procdump"]:
                for string in dump["strings"]:
                    if string == "SELECT * FROM Win32_SMBIOSMemory" and createdInstance:
                        return True
        return False
