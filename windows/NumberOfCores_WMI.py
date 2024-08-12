from lib.cuckoo.common.abstracts import Signature

class AntiSandbox_NumberCores_WMI(Signature):
    name = "Current_NumberCores_WMI"
    description = "[ByMaxim] Check number of cores using WMI."
    severity = 3
    categories = ["anti-sandbox"]
    authors = ["Maxim Reynvoet"]
    minimum = "0.5"

    def run(self):
        queryWMI = False
        getNumberOfCores = False
        
        createdInstance = False
        for process in self.results["behavior"]["processes"]:
            for call in process["calls"]:
                if call["api"] == "CoCreateInstance":
                    createdInstance = True
                
        if "procdump" in self.results:
            for dump in self.results["procdump"]:
                for string in dump["strings"]:
                    if string == "SELECT * FROM Win32_Processor" and createdInstance:
                        queryWMI = True
                    elif string == "NumberOfCores":
                        getNumberOfCores = True
        
        if queryWMI and getNumberOfCores:
            return True
        return False
