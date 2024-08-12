from lib.cuckoo.common.abstracts import Signature

class AntiSandbox_Process_Id_Processor_WMI(Signature):
    name = "Process_Id_Processor_WMI"
    description = "[ByMaxim] Check ProcessId from Win32_Processor using WMI."
    severity = 3
    categories = ["anti-sandbox"]
    authors = ["Maxim Reynvoet"]
    minimum = "0.5"

    def run(self):
        queryWMI = False
        getProcessorId = False
        
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
                    elif string == "ProcessorId":
                        getProcessorId = True
        
        if queryWMI and getProcessorId:
            return True
        return False
