from lib.cuckoo.common.abstracts import Signature

class AntiSandbox_Power_Capabilities(Signature):
    name = "Power_Capabilities"
    description = "[ByMaxim] Check what power states are enabled."
    severity = 3
    categories = ["anti-sandbox"]
    authors = ["Maxim Reynvoet"]
    minimum = "0.5"

    def run(self):
    
        for process in self.results["behavior"]["processes"]:
           for call in process["calls"]:
               if call["api"] == "GetPwrCapabilities":
                   return True
        return False