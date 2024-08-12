from lib.cuckoo.common.abstracts import Signature

class AntiVM_HyperV_Global(Signature):
    name = "HyperV_Global"
    description = "[ByMaxim] Check global object directory for artifacts"
    severity = 3
    categories = ["anti-debug"]
    authors = ["Maxim Reynvoet"]
    minimum = "0.5"

    def run(self):
        
        enumeratesObjectDirectory = False
        for process in self.results["behavior"]["processes"]:
            for call in process["calls"]:
                if call["api"] == "NtOpenDirectoryObject":
                    if call["arguments"][2]["value"] == "C:\\GLOBAL??":
                        enumeratesObjectDirectory = True
        
        if "procdump" in self.results:
            for dump in self.results["procdump"]:
                global_object_strings = [string for string in dump["strings"]]
                if(any(string in ["VMBUS#","VDRVROOT","VmGenerationCounter","VmGid"] for string in global_object_strings)) and enumeratesObjectDirectory:
                    return True
        
        return False 
