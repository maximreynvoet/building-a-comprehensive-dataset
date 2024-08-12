from lib.cuckoo.common.abstracts import Signature

class AntiDebug_MemoryWalk_GMI(Signature):
    name = "MemoryWalk_GMI"
    description = "[ByMaxim] Walk through memory using GetModuleInformation"
    severity = 3
    categories = ["anti-debug"]
    authors = ["Maxim Reynvoet"]
    minimum = "0.5"

    def run(self):
        
        virtualquery = False
        getmodulehandleex = False
        getmodulefilename = False
        for process in self.results["behavior"]["processes"]:
            for call in process["calls"]:
                if call["api"] == "VirtualQuery":
                    virtualquery = True
                elif call["api"] == "GetModuleHandleExW" and virtualquery:
                    getmodulehandleex = True
                elif call["api"] == "GetModuleFileNameW" and getmodulehandleex:
                    getmodulefilename = True
                elif call["api"] == "K32GetModuleInformation" and getmodulefilename:
                    return True
        return False
