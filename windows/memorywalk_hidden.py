from lib.cuckoo.common.abstracts import Signature

class AntiDebug_MemoryWalk_Hidden(Signature):
    name = "MemoryWalk_Hidden"
    description = "[ByMaxim] Walk through memory looking for hidden modules"
    severity = 3
    categories = ["anti-debug"]
    authors = ["Maxim Reynvoet"]
    minimum = "0.5"

    def run(self):
        getHandle = False
        for process in self.results["behavior"]["processes"]:
            for call in process["calls"]:
                if call["api"] == "GetModuleHandleExW":
                    getHandle = True
                elif call["api"] == "K32GetMappedFileNameW" and getHandle:
                    return True
        return False