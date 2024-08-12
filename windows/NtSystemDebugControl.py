from lib.cuckoo.common.abstracts import Signature

class AntiDebug_NtSystemDebugControl(Signature):
    name = "NtSystemDebugControl"
    description = "[ByMaxim] Uses NtSystemDebugControl to check low memory for debugger status"
    severity = 3
    categories = ["anti-debug"]
    authors = ["Maxim Reynvoet"]
    minimum = "0.5"

    def run(self):
        for process in self.results["behavior"]["processes"]:
            for call in process["calls"]:
                if call["api"] == "NtSystemDebugControl":
                    if call["arguments"][0]["value"] == "20":
                        return True
        return False
