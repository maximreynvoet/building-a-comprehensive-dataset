from lib.cuckoo.common.abstracts import Signature

class AntiDebug_NtYieldExecution(Signature):
    name = "NtYieldExecution"
    description = "[ByMaxim] Checks presence of debugger through NtYieldExecution returning NoYieldPerformed status"
    severity = 1 # hopelessly unreliable
    categories = ["anti-debug"]
    authors = ["Maxim Reynvoet"]
    minimum = "0.5"

    def run(self):
        for process in self.results["behavior"]["processes"]:
            no_yields = 0
            for call in process["calls"]:
                if call["api"] == "NtYieldExecution":
                    no_yields += 1
                    if no_yields > 4:
                        return True
        return False
