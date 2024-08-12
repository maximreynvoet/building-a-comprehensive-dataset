from lib.cuckoo.common.abstracts import Signature

class AntiDebug_SeDebugPrivileges(Signature):
    name = "SeDebugPrivilege"
    description = "[ByMaxim] If process has SeDebugPrivileges when debugged then OpenProcess will succeed"
    severity = 3
    categories = ["anti-debug"]
    authors = ["Maxim Reynvoet"]
    minimum = "0.5"

    def run(self):
        pid = "0"
        for process in self.results["behavior"]["processes"]:
            for call in process["calls"]:
                if call["api"] == "CsrGetProcessId":
                    pid = call["arguments"][0]["value"]
                if call["api"] == "OpenProcess" and (call["arguments"][1]["value"] == pid):
                    return True
        return False
