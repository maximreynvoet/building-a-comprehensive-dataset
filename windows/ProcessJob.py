from lib.cuckoo.common.abstracts import Signature

class AntiDebug_ProcessJob(Signature):
    name = "ProcessJob"
    description = "[ByMaxim] Checks whether the process is part of a job object and, if so, any non-whitelisted processes are part of that job"
    severity = 3
    categories = ["anti-debug"]
    authors = ["Maxim Reynvoet"]
    minimum = "0.5"

    def run(self):  
        currentPid = "0"
        getsProcessName = False
        getsProcessIdList = False
        getsJobProcessHandle = False
        conhost_string_present = False
        for process in self.results["behavior"]["processes"]:
            for call in process["calls"]:
                if call["api"] == "QueryInformationJobObject" and (call["arguments"][0]["value"] == "3"):
                    getsProcessIdList = True
                elif call["api"] == "GetCurrentProcessId":
                    currentPid = call["return"]
                elif call["api"] == "OpenProcess" and (call["arguments"][1] != currentPid):
                    getsJobProcessHandle = True
                elif call["api"] == "K32GetProcessImageFileNameW" and getsJobProcessHandle:
                    getsProcessName = True
        if "procdump" in self.results:
            for dump in self.results["procdump"]:
                if ("g\\Windows\\System32\\conhost.exe" in [string for string in dump["strings"]]):
                    conhost_string_present = True
        
        if getsProcessIdList and getsProcessName and conhost_string_present:
            return True
        return False
