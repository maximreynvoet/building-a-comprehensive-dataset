from lib.cuckoo.common.abstracts import Signature

class AntiVM_QEMU_ACPI(Signature):
    name = "QEMU_ACPI"
    description = "[ByMaxim] Check for ACPI firmware"
    severity = 3
    categories = ["anti-debug"]
    authors = ["Maxim Reynvoet"]
    minimum = "0.5"

    def run(self):
        
        getsSystemFirmwareTables = False
        for process in self.results["behavior"]["processes"]:
           for call in process["calls"]:
               if call["api"] == "EnumSystemFirmwareTables":
                   return True
        
        for process in self.results["behavior"]["processes"]:
            for call in process["calls"]:
                if call["api"] == "GetSystemFirmwareTable":
                        getsSystemFirmwareTables

        if "procdump" in self.results:                
            for dump in self.results["procdump"]:
                dump_strings = [string for string in dump["strings"]]
                if(any(string in ["BOCHt","BXPCt"] for string in dump_strings)):
                    if getsSystemFirmwareTables:
                        return True         
        return False 
