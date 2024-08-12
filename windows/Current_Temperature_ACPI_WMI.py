from lib.cuckoo.common.abstracts import Signature

class AntiSandbox_Current_Temperature_ACPI_WMI(Signature):
    name = "Current_Temperature_ACPI_WMI"
    description = "[ByMaxim] Check Current Temperature using WMI, this requires admin privileges."
    severity = 3
    categories = ["anti-sandbox"]
    authors = ["Maxim Reynvoet"]
    minimum = "0.5"

    def run(self):
        queryWMI = False
        getCurrentTemperature = False
        
        createdInstance = False
        for process in self.results["behavior"]["processes"]:
            for call in process["calls"]:
                if call["api"] == "CoCreateInstance":
                    createdInstance = True
                
        if "procdump" in self.results:
            for dump in self.results["procdump"]:
                for string in dump["strings"]:
                    if string == "SELECT * FROM MSAcpi_ThermalZoneTemperature" and createdInstance:
                        queryWMI = True
                    elif string == "CurrentTemperature":
                        getCurrentTemperature = True
        
        if queryWMI and getCurrentTemperature:
            return True
        return False
