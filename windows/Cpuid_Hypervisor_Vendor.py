from lib.cuckoo.common.abstracts import Signature

class AntiSandbox_Cpuid_Hypervisor_Vendor(Signature):
    name = "Cpuid_Hypervisor_Vendor"
    description = "[ByMaxim] When CPUID is called with EAX=0x40000000, cpuid returns the hypervisor signature."
    severity = 3
    categories = ["anti-sandbox"]
    authors = ["Maxim Reynvoet"]
    minimum = "0.5"

    def run(self):
    
        hypervisor_strings = ["KVMKVMKVM","Microsoft Hv","VMwareVMware","XenVMMXenVMM","prl hyperv  ","VBoxVBoxVBox"]
        #if(any(string in self.results["target"]["file"]["strings"] for string in hypervisor_strings)):
        #    return True
                
        if "procdump" in self.results:
            for dump in self.results["procdump"]:
                if(any(string in dump["strings"] for string in hypervisor_strings)):
                    return True
        return False
