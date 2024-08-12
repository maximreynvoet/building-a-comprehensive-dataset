from lib.cuckoo.common.abstracts import Signature

class AntiSandbox_Cuckoo_AgentArtifacts(Signature):
    name = "Cuckoo_AgentArtifacts"
    description = "Check C directory for files related to cuckoo"
    severity = 3
    categories = ["anti-sandbox"]
    authors = ["Maxim Reynvoet"]
    minimum = "0.5"

    def run(self):

        cuckoo_files = ["analyzer.py","analysis.conf"]
        if(any(string in self.results["target"]["file"]["strings"] for string in cuckoo_files)):
            return True
        
        return False 
