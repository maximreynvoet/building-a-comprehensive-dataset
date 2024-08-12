LOAD 'age';
set search_path = ag_catalog, "$user", public;
select create_graph('metx');
select create_vlabel('metx', 'Catalog');
select create_vlabel('metx', 'EvasionType');
select create_vlabel('metx', 'Tactic');
select create_vlabel('metx', 'Technique');
select create_elabel('metx','EVASIONTYPE_OF');
select create_elabel('metx','TACTIC_OF');
select create_elabel('metx','TECHNIQUE_OF');
select * from cypher('metx', $$ CREATE (c:Catalog {id : "C01" }) SET c.name = "Malware Evasion Techniques Catalog" RETURN c $$) as (catalog agtype);
select * from cypher('metx', $$ MATCH (c:Catalog {id: "C01"}) MERGE (as1:EvasionType {id : "AS1" , name : "Anti-Sandbox"}) MERGE (as1)-[:EVASIONTYPE_OF]->(c) RETURN as1 $$) as (evasiontype agtype);
select * from cypher('metx', $$ MATCH (c:Catalog {id: "C01"}) MERGE (ad1:EvasionType {id : "AD1" , name : "Anti-Debugging"}) MERGE (ad1)-[:EVASIONTYPE_OF]->(c) RETURN ad1 $$) as (evasiontype agtype);
select * from cypher('metx', $$ MATCH (c:Catalog {id: "C01"}) MERGE (ai1:EvasionType {id : "AI1" , name : "Anti-Instrumentation"}) MERGE (ai1)-[:EVASIONTYPE_OF]->(c) RETURN ai1 $$) as (evasiontype agtype);
select * from cypher('metx', $$ MATCH (c:Catalog {id: "C01"}) MERGE (aa1:EvasionType {id : "AA1" , name : "Anti-Analysis"}) MERGE (aa1)-[:EVASIONTYPE_OF]->(c) RETURN aa1 $$) as (evasiontype agtype);
select * from cypher('metx', $$ MATCH (c:Catalog {id: "C01"}) MERGE (av1:EvasionType {id : "AV1" , name : "Anti-AV"}) MERGE (av1)-[:EVASIONTYPE_OF]->(c) RETURN av1 $$) as (evasiontype agtype);
select * from cypher('metx', $$ MATCH (c:Catalog {id: "C01"}) MERGE (ae1:EvasionType {id : "AE1" , name : "Anti-Emulation"}) MERGE (ae1)-[:EVASIONTYPE_OF]->(c) RETURN ae1 $$) as (evasiontype agtype);
select * from cypher('metx', $$ MATCH (c:Catalog {id: "C01"}) MERGE (am1:EvasionType {id : "AM1" , name : "Anti-VM"}) MERGE (am1)-[:EVASIONTYPE_OF]->(c) RETURN am1 $$) as (evasiontype agtype);
select * from cypher('metx', $$ MATCH (as1:EvasionType {id: "AS1"}) MERGE (asdiavt1:Tactic {id : "ASDIAVT1" , name : "Fileless(AVT) Attacks" , category : "Detection-Independent"}) MERGE (asdiavt1)-[:TACTIC_OF]->(as1) RETURN asdiavt1 $$) as (tactic agtype);
select * from cypher('metx', $$ MATCH (as1:EvasionType {id: "AS1"}) MERGE (asddfin1:Tactic {id : "ASDDFIN1" , name : "Fingerprinting" , category : "Detection-Dependent"}) MERGE (asddfin1)-[:TACTIC_OF]->(as1) RETURN asddfin1 $$) as (tactic agtype);
select * from cypher('metx', $$ MATCH (as1:EvasionType {id: "AS1"}) MERGE (asddtar1:Tactic {id : "ASDDTAR1" , name : "Targeted" , category : "Detection-Dependent"}) MERGE (asddtar1)-[:TACTIC_OF]->(as1) RETURN asddtar1 $$) as (tactic agtype);
select * from cypher('metx', $$ MATCH (as1:EvasionType {id: "AS1"}) MERGE (asddrtt1:Tactic {id : "ASDDRTT1" , name : "Reverse Turing Test" , category : "Detection-Dependent"}) MERGE (asddrtt1)-[:TACTIC_OF]->(as1) RETURN asddrtt1 $$) as (tactic agtype);
select * from cypher('metx', $$ MATCH (as1:EvasionType {id: "AS1"}) MERGE (asdista1:Tactic {id : "ASDISTA1" , name : "Stalling" , category : "Detection-Independent"}) MERGE (asdista1)-[:TACTIC_OF]->(as1) RETURN asdista1 $$) as (tactic agtype);
select * from cypher('metx', $$ MATCH (as1:EvasionType {id: "AS1"}) MERGE (asditrb1:Tactic {id : "ASDITRB1" , name : "Trigger-based" , category : "Detection-Independent"}) MERGE (asditrb1)-[:TACTIC_OF]->(as1) RETURN asditrb1 $$) as (tactic agtype);
select * from cypher('metx', $$ MATCH (ad1:EvasionType {id: "AD1"}) MERGE (adddfin1:Tactic {id : "ADDDFIN1" , name : "Fingerprinting" , category : "Detection-Dependent"}) MERGE (adddfin1)-[:TACTIC_OF]->(ad1) RETURN adddfin1 $$) as (tactic agtype);
select * from cypher('metx', $$ MATCH (ad1:EvasionType {id: "AD1"}) MERGE (adddexc1:Tactic {id : "ADDDEXC1" , name : "Exception Exploitation" , category : "Detection-Dependent"}) MERGE (adddexc1)-[:TACTIC_OF]->(ad1) RETURN adddexc1 $$) as (tactic agtype);
select * from cypher('metx', $$ MATCH (ad1:EvasionType {id: "AD1"}) MERGE (adddtra1:Tactic {id : "ADDDTRA1" , name : "Traps" , category : "Detection-Dependent"}) MERGE (adddtra1)-[:TACTIC_OF]->(ad1) RETURN adddtra1 $$) as (tactic agtype);
select * from cypher('metx', $$ MATCH (ad1:EvasionType {id: "AD1"}) MERGE (addddbs1:Tactic {id : "ADDDDBS1" , name : "Debugger-Specific" , category : "Detection-Dependent"}) MERGE (addddbs1)-[:TACTIC_OF]->(ad1) RETURN addddbs1 $$) as (tactic agtype);
select * from cypher('metx', $$ MATCH (ad1:EvasionType {id: "AD1"}) MERGE (adddtar1:Tactic {id : "ADDDTAR1" , name : "Targeted" , category : "Detection-Dependent"}) MERGE (adddtar1)-[:TACTIC_OF]->(ad1) RETURN adddtar1 $$) as (tactic agtype);
select * from cypher('metx', $$ MATCH (ad1:EvasionType {id: "AD1"}) MERGE (addicfm1:Tactic {id : "ADDICFM1" , name : "Control Flow Manipulation" , category : "Detection-Independent"}) MERGE (addicfm1)-[:TACTIC_OF]->(ad1) RETURN addicfm1 $$) as (tactic agtype);
select * from cypher('metx', $$ MATCH (ad1:EvasionType {id: "AD1"}) MERGE (addiloe1:Tactic {id : "ADDILOE1" , name : "Lockout Evasion" , category : "Detection-Independent"}) MERGE (addiloe1)-[:TACTIC_OF]->(ad1) RETURN addiloe1 $$) as (tactic agtype);
select * from cypher('metx', $$ MATCH (ad1:EvasionType {id: "AD1"}) MERGE (addiavt1:Tactic {id : "ADDIAVT1" , name : "Fileless(AVT) Attacks" , category : "Detection-Independent"}) MERGE (addiavt1)-[:TACTIC_OF]->(ad1) RETURN addiavt1 $$) as (tactic agtype);
select * from cypher('metx', $$ MATCH (ai1:EvasionType {id: "AI1"}) MERGE (aiddfin1:Tactic {id : "AIDDFIN1" , name : "Fingerprinting" , category : "Detection-Dependent"}) MERGE (aiddfin1)-[:TACTIC_OF]->(ai1) RETURN aiddfin1 $$) as (tactic agtype);
select * from cypher('metx', $$ MATCH (ai1:EvasionType {id: "AI1"}) MERGE (aidista1:Tactic {id : "AIDISTA1" , name : "Stalling" , category : "Detection-Independent"}) MERGE (aidista1)-[:TACTIC_OF]->(ai1) RETURN aidista1 $$) as (tactic agtype);
select * from cypher('metx', $$ MATCH (aa1:EvasionType {id: "AA1"}) MERGE (aaddfin1:Tactic {id : "AADDFIN1" , name : "Fingerprinting" , category : "Detection-Dependent"}) MERGE (aaddfin1)-[:TACTIC_OF]->(aa1) RETURN aaddfin1 $$) as (tactic agtype);
select * from cypher('metx', $$ MATCH (av1:EvasionType {id: "AV1"}) MERGE (avddfin1:Tactic {id : "AVDDFIN1" , name : "Fingerprinting" , category : "Detection-Dependent"}) MERGE (avddfin1)-[:TACTIC_OF]->(av1) RETURN avddfin1 $$) as (tactic agtype);
select * from cypher('metx', $$ MATCH (av1:EvasionType {id: "AV1"}) MERGE (avdddis1:Tactic {id : "AVDDDIS1" , name : "Disabling" , category : "Detection-Dependent"}) MERGE (avdddis1)-[:TACTIC_OF]->(av1) RETURN avdddis1 $$) as (tactic agtype);
select * from cypher('metx', $$ MATCH (av1:EvasionType {id: "AV1"}) MERGE (avdiobf1:Tactic {id : "AVDIOBF1" , name : "Obfuscation" , category : "Detection-Independent"}) MERGE (avdiobf1)-[:TACTIC_OF]->(av1) RETURN avdiobf1 $$) as (tactic agtype);
select * from cypher('metx', $$ MATCH (ae1:EvasionType {id: "AE1"}) MERGE (aeddfin1:Tactic {id : "AEDDFIN1" , name : "Fingerprinting" , category : "Detection-Dependent"}) MERGE (aeddfin1)-[:TACTIC_OF]->(ae1) RETURN aeddfin1 $$) as (tactic agtype);
select * from cypher('metx', $$ MATCH (as1:EvasionType {id: "AS1"}) MERGE (asdihin1:Tactic {id : "ASDIHIN1" , name : "Hindering" , category : "Detection-Independent"}) MERGE (asdihin1)-[:TACTIC_OF]->(as1) RETURN asdihin1 $$) as (tactic agtype);
select * from cypher('metx', $$ MATCH (as1:EvasionType {id: "AS1"}) MERGE (asddunh1:Tactic {id : "ASDDUNH1" , name : "Unhooking" , category : "Detection-Dependent"}) MERGE (asddunh1)-[:TACTIC_OF]->(as1) RETURN asddunh1 $$) as (tactic agtype);
select * from cypher('metx', $$ MATCH (am1:EvasionType {id: "AM1"}) MERGE (amddfin1:Tactic {id : "AMDDFIN1" , name : "Fingerprinting" , category : "Detection-Dependent"}) MERGE (amddfin1)-[:TACTIC_OF]->(am1) RETURN amddfin1 $$) as (tactic agtype);
select * from cypher('metx', $$ MATCH (aa1:EvasionType {id: "AA1"}) MERGE (aadista1:Tactic {id : "AADISTA1" , name : "Stalling" , category : "Detection-Independent"}) MERGE (aadista1)-[:TACTIC_OF]->(aa1) RETURN aadista1 $$) as (tactic agtype);
select * from cypher('metx', $$ MATCH (aa1:EvasionType {id: "AA1"}) MERGE (aadiobf1:Tactic {id : "AADIOBF1" , name : "Obfuscation" , category : "Detection-Independent"}) MERGE (aadiobf1)-[:TACTIC_OF]->(aa1) RETURN aadiobf1 $$) as (tactic agtype);
select * from cypher('metx', $$ MATCH (aa1:EvasionType {id: "AA1"}) MERGE (aaddste1:Tactic {id : "AADDSTE1" , name : "Stealth" , category : "Detection-Dependent"}) MERGE (aaddste1)-[:TACTIC_OF]->(aa1) RETURN aaddste1 $$) as (tactic agtype);
select * from cypher('metx', $$ MATCH (aa1:EvasionType {id: "AA1"}) MERGE (aadihin1:Tactic {id : "AADIHIN1" , name : "Hindering" , category : "Detection-Independent"}) MERGE (aadihin1)-[:TACTIC_OF]->(aa1) RETURN aadihin1 $$) as (tactic agtype);
select * from cypher('metx', $$ MATCH (aa1:EvasionType {id: "AA1"}) MERGE (aadddis1:Tactic {id : "AADDDIS1" , name : "Disabling" , category : "Detection-Dependent"}) MERGE (aadddis1)-[:TACTIC_OF]->(aa1) RETURN aadddis1 $$) as (tactic agtype);
select * from cypher('metx', $$ MATCH (aa1:EvasionType {id: "AA1"}) MERGE (aadipri1:Tactic {id : "AADIPRI1" , name : "Process Injection" , category : "Detection-Independent"}) MERGE (aadipri1)-[:TACTIC_OF]->(aa1) RETURN aadipri1 $$) as (tactic agtype);
select * from cypher('metx', $$ MATCH (aa1:EvasionType {id: "AA1"}) MERGE (aadiste2:Tactic {id : "AADISTE2" , name : "Stealth(Detection Independent)" , category : "Detection-Independent"}) MERGE (aadiste2)-[:TACTIC_OF]->(aa1) RETURN aadiste2 $$) as (tactic agtype);
select * from cypher('metx', $$ MATCH (ad1:EvasionType {id: "AD1"}) MERGE (adddche1:Tactic {id : "ADDDCHE1" , name : "Check Integrity" , category : "Detection-Dependent"}) MERGE (adddche1)-[:TACTIC_OF]->(ad1) RETURN adddche1 $$) as (tactic agtype);



select * from cypher('metx', $$ MATCH (asddfin1:Tactic {id: "ASDDFIN1"}) MERGE (t00001:Technique {id : "T00001" , name : "Hardware"}) MERGE (t00001)-[:TECHNIQUE_OF]->(asddfin1) RETURN t00001 $$) as (technique agtype);
select * from cypher('metx', $$ MATCH (asddfin1:Tactic {id: "ASDDFIN1"}) MERGE (t00002:Technique {id : "T00002" , name : "Execution Environment"}) MERGE (t00002)-[:TECHNIQUE_OF]->(asddfin1) RETURN t00002 $$) as (technique agtype);
select * from cypher('metx', $$ MATCH (asddfin1:Tactic {id: "ASDDFIN1"}) MERGE (t00003:Technique {id : "T00003" , name : "Application"}) MERGE (t00003)-[:TECHNIQUE_OF]->(asddfin1) RETURN t00003 $$) as (technique agtype);
select * from cypher('metx', $$ MATCH (asddfin1:Tactic {id: "ASDDFIN1"}) MERGE (t00004:Technique {id : "T00004" , name : "Behavior"}) MERGE (t00004)-[:TECHNIQUE_OF]->(asddfin1) RETURN t00004 $$) as (technique agtype);
select * from cypher('metx', $$ MATCH (asddfin1:Tactic {id: "ASDDFIN1"}) MERGE (t00005:Technique {id : "T00005" , name : "Network"}) MERGE (t00005)-[:TECHNIQUE_OF]->(asddfin1) RETURN t00005 $$) as (technique agtype);

select * from cypher('metx', $$ MATCH (asddtar1:Tactic {id: "ASDDTAR1"}) MERGE (t00006:Technique {id : "T00006" , name : "Environmentally Targeted"}) MERGE (t00006)-[:TECHNIQUE_OF]->(asddtar1) RETURN t00006 $$) as (technique agtype);
select * from cypher('metx', $$ MATCH (asddtar1:Tactic {id: "ASDDTAR1"}) MERGE (t00007:Technique {id : "T00007" , name : "Individually Targeted"}) MERGE (t00007)-[:TECHNIQUE_OF]->(asddtar1) RETURN t00007 $$) as (technique agtype);
select * from cypher('metx', $$ MATCH (asddtar1:Tactic {id: "ASDDTAR1"}) MERGE (t00008:Technique {id : "T00008" , name : "Environment-Dependent Encryption"}) MERGE (t00008)-[:TECHNIQUE_OF]->(asddtar1) RETURN t00008 $$) as (technique agtype);

select * from cypher('metx', $$ MATCH (asddrtt1:Tactic {id: "ASDDRTT1"}) MERGE (t00009:Technique {id : "T00009" , name : "I/O"}) MERGE (t00009)-[:TECHNIQUE_OF]->(asddrtt1) RETURN t00009 $$) as (technique agtype);


select * from cypher('metx', $$ MATCH (asdista1:Tactic {id: "ASDISTA1"}) MERGE (t00010:Technique {id : "T00010" , name : "Simple Sleep"}) MERGE (t00010)-[:TECHNIQUE_OF]->(asdista1) RETURN t00010 $$) as (technique agtype);
select * from cypher('metx', $$ MATCH (asdista1:Tactic {id: "ASDISTA1"}) MERGE (t00011:Technique {id : "T00011" , name : "Advanced Sleep"}) MERGE (t00011)-[:TECHNIQUE_OF]->(asdista1) RETURN t00011 $$) as (technique agtype);
select * from cypher('metx', $$ MATCH (asdista1:Tactic {id: "ASDISTA1"}) MERGE (t00012:Technique {id : "T00012" , name : "Code Stalling"}) MERGE (t00012)-[:TECHNIQUE_OF]->(asdista1) RETURN t00012 $$) as (technique agtype);

select * from cypher('metx', $$ MATCH (asditrb1:Tactic {id: "ASDITRB1"}) MERGE (t00013:Technique {id : "T00013" , name : "Keystroke-Based"}) MERGE (t00013)-[:TECHNIQUE_OF]->(asditrb1) RETURN t00013 $$) as (technique agtype);
select * from cypher('metx', $$ MATCH (asditrb1:Tactic {id: "ASDITRB1"}) MERGE (t00014:Technique {id : "T00014" , name : "System Time"}) MERGE (t00014)-[:TECHNIQUE_OF]->(asditrb1) RETURN t00014 $$) as (technique agtype);
select * from cypher('metx', $$ MATCH (asditrb1:Tactic {id: "ASDITRB1"}) MERGE (t00015:Technique {id : "T00015" , name : "Network Inputs"}) MERGE (t00015)-[:TECHNIQUE_OF]->(asditrb1) RETURN t00015 $$) as (technique agtype);
select * from cypher('metx', $$ MATCH (asditrb1:Tactic {id: "ASDITRB1"}) MERGE (t00016:Technique {id : "T00016" , name : "Covert Trigger Based"}) MERGE (t00016)-[:TECHNIQUE_OF]->(asditrb1) RETURN t00016 $$) as (technique agtype);

select * from cypher('metx', $$ MATCH (adddfin1:Tactic {id: "ADDDFIN1"}) MERGE (t00017:Technique {id : "T00017" , name : "Reading PEB"}) MERGE (t00017)-[:TECHNIQUE_OF]->(adddfin1) RETURN t00017 $$) as (technique agtype);
select * from cypher('metx', $$ MATCH (adddfin1:Tactic {id: "ADDDFIN1"}) MERGE (t00018:Technique {id : "T00018" , name : "Detecting breakpoints"}) MERGE (t00018)-[:TECHNIQUE_OF]->(adddfin1) RETURN t00018 $$) as (technique agtype);
select * from cypher('metx', $$ MATCH (adddfin1:Tactic {id: "ADDDFIN1"}) MERGE (t00019:Technique {id : "T00019" , name : "System Artifacts"}) MERGE (t00019)-[:TECHNIQUE_OF]->(adddfin1) RETURN t00019 $$) as (technique agtype);
select * from cypher('metx', $$ MATCH (adddfin1:Tactic {id: "ADDDFIN1"}) MERGE (t00020:Technique {id : "T00020" , name : "Mining NTQuery Object"}) MERGE (t00020)-[:TECHNIQUE_OF]->(adddfin1) RETURN t00020 $$) as (technique agtype);
select * from cypher('metx', $$ MATCH (adddfin1:Tactic {id: "ADDDFIN1"}) MERGE (t00021:Technique {id : "T00021" , name : "Parent Check"}) MERGE (t00021)-[:TECHNIQUE_OF]->(adddfin1) RETURN t00021 $$) as (technique agtype);
select * from cypher('metx', $$ MATCH (adddfin1:Tactic {id: "ADDDFIN1"}) MERGE (t00022:Technique {id : "T00022" , name : "Timing-Based Detection"}) MERGE (t00022)-[:TECHNIQUE_OF]->(adddfin1) RETURN t00022 $$) as (technique agtype);

select * from cypher('metx', $$ MATCH (adddexc1:Tactic {id: "ADDDEXC1"}) MERGE (t00023:Technique {id : "T00023" , name : "Custom Exception handler"}) MERGE (t00023)-[:TECHNIQUE_OF]->(adddexc1) RETURN t00023 $$) as (technique agtype);

select * from cypher('metx', $$ MATCH (adddtra1:Tactic {id: "ADDDTRA1"}) MERGE (t00024:Technique {id : "T00024" , name : "Instruction Prefix(Rep)"}) MERGE (t00024)-[:TECHNIQUE_OF]->(adddtra1) RETURN t00024 $$) as (technique agtype);
select * from cypher('metx', $$ MATCH (adddtra1:Tactic {id: "ADDDTRA1"}) MERGE (t00025:Technique {id : "T00025" , name : "Interrupt 3,0x2D"}) MERGE (t00025)-[:TECHNIQUE_OF]->(adddtra1) RETURN t00025 $$) as (technique agtype);
select * from cypher('metx', $$ MATCH (adddtra1:Tactic {id: "ADDDTRA1"}) MERGE (t00026:Technique {id : "T00026" , name : "Interrupt 0x41"}) MERGE (t00026)-[:TECHNIQUE_OF]->(adddtra1) RETURN t00026 $$) as (technique agtype);

select * from cypher('metx', $$ MATCH (addddbs1:Tactic {id: "ADDDDBS1"}) MERGE (t00027:Technique {id : "T00027" , name : "OllyDBG"}) MERGE (t00027)-[:TECHNIQUE_OF]->(addddbs1) RETURN t00027 $$) as (technique agtype);
select * from cypher('metx', $$ MATCH (addddbs1:Tactic {id: "ADDDDBS1"}) MERGE (t00028:Technique {id : "T00028" , name : "SoftICE Interrupt 1"}) MERGE (t00028)-[:TECHNIQUE_OF]->(addddbs1) RETURN t00028 $$) as (technique agtype);

select * from cypher('metx', $$ MATCH (adddtar1:Tactic {id: "ADDDTAR1"}) MERGE (t00029:Technique {id : "T00029" , name : "APT Environment Keying"}) MERGE (t00029)-[:TECHNIQUE_OF]->(adddtar1) RETURN t00029 $$) as (technique agtype);
select * from cypher('metx', $$ MATCH (adddtar1:Tactic {id: "ADDDTAR1"}) MERGE (t00030:Technique {id : "T00030" , name : "AI Locksmithing"}) MERGE (t00030)-[:TECHNIQUE_OF]->(adddtar1) RETURN t00030 $$) as (technique agtype);

select * from cypher('metx', $$ MATCH (addicfm1:Tactic {id: "ADDICFM1"}) MERGE (t00031:Technique {id : "T00031" , name : "Self Debugging"}) MERGE (t00031)-[:TECHNIQUE_OF]->(addicfm1) RETURN t00031 $$) as (technique agtype);
select * from cypher('metx', $$ MATCH (addicfm1:Tactic {id: "ADDICFM1"}) MERGE (t00032:Technique {id : "T00032" , name : "Suspended Thread"}) MERGE (t00032)-[:TECHNIQUE_OF]->(addicfm1) RETURN t00032 $$) as (technique agtype);

select * from cypher('metx', $$ MATCH (addicfm1:Tactic {id: "ADDICFM1"}) MERGE (t00033:Technique {id : "T00033" , name : "Thread Hiding"}) MERGE (t00033)-[:TECHNIQUE_OF]->(addicfm1) RETURN t00033 $$) as (technique agtype);
select * from cypher('metx', $$ MATCH (addicfm1:Tactic {id: "ADDICFM1"}) MERGE (t00034:Technique {id : "T00034" , name : "Multi-threading"}) MERGE (t00034)-[:TECHNIQUE_OF]->(addicfm1) RETURN t00034 $$) as (technique agtype);

select * from cypher('metx', $$ MATCH (aiddfin1:Tactic {id: "AIDDFIN1"}) MERGE (t00035:Technique {id : "T00035" , name : "Code Cache Artifacts"}) MERGE (t00035)-[:TECHNIQUE_OF]->(aiddfin1) RETURN t00035 $$) as (technique agtype);
select * from cypher('metx', $$ MATCH (aiddfin1:Tactic {id: "AIDDFIN1"}) MERGE (t00036:Technique {id : "T00036" , name : "Environment Artifacts"}) MERGE (t00036)-[:TECHNIQUE_OF]->(aiddfin1) RETURN t00036 $$) as (technique agtype);
select * from cypher('metx', $$ MATCH (aiddfin1:Tactic {id: "AIDDFIN1"}) MERGE (t00037:Technique {id : "T00037" , name : "JIT Compiler Detection"}) MERGE (t00037)-[:TECHNIQUE_OF]->(aiddfin1) RETURN t00037 $$) as (technique agtype);
select * from cypher('metx', $$ MATCH (aiddfin1:Tactic {id: "AIDDFIN1"}) MERGE (t00038:Technique {id : "T00038" , name : "Overhead Detection"}) MERGE (t00038)-[:TECHNIQUE_OF]->(aiddfin1) RETURN t00038 $$) as (technique agtype);

select * from cypher('metx', $$ MATCH (aidista1:Tactic {id: "AIDISTA1"}) MERGE (t00039:Technique {id : "T00039" , name : "Simple Sleep"}) MERGE (t00039)-[:TECHNIQUE_OF]->(aidista1) RETURN t00039 $$) as (technique agtype);
select * from cypher('metx', $$ MATCH (aidista1:Tactic {id: "AIDISTA1"}) MERGE (t00040:Technique {id : "T00040" , name : "Advanced Sleep"}) MERGE (t00040)-[:TECHNIQUE_OF]->(aidista1) RETURN t00040 $$) as (technique agtype);
select * from cypher('metx', $$ MATCH (aidista1:Tactic {id: "AIDISTA1"}) MERGE (t00041:Technique {id : "T00041" , name : "Code Stalling"}) MERGE (t00041)-[:TECHNIQUE_OF]->(aidista1) RETURN t00041 $$) as (technique agtype);
select * from cypher('metx', $$ MATCH (adddfin1:Tactic {id: "ADDDFIN1"}) MERGE (t00042:Technique {id : "T00042" , name : "Check execution yielding"}) MERGE (t00042)-[:TECHNIQUE_OF]->(adddfin1) RETURN t00042 $$) as (technique agtype);

select * from cypher('metx', $$ MATCH (adddfin1:Tactic {id: "ADDDFIN1"}) MERGE (t00043:Technique {id : "T00043" , name : "Check job object"}) MERGE (t00043)-[:TECHNIQUE_OF]->(adddfin1) RETURN t00043 $$) as (technique agtype);

select * from cypher('metx', $$ MATCH (adddfin1:Tactic {id: "ADDDFIN1"}) MERGE (t00044:Technique {id : "T00044" , name : "Module scanning"}) MERGE (t00044)-[:TECHNIQUE_OF]->(adddfin1) RETURN t00044 $$) as (technique agtype);

select * from cypher('metx', $$ MATCH (adddfin1:Tactic {id: "ADDDFIN1"}) MERGE (t00045:Technique {id : "T00045" , name : "Check debug privileges"}) MERGE (t00045)-[:TECHNIQUE_OF]->(adddfin1) RETURN t00045 $$) as (technique agtype);


select * from cypher('metx', $$ MATCH (aaddfin1:Tactic {id: "AADDFIN1"}) MERGE (t00053:Technique {id : "T00053" , name : "Application"}) MERGE (t00053)-[:TECHNIQUE_OF]->(aaddfin1) RETURN t00053 $$) as (technique agtype);

select * from cypher('metx', $$ MATCH (avddfin1:Tactic {id: "AVDDFIN1"}) MERGE (t00046:Technique {id : "T00046" , name : "Library"}) MERGE (t00046)-[:TECHNIQUE_OF]->(avddfin1) RETURN t00046 $$) as (technique agtype);
select * from cypher('metx', $$ MATCH (avdddis1:Tactic {id: "AVDDDIS1"}) MERGE (t00047:Technique {id : "T00047" , name : "Stop Service"}) MERGE (t00047)-[:TECHNIQUE_OF]->(avdddis1) RETURN t00047 $$) as (technique agtype);
select * from cypher('metx', $$ MATCH (avdddis1:Tactic {id: "AVDDDIS1"}) MERGE (t00048:Technique {id : "T00048" , name : "Set Software Restriction Policy"}) MERGE (t00048)-[:TECHNIQUE_OF]->(avdddis1) RETURN t00048 $$) as (technique agtype);
select * from cypher('metx', $$ MATCH (avdiobf1:Tactic {id: "AVDIOBF1"}) MERGE (t00049:Technique {id : "T00049" , name : "Command Obfuscation"}) MERGE (t00049)-[:TECHNIQUE_OF]->(avdiobf1) RETURN t00049 $$) as (technique agtype);
select * from cypher('metx', $$ MATCH (adddfin1:Tactic {id: "ADDDFIN1"}) MERGE (t00050:Technique {id : "T00050" , name : "Mining PROCESS_INFORMATION_CLASS"}) MERGE (t00050)-[:TECHNIQUE_OF]->(adddfin1) RETURN t00050 $$) as (technique agtype);
select * from cypher('metx', $$ MATCH (adddexc1:Tactic {id: "ADDDEXC1"}) MERGE (t00051:Technique {id : "T00051" , name : "OutputDebugString Errors"}) MERGE (t00051)-[:TECHNIQUE_OF]->(adddexc1) RETURN t00051 $$) as (technique agtype);
select * from cypher('metx', $$ MATCH (adddexc1:Tactic {id: "ADDDEXC1"}) MERGE (t00052:Technique {id : "T00052" , name : "UnhandledExceptionFilter Registration"}) MERGE (t00052)-[:TECHNIQUE_OF]->(adddexc1) RETURN t00052 $$) as (technique agtype);
select * from cypher('metx', $$ MATCH (aeddfin1:Tactic {id: "AEDDFIN1"}) MERGE (t00054:Technique {id : "T00054" , name : "Application"}) MERGE (t00054)-[:TECHNIQUE_OF]->(aeddfin1) RETURN t00054 $$) as (technique agtype);
select * from cypher('metx', $$ MATCH (asdihin1:Tactic {id: "ASDIHIN1"}) MERGE (t00055:Technique {id : "T00055" , name : "Reboot/Shutdown System"}) MERGE (t00055)-[:TECHNIQUE_OF]->(asdihin1) RETURN t00055 $$) as (technique agtype);
select * from cypher('metx', $$ MATCH (asdista1:Tactic {id: "ASDISTA1"}) MERGE (t00056:Technique {id : "T00056" , name : "Onset Delay"}) MERGE (t00056)-[:TECHNIQUE_OF]->(asdista1) RETURN t00056 $$) as (technique agtype);
select * from cypher('metx', $$ MATCH (asddunh1:Tactic {id: "ASDDUNH1"}) MERGE (t00057:Technique {id : "T00057" , name : "Unhooking"}) MERGE (t00057)-[:TECHNIQUE_OF]->(asddunh1) RETURN t00057 $$) as (technique agtype);
select * from cypher('metx', $$ MATCH (amddfin1:Tactic {id: "AMDDFIN1"}) MERGE (t00058:Technique {id : "T00058" , name : "Application"}) MERGE (t00058)-[:TECHNIQUE_OF]->(amddfin1) RETURN t00058 $$) as (technique agtype);
select * from cypher('metx', $$ MATCH (amddfin1:Tactic {id: "AMDDFIN1"}) MERGE (t00059:Technique {id : "T00059" , name : "Execution Environment"}) MERGE (t00059)-[:TECHNIQUE_OF]->(amddfin1) RETURN t00059 $$) as (technique agtype);
select * from cypher('metx', $$ MATCH (amddfin1:Tactic {id: "AMDDFIN1"}) MERGE (t00060:Technique {id : "T00060" , name : "Hardware"}) MERGE (t00060)-[:TECHNIQUE_OF]->(amddfin1) RETURN t00060 $$) as (technique agtype);
select * from cypher('metx', $$ MATCH (aadista1:Tactic {id: "AADISTA1"}) MERGE (t00061:Technique {id : "T00061" , name : "Code Stalling"}) MERGE (t00061)-[:TECHNIQUE_OF]->(aadista1) RETURN t00061 $$) as (technique agtype);
select * from cypher('metx', $$ MATCH (aadiobf1:Tactic {id: "AADIOBF1"}) MERGE (t00062:Technique {id : "T00062" , name : "Embedded Payloads"}) MERGE (t00062)-[:TECHNIQUE_OF]->(aadiobf1) RETURN t00062 $$) as (technique agtype);
select * from cypher('metx', $$ MATCH (aaddste1:Tactic {id: "AADDSTE1"}) MERGE (t00063:Technique {id : "T00063" , name : "Clear Artifacts"}) MERGE (t00063)-[:TECHNIQUE_OF]->(aaddste1) RETURN t00063 $$) as (technique agtype);
select * from cypher('metx', $$ MATCH (aadiobf1:Tactic {id: "AADIOBF1"}) MERGE (t00064:Technique {id : "T00064" , name : "Compile After Delivery"}) MERGE (t00064)-[:TECHNIQUE_OF]->(aadiobf1) RETURN t00064 $$) as (technique agtype);
select * from cypher('metx', $$ MATCH (aadiobf1:Tactic {id: "AADIOBF1"}) MERGE (t00065:Technique {id : "T00065" , name : "Padding"}) MERGE (t00065)-[:TECHNIQUE_OF]->(aadiobf1) RETURN t00065 $$) as (technique agtype);
select * from cypher('metx', $$ MATCH (aadddis1:Tactic {id: "AADDDIS1"}) MERGE (t00066:Technique {id : "T00066" , name : "Set Policies"}) MERGE (t00066)-[:TECHNIQUE_OF]->(aadddis1) RETURN t00066 $$) as (technique agtype);
select * from cypher('metx', $$ MATCH (aadddis1:Tactic {id: "AADDDIS1"}) MERGE (t00067:Technique {id : "T00067" , name : "Set Registry Keys"}) MERGE (t00067)-[:TECHNIQUE_OF]->(aadddis1) RETURN t00067 $$) as (technique agtype);
select * from cypher('metx', $$ MATCH (aadddis1:Tactic {id: "AADDDIS1"}) MERGE (t00068:Technique {id : "T00068" , name : "Disable Windows File Protections"}) MERGE (t00068)-[:TECHNIQUE_OF]->(aadddis1) RETURN t00068 $$) as (technique agtype);
select * from cypher('metx', $$ MATCH (avdddis1:Tactic {id: "AVDDDIS1"}) MERGE (t00069:Technique {id : "T00069" , name : "Command Line Tools"}) MERGE (t00069)-[:TECHNIQUE_OF]->(avdddis1) RETURN t00069 $$) as (technique agtype);
select * from cypher('metx', $$ MATCH (addicfm1:Tactic {id: "ADDICFM1"}) MERGE (t00070:Technique {id : "T00070" , name : "Load Malicious Library"}) MERGE (t00070)-[:TECHNIQUE_OF]->(addicfm1) RETURN t00070 $$) as (technique agtype);
select * from cypher('metx', $$ MATCH (aadipri1:Tactic {id: "AADIPRI1"}) MERGE (t00071:Technique {id : "T00071" , name : "DLL Injection"}) MERGE (t00071)-[:TECHNIQUE_OF]->(aadipri1) RETURN t00071 $$) as (technique agtype);
select * from cypher('metx', $$ MATCH (aadipri1:Tactic {id: "AADIPRI1"}) MERGE (t00072:Technique {id : "T00072" , name : "Extra Window Memory Injection"}) MERGE (t00072)-[:TECHNIQUE_OF]->(aadipri1) RETURN t00072 $$) as (technique agtype);
select * from cypher('metx', $$ MATCH (aadipri1:Tactic {id: "AADIPRI1"}) MERGE (t00073:Technique {id : "T00073" , name : "Process Hollowing"}) MERGE (t00073)-[:TECHNIQUE_OF]->(aadipri1) RETURN t00073 $$) as (technique agtype);
select * from cypher('metx', $$ MATCH (aadiste2:Tactic {id: "AADISTE2"}) MERGE (t00074:Technique {id : "T00074" , name : "Covert Channel"}) MERGE (t00074)-[:TECHNIQUE_OF]->(aadiste2) RETURN t00074 $$) as (technique agtype);
select * from cypher('metx', $$ MATCH (aadiste2:Tactic {id: "AADISTE2"}) MERGE (t00075:Technique {id : "T00075" , name : "Masquerading"}) MERGE (t00075)-[:TECHNIQUE_OF]->(aadiste2) RETURN t00075 $$) as (technique agtype);
select * from cypher('metx', $$ MATCH (aadddis1:Tactic {id: "AADDDIS1"}) MERGE (t00076:Technique {id : "T00076" , name : "Disable Warnings"}) MERGE (t00076)-[:TECHNIQUE_OF]->(aadddis1) RETURN t00076 $$) as (technique agtype);
select * from cypher('metx', $$ MATCH (aadipri1:Tactic {id: "AADIPRI1"}) MERGE (t00077:Technique {id : "T00077" , name : "Image File Execution Options Injection"}) MERGE (t00077)-[:TECHNIQUE_OF]->(aadipri1) RETURN t00077 $$) as (technique agtype);
select * from cypher('metx', $$ MATCH (aadipri1:Tactic {id: "AADIPRI1"}) MERGE (t00078:Technique {id : "T00078" , name : "Silent Process Exit Options Injection"}) MERGE (t00078)-[:TECHNIQUE_OF]->(aadipri1) RETURN t00078 $$) as (technique agtype);
select * from cypher('metx', $$ MATCH (asdiavt1:Tactic {id: "ASDIAVT1"}) MERGE (t00079:Technique {id : "T00079" , name : "PowerShell"}) MERGE (t00079)-[:TECHNIQUE_OF]->(asdiavt1) RETURN t00079 $$) as (technique agtype);
select * from cypher('metx', $$ MATCH (adddche1:Tactic {id: "ADDDCHE1"}) MERGE (t00080:Technique {id : "T00080" , name : "Read Self"}) MERGE (t00080)-[:TECHNIQUE_OF]->(adddche1) RETURN t00080 $$) as (technique agtype);
select * from cypher('metx', $$ MATCH (avddfin1:Tactic {id: "AVDDFIN1"}) MERGE (t00081:Technique {id : "T00081" , name : "Application"}) MERGE (t00081)-[:TECHNIQUE_OF]->(avddfin1) RETURN t00081 $$) as (technique agtype);
select * from cypher('metx', $$ MATCH (aadihin1:Tactic {id: "AADIHIN1"}) MERGE (t00082:Technique {id : "T00082" , name : "Reboot/Shutdown System"}) MERGE (t00082)-[:TECHNIQUE_OF]->(aadihin1) RETURN t00082 $$) as (technique agtype);
select * from cypher('metx', $$ MATCH (avdddis1:Tactic {id: "AVDDDIS1"}) MERGE (t00083:Technique {id : "T00083" , name : "Set Registry Keys"}) MERGE (t00083)-[:TECHNIQUE_OF]->(avdddis1) RETURN t00083 $$) as (technique agtype);
select * from cypher('metx', $$ MATCH (aadddis1:Tactic {id: "AADDDIS1"}) MERGE (t00084:Technique {id : "T00084" , name : "Command Line Tools"}) MERGE (t00084)-[:TECHNIQUE_OF]->(aadddis1) RETURN t00084 $$) as (technique agtype);
select * from cypher('metx', $$ MATCH (asddfin1:Tactic {id: "ASDDFIN1"}) MERGE (t00085:Technique {id : "T00085" , name : "Parent check"}) MERGE (t00085)-[:TECHNIQUE_OF]->(asddfin1) RETURN t00085 $$) as (technique agtype);

select * from cypher('metx', $$ MATCH (asddrtt1:Tactic {id: "ASDDRTT1"}) MERGE (t00086:Technique {id : "T00086" , name : "wear and tear"}) MERGE (t00086)-[:TECHNIQUE_OF]->(asddrtt1) RETURN t00086 $$) as (technique agtype);


LOAD 'age';
set search_path = ag_catalog, "$user", public;
select * from cypher('metx', $$ MATCH (t00001:Technique {id: "T00001"})
SET t00001.Implementations = '[id:i00001;name:CIM_Memory_WMI],[id:i00002;name:CIM_NumericSensor_WMI],[id:i00003;name:CIM_PhysicalConnector_WMI],[id:i00004;name:CIM_Sensor_WMI],[id:i00005;name:CIM_Slot_WMI],[id:i00006;name:CIM_TemperatureSensor_WMI],[id:i00007;name:CIM_VoltageSensor_WMI],[id:i00008;name:CPU_FAN_WMI],[id:i00009;name:Cachememory_WMI],[id:i00014;name:MemoryArray_WMI],[id:i00015;name:MemoryDevice_WMI],[id:i00018;name:Current_NumberCores_WMI],[id:i00020;name:Perfctrs_ThermalZoneInfo_WMI],[id:i00021;name:PhysicalMemory_WMI],[id:i00023;name:PortConnector_WMI],[id:i00024;name:Power_Capabilities],[id:i00026;name:Process_Id_Processor_WMI],[id:i00027;name:QEMU_ACPI],[id:i00028;name:SMBIOSMemory_WMI],[id:i00030;name:VoltageProbe_WMI],[id:i00628;name:HDDName]'
RETURN t00001 $$) as (technique agtype);
select * from cypher('metx', $$ MATCH (t00002:Technique {id: "T00002"})
SET t00002.Implementations = '[id:i00010;name:Cpuid_Hypervisor_Vendor],[id:i00012;name:Current_Temperature_ACPI_WMI],[id:i00013;name:HyperV_Global],[id:i00022;name:PiratedWindows],[id:i00516;name:recon_fingerprint],[id:i00518;name:recon_systeminfo],[id:i00559;name:queries_keyboard_layout],[id:i00573;name:user_enum],[id:i00626;name:screenResolution],[id:i00627;name:Uptime]'
RETURN t00002 $$) as (technique agtype);
LOAD 'age';
set search_path = ag_catalog, "$user", public;
select * from cypher('metx', $$ MATCH (t00003:Technique {id: "T00003"})
SET t00003.Implementations = '[id:i00011;name:Cuckoo_AgentArtifacts], [id:i00073;name:antisandbox_cuckoo_files],[id:i00076;name:antisandbox_fortinet_files],[id:i00077;name:antisandbox_joe_anubis_files],[id:i00080;name:antisandbox_sboxie_libs],[id:i00081;name:antisandbox_sboxie_mutex],[id:i00082;name:antisandbox_sboxie_objects],[id:i00085;name:antisandbox_sunbelt_files],[id:i00086;name:antisandbox_sunbelt_libs],[id:i00088;name:antisandbox_threattrack_files],[id:i00441;name:enumerates_running_processes],[id:i00443;name:cmdline_process_discovery],[id:i00517;name:recon_programs]'
 RETURN t00003 $$) as (technique agtype);

select * from cypher('metx', $$ MATCH (t00005:Technique {id: "T00005"})
SET t00005.Implementations = '[id:i00071;name:antisandbox_check_userdomain],[id:i00574;name:uses_adfind],[id:i00630;name:CuckooTCP]'
 RETURN t00005 $$) as (technique agtype);

select * from cypher('metx', $$ MATCH (t00009:Technique {id: "T00009"})
SET t00009.Implementations = '[id:i00075;name:antisandbox_foregroundwindows],[id:i00078;name:antisandbox_mouse_hook],[id:i00539;name:get_clipboard_data],[id:i00629;name:GetLastInputInfo]'
 RETURN t00009 $$) as (technique agtype);
select * from cypher('metx', $$ MATCH (t00010:Technique {id: "T00010"})
SET t00010.Implementations = '[id:i00084;name:antisandbox_sleep]'
 RETURN t00010 $$) as (technique agtype);

select * from cypher('metx', $$ MATCH (t00019:Technique {id: "T00019"})
SET t00019.Implementations = '[id:i00056;name:antiav_apioverride_libs],[id:i00059;name:antidebug_devices],[id:i00063;name:antiav_nthookengine_libs],[id:i00067;name:antidebug_windows]'
 RETURN t00019 $$) as (technique agtype);


select * from cypher('metx', $$ MATCH (t00022:Technique {id: "T00022"})
SET t00022.Implementations = '[id:i00060;name:antidebug_gettickcount]'
 RETURN t00022 $$) as (technique agtype);

  select * from cypher('metx', $$ MATCH (t00023:Technique {id: "T00023"})
SET t00023.Implementations = '[id:i00055;name:antidebug_addvectoredexceptionhandler],[id:i00061;name:antidebug_guardpages]'
 RETURN t00023 $$) as (technique agtype);

   select * from cypher('metx', $$ MATCH (t00031:Technique {id: "T00031"})
SET t00031.Implementations = '[id:i00058;name:antidebug_debugactiveprocess],[id:i00209;name:debugs_self]'
 RETURN t00031 $$) as (technique agtype);


  select * from cypher('metx', $$ MATCH (t00032:Technique {id: "T00032"})
SET t00032.Implementations = '[id:i00087;name:antisandbox_suspend]'
 RETURN t00032 $$) as (technique agtype);

  select * from cypher('metx', $$ MATCH (t00033:Technique {id: "T00033"})
SET t00033.Implementations = '[id:i00064;name:antidebug_ntsetinformationthread]'
 RETURN t00033 $$) as (technique agtype);

 select * from cypher('metx', $$ MATCH (t00034:Technique {id: "T00034"})
SET t00034.Implementations = '[id:i00062;name:antidebug_ntcreatethreadex]'
 RETURN t00034 $$) as (technique agtype);


 select * from cypher('metx', $$ MATCH (t00041:Technique {id: "T00041"})
SET t00041.Implementations = '[id:i00330;name:MemoryWalk_GMI],[id:i00331;name:MemoryWalk_Hidden]'
 RETURN t00041 $$) as (technique agtype);

 select * from cypher('metx', $$ MATCH (t00042:Technique {id: "T00042"})
SET t00042.Implementations = '[id:i00017;name:NtYieldExecution]'
 RETURN t00042 $$) as (technique agtype);

 select * from cypher('metx', $$ MATCH (t00043:Technique {id: "T00043"})
SET t00043.Implementations = '[id:i00025;name:ProcessJob]'
 RETURN t00043 $$) as (technique agtype);

 select * from cypher('metx', $$ MATCH (t00045:Technique {id: "T00045"})
SET t00045.Implementations = '[id:i00029;name:SeDebugPrivilege]'
 RETURN t00045 $$) as (technique agtype);

 select * from cypher('metx', $$ MATCH (t00046:Technique {id: "T00046"})
SET t00046.Implementations = '[id:i00042;name:antiav_360_libs],[id:i00043;name:antiav_ahnlab_libs],[id:i00044;name:antiav_avast_libs],[id:i00045;name:antiav_bitdefender_libs],[id:i00046;name:antiav_bullgaurd_libs]'
 RETURN t00046 $$) as (technique agtype);


 select * from cypher('metx', $$ MATCH (t00047:Technique {id: "T00047"})
SET t00047.Implementations = '[id:i00052;name:antiav_servicestop]'
 RETURN t00047 $$) as (technique agtype);

 select * from cypher('metx', $$ MATCH (t00048:Technique {id: "T00048"})
SET t00048.Implementations = '[id:i00053;name:antiav_srp]'
 RETURN t00048 $$) as (technique agtype);

 select * from cypher('metx', $$ MATCH (t00049:Technique {id: "T00049"})
SET t00049.Implementations = '[id:i00054;name:antiav_whitespace]'
 RETURN t00049 $$) as (technique agtype);

select * from cypher('metx', $$ MATCH (t00050:Technique {id: "T00050"})
SET t00050.Implementations = '[id:i00057;name:antidebug_checkremotedebuggerpresent]'
 RETURN t00050 $$) as (technique agtype);

select * from cypher('metx', $$ MATCH (t00051:Technique {id: "T00051"})
SET t00051.Implementations = '[id:i00065;name:antidebug_outputdebugstring]'
 RETURN t00051 $$) as (technique agtype);


select * from cypher('metx', $$ MATCH (t00052:Technique {id: "T00052"})
SET t00052.Implementations = '[id:i00066;name:antidebug_setunhandledexceptionfilter]'
 RETURN t00052 $$) as (technique agtype);


select * from cypher('metx', $$ MATCH (t00053:Technique {id: "T00053"})
SET t00053.Implementations = '[id:i00040;name:antianalysis_detectfile],[id:i00041;name:antianalysis_detectreg]'
 RETURN t00053 $$) as (technique agtype);

select * from cypher('metx', $$ MATCH (t00054:Technique {id: "T00054"})
SET t00054.Implementations = '[id:i00068;name:antiemu_windefend],[id:i00069;name:antiemu_wine_reg],[id:i00070;name:antiemu_wine_func]'
 RETURN t00054 $$) as (technique agtype);

 select * from cypher('metx', $$ MATCH (t00055:Technique {id: "T00055"})
SET t00055.Implementations = '[id:i00079;name:antisandbox_restart]'
 RETURN t00055 $$) as (technique agtype);

 select * from cypher('metx', $$ MATCH (t00056:Technique {id: "T00056"})
SET t00056.Implementations = '[id:i00083;name:antisandbox_script_timer]'
 RETURN t00056 $$) as (technique agtype);

  select * from cypher('metx', $$ MATCH (t00057:Technique {id: "T00057"})
SET t00057.Implementations = '[id:i00089;name:antisandbox_unhook]'
 RETURN t00057 $$) as (technique agtype);

 select * from cypher('metx', $$ MATCH (t00058:Technique {id: "T00058"})
SET t00058.Implementations = '[id:i00090;name:antivm_bochs_keys],[id:i00103;name:antivm_parallels_keys],[id:i00104;name:antivm_vbox_devices],[id:i00105;name:antivm_vbox_files],[id:i00106;name:antivm_vbox_keys],[id:i00107;name:antivm_vbox_libs],[id:i00108;name:antivm_vbox_provname],[id:i00109;name:antivm_vbox_window],[id:i00110;name:antivm_vmware_devices],[id:i00111;name:antivm_vmware_events],[id:i00112;name:antivm_vmware_files],[id:i00113;name:antivm_vmware_keys],[id:i00114;name:antivm_vmware_libs],[id:i00115;name:antivm_vmware_mutexes],[id:i00116;name:antivm_vpc_files],[id:i00117;name:antivm_vpc_keys],[id:i00118;name:antivm_vpc_mutex],[id:i00119;name:antivm_xen_keys]'
  RETURN t00058 $$) as (technique agtype);


select * from cypher('metx', $$ MATCH (t00059:Technique {id: "T00059"})
SET t00059.Implementations = '[id:i00091;name:antivm_directory_objects],[id:i00092;name:antivm_generic_bios],[id:i00098;name:antivm_generic_services],[id:i00099;name:antivm_generic_system],[id:i00100;name:antivm_hyperv_keys],[id:i00102;name:antivm_network_adapters]'
 RETURN t00059 $$) as (technique agtype);



 select * from cypher('metx', $$ MATCH (t00060:Technique {id: "T00060"})
SET t00060.Implementations = '[id:i00093;name:antivm_generic_cpu],[id:i00094;name:antivm_generic_disk],[id:i00095;name:antivm_generic_disk_setupapi],[id:i00096;name:antivm_generic_diskreg],[id:i00097;name:antivm_generic_scsi],[id:i00101;name:antivm_checks_available_memory]'
 RETURN t00060 $$) as (technique agtype);

  select * from cypher('metx', $$ MATCH (t00061:Technique {id: "T00061"})
SET t00061.Implementations = '[id:i00120;name:api_spamming]'
 RETURN t00061 $$) as (technique agtype);

   select * from cypher('metx', $$ MATCH (t00062:Technique {id: "T00062"})
SET t00062.Implementations = '[id:i00121;name:api_uuidfromstringa],[id:i00185;name:creates_largekey]'
 RETURN t00062 $$) as (technique agtype);

select * from cypher('metx', $$ MATCH (t00063:Technique {id: "T00063"})
SET t00063.Implementations = '[id:i00163;name:clears_logs],[id:i00213;name:deletes_executed_files],[id:i00333;name:mimics_filetime],[id:i00531;name:removes_zoneid_ads],[id:i00555;name:stealth_webhistory]'
 RETURN t00063 $$) as (technique agtype);

   select * from cypher('metx', $$ MATCH (t00064:Technique {id: "T00064"})
SET t00064.Implementations = '[id:i00182;name:dotnet_code_compile],[id:i00415;name:office_suspicious_processes]'
 RETURN t00064 $$) as (technique agtype);


  select * from cypher('metx', $$ MATCH (t00065:Technique {id: "T00065"})
SET t00065.Implementations = '[id:i00186;name:creates_nullvalue]'
 RETURN t00065 $$) as (technique agtype);


  select * from cypher('metx', $$ MATCH (t00066:Technique {id: "T00066"})
SET t00066.Implementations = '[id:i00219;name:disables_app_launch]'
 RETURN t00066 $$) as (technique agtype);

 select * from cypher('metx', $$ MATCH (t00067:Technique {id: "T00067"})
SET t00067.Implementations = '[id:i00223;name:disables_browser_warn],[id:i00226;name:disables_crashdumps],[id:i00228;name:disables_event_logging],[id:i00229;name:disables_folder_options],[id:i00230;name:disables_notificationcenter],[id:i00233;name:disables_run_command],[id:i00234;name:disables_security],[id:i00235;name:disables_smartscreen],[id:i00236;name:disables_spdy],[id:i00239;name:disables_uac],[id:i00240;name:disables_wer],[id:i00242;name:disables_windows_defender],[id:i00339;name:dotnet_clr_usagelog_regkeys],[id:i00342;name:modify_security_center_warnings],[id:i00343;name:modify_uac_prompt],[id:i00400;name:disables_vba_trust_access],[id:i00401;name:changes_trust_center_settings],[id:i00440;name:prevents_safeboot],[id:i00550;name:stealth_hidden_extension],[id:i00551;name:stealth_hiddenreg],[id:i00552;name:stealth_hide_notifications],[id:i00560;name:tampers_etw],[id:i00562;name:tampers_powershell_logging]'
  RETURN t00067 $$) as (technique agtype);

   select * from cypher('metx', $$ MATCH (t00068:Technique {id: "T00068"})
SET t00068.Implementations = '[id:i00241;name:disables_wfp],[id:i00247;name:disables_windows_file_protection]'
 RETURN t00068 $$) as (technique agtype);

   select * from cypher('metx', $$ MATCH (t00069:Technique {id: "T00069"})
SET t00069.Implementations = '[id:i00243;name:windows_defender_powershell],[id:i00246;name:disables_windows_defender_dism]'
 RETURN t00069 $$) as (technique agtype);

  select * from cypher('metx', $$ MATCH (t00070:Technique {id: "T00070"})
SET t00070.Implementations = '[id:i00250;name:dll_load_uncommon_file_types]'
 RETURN t00070 $$) as (technique agtype);

   select * from cypher('metx', $$ MATCH (t00071:Technique {id: "T00071"})
SET t00071.Implementations = '[id:i00312;name:injection_createremotethread],[id:i00313;name:injection_explorer]'
 RETURN t00071 $$) as (technique agtype);

   select * from cypher('metx', $$ MATCH (t00073:Technique {id: "T00073"})
SET t00073.Implementations = '[id:i00316;name:injection_runpe]'
 RETURN t00073 $$) as (technique agtype);

  select * from cypher('metx', $$ MATCH (t00074:Technique {id: "T00074"})
SET t00074.Implementations = '[id:i00320;name:ipc_namedpipe],[id:i00383;name:network_tor],[id:i00384;name:network_tor_service],[id:i00519;name:accesses_recyclebin]'
 RETURN t00074 $$) as (technique agtype);

  select * from cypher('metx', $$ MATCH (t00075:Technique {id: "T00075"})
SET t00075.Implementations = '[id:i00332;name:mimics_agent],[id:i00334;name:mimics_icon],[id:i00335;name:masquerade_process_name],[id:i00379;name:explorer_http],[id:i00380;name:network_fake_useragent],[id:i00542;name:spoofs_procname],[id:i00553;name:stealth_system_procname]'
 RETURN t00075 $$) as (technique agtype);

    select * from cypher('metx', $$ MATCH (t00076:Technique {id: "T00076"})
SET t00076.Implementations = '[id:i00345;name:modify_zoneid_ads]'
 RETURN t00076 $$) as (technique agtype);

   select * from cypher('metx', $$ MATCH (t00077:Technique {id: "T00077"})
SET t00077.Implementations = '[id:i00425;name:persistence_ifeo]'
 RETURN t00077 $$) as (technique agtype);


  select * from cypher('metx', $$ MATCH (t00078:Technique {id: "T00078"})
SET t00078.Implementations = '[id:i00426;name:persistence_silent_process_exit]'
 RETURN t00078 $$) as (technique agtype);


  select * from cypher('metx', $$ MATCH (t00079:Technique {id: "T00079"})
SET t00079.Implementations = '[id:i00432;name:powershell_command_suspicious],[id:i00433;name:powershell_renamed],[id:i00434;name:powershell_reversed],[id:i00435;name:powershell_variable_obfuscation],[id:i00436;name:powershell_network_connection],[id:i00437;name:powershell_scriptblock_logging],[id:i00438;name:powershell_download],[id:i00439;name:powershell_request]'
 RETURN t00079 $$) as (technique agtype);

   select * from cypher('metx', $$ MATCH (t00080:Technique {id: "T00080"})
SET t00080.Implementations = '[id:i00514;name:reads_self]'
 RETURN t00080 $$) as (technique agtype);

   select * from cypher('metx', $$ MATCH (t00081:Technique {id: "T00081"})
SET t00081.Implementations = '[id:i00048;name:antiav_detectfile],[id:i00049;name:antiav_detectreg],[id:i00050;name:antiav_emsisoft_libs],[id:i00051;name:antiav_qurb_libs]'
 RETURN t00081 $$) as (technique agtype);

  select * from cypher('metx', $$ MATCH (t00082:Technique {id: "T00082"})
SET t00082.Implementations = '[id:i00197;name:critical_process]'
 RETURN t00082 $$) as (technique agtype);

  select * from cypher('metx', $$ MATCH (t00083:Technique {id: "T00083"})
SET t00083.Implementations = '[id:i00244;name:removes_windows_defender_contextmenu],[id:i00245;name:disables_windows_defender_logging],[id:i00248;name:disables_windowsupdate]'
 RETURN t00083 $$) as (technique agtype);

  select * from cypher('metx', $$ MATCH (t00084:Technique {id: "T00084"})
SET t00084.Implementations = '[id:i00249;name:disables_windowsupdate]'
 RETURN t00084 $$) as (technique agtype);
 
  select * from cypher('metx', $$ MATCH (t00085:Technique {id: "T00085"})
SET t00085.Implementations = '[id:i00622;name:parent_process_explorer_1],[id:i00623;name:parent_process_explorer_2],[id:i00623;name:parent_process_explorer_3],[id:i00624;name:parent_process_explorer_4]'
 RETURN t00085 $$) as (technique agtype);
 

select create_vlabel('metx', 'Malware');

select create_elabel('metx','USES');

