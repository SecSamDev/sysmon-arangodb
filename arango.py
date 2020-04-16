from pyArango.connection import *
from pyArango.collection import Collection, Field
from pyArango.graph import Graph, EdgeDefinition
import json
from arango_sysmon import * 
conn = Connection(username="root", password="openSesame")
import ntpath
from time import perf_counter
from random import randrange
from sysmon_ingest import SysmonIngest


# Documentos
try:
    db = conn.createDatabase(name="sysmon")
except Exception as e:
    db = conn["sysmon"]

db.dropAllCollections()

# Grafos
name = 'Sysmon_PC_GRAPH_1'
customSysmonGraph(name)
PC_GRAPH_1 = db.createGraph(name, numberOfShards = 10, smartGraphAttribute = "provider_guid")

# Only for Logs from winlogbeat (Elasticsearch)
ingest = SysmonIngest(db,PC_GRAPH_1)

with open('SysmonEventCodes/EventCode1.json', 'r') as json_file:
    data = json.load(json_file)
    for log_entrie in data:
        ingest.process_event(log_entrie)
    
with open('SysmonEventCodes/EventCode3.json', 'r') as json_file:
    data = json.load(json_file)
    for log_entrie in data:
        ingest.process_event(log_entrie)

with open('SysmonEventCodes/EventCode10.json', 'r') as json_file:
    data = json.load(json_file)
    for log_entrie in data:
        ingest.process_event(log_entrie)         

with open('SysmonEventCodes/EventCode12.json', 'r') as json_file:
    data = json.load(json_file)
    for log_entrie in data:
        ingest.process_event(log_entrie)                