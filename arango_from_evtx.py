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
from flatten_json import flatten

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

ingest = SysmonIngest(db,PC_GRAPH_1)

def clean_data(event_data):
    new_event = {}
    for key in event_data.keys():
        new_event[key.replace("Event.","").replace("System.","").replace("EventData.","").replace(".#attributes.","")] = event_data[key]
    return new_event

with open('evtx_syspce.jsonl', 'r') as json_file:
    line = json_file.readline()
    while line:
        data = json.loads(line)
        event_data = clean_data(flatten(data,separator="."))
        #print(json.dumps(event_data))
        #break
        ingest.process_event(event_data)
        line = json_file.readline()
        

