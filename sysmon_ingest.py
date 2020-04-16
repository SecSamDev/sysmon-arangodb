from sysmon_cache import SysmonCache
from sysmon_exceptioner import SysmonExcepcioner
from arango_sysmon import *
import ntpath

def clean_guid(text):
    return text.replace("{","").replace("}","")

def clean_attribute_name(attr_name):
    if attr_name == "winlog.event_id":
        return "EventID"
    if attr_name == "winlog.computer_name":
        return "Computer"
    if attr_name == "winlog.record_id":
        return "EventRecordID"
    if attr_name == "SecurityUserID":
        return "UserID"
    return attr_name.replace("event_data.","").replace("winlog.","").replace("#attributes.","").replace(".","_")

class SysmonIngest():
    def __init__(self,db, graph):
        self.cache = SysmonCache(db,graph)
        self.graph = graph
        self.db = db
        self.excepcioner = SysmonExcepcioner()

    def process_event(self,log_event):
        log_event = SysmonIngest.translate_attributes(log_event)
        log_event["EventID"] = int(log_event["EventID"])
        if self.excepcioner.is_false_positive(log_event):
            return
        if log_event["EventID"] == 1:
            return self.process_event_1(log_event)
        if log_event["EventID"] == 3:
            return self.process_event_3(log_event)
        if log_event["EventID"] == 10:
            return self.process_event_10(log_event)
        if log_event["EventID"] == 12:
            return self.process_event_12(log_event)

    def process_event_1(self, log_event):
        log_event["ParentProcessId"] = int(log_event["ParentProcessId"])
        log_event["ProcessId"] = int(log_event["ProcessId"])
        log_event["ParentProcessGuid"] = clean_guid(log_event["ParentProcessGuid"])
        log_event["ProcessGuid"] = clean_guid(log_event["ProcessGuid"])
        log_event["ProcessName"] = ntpath.basename(log_event["Image"])
        log_event["_name"] = log_event["ProcessName"]
        
        new_log = {}

        for log_key in SysmonProcess._fields.keys():
            new_log[log_key] = log_event[log_key]

        edgeInfo = {
            "_name" : log_event["CommandLine"],
            "EventRecordID": log_event["EventRecordID"],
           
            "UtcTime": log_event["UtcTime"],
            
            "CurrentDirectory": log_event["CurrentDirectory"],
            "CommandLine" : log_event["CommandLine"],
            "Hashes" : log_event["Hashes"],
            "Computer" : log_event["Computer"]
        }

        parentProcess = self.cache.find_sysmon_process(int(log_event["ParentProcessId"]),log_event["ParentProcessGuid"], computer=log_event["Computer"],process_image=log_event["ParentImage"], logon_guid=log_event["LogonGuid"])

        saved_entrie = self.graph.createVertex("SysmonProcess", new_log)
        self.graph.link('CreateNewProcess', parentProcess, saved_entrie, edgeInfo)
        return saved_entrie


    def process_event_3(self, log_event):

        log_event["Computer"] = log_event["Computer"]
        log_event["ProcessGuid"] = clean_guid(log_event["ProcessGuid"])

        edgeInfo = {
            "_name" : log_event["Protocol"],
            "EventRecordID": log_event["EventRecordID"],
           
            "UtcTime": log_event["UtcTime"],
            
            "User": log_event["user_name"],
            "DestinationPort": log_event["DestinationPort"],
            "DestinationIp": log_event["DestinationIp"],
            "SourceIp": log_event["SourceIp"],
            "SourcePort" : log_event["SourcePort"],
            "Protocol" : log_event["Protocol"],
            "Computer" : log_event["Computer"]
        }

        parentProcess = self.cache.find_sysmon_process(int(log_event["ProcessId"]),log_event["ProcessGuid"],process_image=log_event["Image"], computer=log_event["Computer"])

        saved_entrie = self.cache.find_ip(log_event["DestinationIp"], log_event["Computer"])
        self.graph.link('NetworkConnection', parentProcess, saved_entrie, edgeInfo)
        return saved_entrie

    def process_event_10(self, log_event):
        log_event["TargetProcessId"] = int(log_event["TargetProcessId"])
        log_event["SourceProcessId"] = int(log_event["SourceProcessId"])
        log_event["SourceProcessGUID"] = clean_guid(log_event["SourceProcessGUID"])
        log_event["TargetProcessGUID"] = clean_guid(log_event["TargetProcessGUID"])
        log_event["SourceImage"] = log_event["SourceImage"]
        log_event["TargetImage"] = log_event["TargetImage"]
        log_event["_name"] = "Process accessed"

        edgeInfo = {
            "_name" : log_event["CallTrace"],
            "EventRecordID": log_event["EventRecordID"],
            "UtcTime": log_event["UtcTime"],
            "CallTrace": log_event["CallTrace"],
            "User": log_event["user_name"] if "user_name" in log_event else (log_event["UserID"] if "UserID" in log_event else "" + str(print(str(log_event.keys())))) ,
            "Computer" : log_event["Computer"]
        }

        sourceProcess = self.cache.find_sysmon_process(int(log_event["SourceProcessId"]),log_event["SourceProcessGUID"], computer=log_event["Computer"],process_image=log_event["SourceImage"])
        targetProcess = self.cache.find_sysmon_process(int(log_event["TargetProcessId"]),log_event["TargetProcessGUID"], computer=log_event["Computer"],process_image=log_event["TargetImage"])

        self.graph.link('ProcessAccessed', sourceProcess, targetProcess, edgeInfo)
        return None

    def process_event_12(self, log_event):
        log_event["ProcessGuid"] = clean_guid(log_event["ProcessGuid"])
        log_event["Computer"] = log_event["Computer"]
        edgeInfo = {
            "_name" : log_event["EventType"],
            "EventRecordID": log_event["EventRecordID"],
           
            "UtcTime": log_event["UtcTime"],
            
            "EventType": log_event["EventType"],
            "User": log_event["user_name"],
            "Computer" : log_event["Computer"]
        }

        parentProcess = self.cache.find_sysmon_process(int(log_event["ProcessId"]),log_event["ProcessGuid"],process_image=log_event["Image"], computer=log_event["Computer"])

        saved_entrie = self.cache.find_registry(log_event["TargetObject"], log_event["Computer"])
        self.graph.link('RegistryEvent', parentProcess, saved_entrie, edgeInfo)
        return saved_entrie

    def translate_attributes(log_event):
        new_event = {}
        for log_attribute_name in log_event.keys():
            new_event[clean_attribute_name(log_attribute_name)] = log_event[log_attribute_name]

        return new_event
    
