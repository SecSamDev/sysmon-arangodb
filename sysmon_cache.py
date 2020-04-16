import ntpath

emptyEdgeInfo = {
    "_name" : "EMPTY",
    "record_id": 0,
    "@timestamp": 0,
    "UtcTime": 0,
    "LogonGuid": "0",
    "event_id": 0,
    "CurrentDirectory": ""
}

class SysmonCache():
    def __init__(self,db, graph):
        self.process_list = {}
        self.ipList = {}
        self.registryList = {}
        self.db = db
        self.graph = graph

    def find_ip(self, ip,computer):
        if ip in self.ipList:
            return self.ipList[ip]
        else:
            queryResult = self.db.AQLQuery("FOR x IN NetworkObject FILTER x.Ip == @ip AND x.Computer == @computer LIMIT 1 RETURN x", bindVars={"ip": ip, "computer" : computer})
            if len(queryResult) > 0:
                self.ipList[ip] = queryResult[0]
                return queryResult[0]
            else:
                ipNode = self.graph.createVertex("NetworkObject", {
                    "_name" : ip,
                    "Ip": ip,
                    "Computer" : computer
                })
                self.ipList[ip] = ipNode
                return ipNode


    def find_registry(self, target,computer):
        if target in self.registryList:
            return self.registryList[target]
        else:
            queryResult = self.db.AQLQuery("FOR x IN RegistryObject FILTER x.Path == @path AND x.Computer == @computer LIMIT 1 RETURN x", bindVars={"path": target, "computer" : computer})
            if len(queryResult) > 0:
                self.registryList[target] = queryResult[0]
                return queryResult[0]
            else:
                nodo = self.graph.createVertex("RegistryObject", {
                    "_name" : target,
                    "Path": target,
                    "Computer" : computer
                })
                self.registryList[target] = nodo
                return nodo


    def find_sysmon_process(self, process_id, process_guid, process_image="", computer="", logon_guid=""):
        if process_id in self.process_list and self.process_list[process_id]["ProcessGuid"] == process_guid:
            return self.process_list[process_id]
        else:
            queryResult = self.db.AQLQuery(
                "FOR x IN SysmonProcess FILTER x.ProcessId == @process_id AND x.ProcessGuid == @process_guid AND x.Computer == @computer LIMIT 1 RETURN x", bindVars={"process_id": process_id, "process_guid": process_guid, "computer" : computer})
            if len(queryResult) > 0:
                self.process_list[process_id] = queryResult[0]
                return queryResult[0]
            else:
                parentProcess = self.graph.createVertex("SysmonProcess", {
                    "_name" : ntpath.basename(process_image),
                    "ProcessId": int(process_id),
                    "ProcessGuid": process_guid,
                    "Image": process_image,
                    "ProcessName": ntpath.basename(process_image),
                    "LogonGuid" : logon_guid if logon_guid != "" else "",
                    "Computer" : computer
                })
                if not 0 in self.process_list:
                    self.process_list[0] = self.graph.createVertex("SysmonProcess", {
                        "_name" : "STARTUP",
                        "ProcessId": 0,
                        "ProcessGuid": "0",
                        "CommandLine": "STARTUP",
                        "Image": "STARTUP",
                        "ProcessName": "STARTUP",
                        "LogonGuid" : logon_guid,
                        "Computer" : computer
                    })
                self.graph.link('CreateNewProcess',
                        self.process_list[0], parentProcess, emptyEdgeInfo)
                self.process_list[parentProcess["ProcessId"]] = parentProcess
                return parentProcess
