from pyArango.collection import Collection, Field, Edges
from pyArango.graph import Graph, EdgeDefinition


class SysmonProcess(Collection):
    _fields = {
        "_name" : Field(),
        "Image": Field(),
        "ProcessId": Field(),
        "ProcessGuid": Field(),
        "User": Field(),
        "ProcessName": Field(),
        "LogonGuid": Field(),
        "Computer" : Field() # For shardening
    }

class NetworkObject(Collection):
    _fields = {
        "_name" : Field(),
        "Ip": Field(),
        "Computer" : Field() # For shardening
    }

class RegistryObject(Collection):
    _fields = {
        "_name" : Field(),
        "Path": Field(),
        "Computer" : Field() # For shardening
    }

class CreateNewProcess(Edges):
    _fields = {
        "_name" : Field(),
        "UtcTime": Field(),
        "EventRecordID": Field(),
        "CurrentDirectory": Field(),
        "User": Field(),
        "CommandLine": Field(),
        "Hashes": Field(),
        "Computer" : Field() # For shardening
    }


class NetworkConnection(Edges):
    _fields = {
        "_name" : Field(),
        "UtcTime": Field(),
        "EventRecordID": Field(),
        "User": Field(),
        "DestinationPort": Field(),
        "DestinationIp": Field(),
        "SourceIp": Field(),
        "SourcePort" : Field(),
        "Protocol" : Field(),
        "Computer" : Field() # For shardening
    }

class NetworkConnection(Edges):
    _fields = {
        "_name" : Field(),
        "UtcTime": Field(),
        "EventRecordID": Field(),
        "User": Field(),
        "DestinationPort": Field(),
        "DestinationIp": Field(),
        "SourceIp": Field(),
        "SourcePort" : Field(),
        "Protocol" : Field(),
        "Computer" : Field() # For shardening
    }

class RegistryEvent(Edges):
    _fields = {
        "_name" : Field(),
        "UtcTime": Field(),
        "EventRecordID": Field(),
        "User": Field(),
        "EventType": Field(),
        "Computer" : Field() # For shardening
    }

class ProcessAccessed(Edges):
    _fields = {
        "_name" : Field(),
        "UtcTime": Field(),
        "EventRecordID": Field(),
        "User": Field(),
        "CallTrace": Field(),
        "TargetImage" : Field(),
        "Computer" : Field() # For shardening
    }

class SysmonGraph(Graph):
    _edgeDefinitions = [EdgeDefinition("CreateNewProcess", fromCollections=[
                                       "SysmonProcess"], toCollections=["SysmonProcess"]),
                        EdgeDefinition("NetworkConnection", fromCollections=[
                                       "SysmonProcess"], toCollections=["NetworkObject"]),
                        EdgeDefinition("RegistryEvent", fromCollections=[
                                       "SysmonProcess"], toCollections=["RegistryObject"]),
                        EdgeDefinition("ProcessAccessed", fromCollections=[
                                       "SysmonProcess"], toCollections=["SysmonProcess"])]
    _orphanedCollections = []


def customSysmonGraph(name):
    return type(name, (Graph, ), {
        "_edgeDefinitions" : [EdgeDefinition("CreateNewProcess", fromCollections=[
                                       "SysmonProcess"], toCollections=["SysmonProcess"]),
                        EdgeDefinition("NetworkConnection", fromCollections=[
                                       "SysmonProcess"], toCollections=["NetworkObject"]),
                        EdgeDefinition("RegistryEvent", fromCollections=[
                                       "SysmonProcess"], toCollections=["RegistryObject"]),
                        EdgeDefinition("ProcessAccessed", fromCollections=[
                                       "SysmonProcess"], toCollections=["SysmonProcess"])],
        "_orphanedCollections" : []
    })