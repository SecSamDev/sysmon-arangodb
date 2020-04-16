import re
retype = type(re.compile('a'))

class SysmonExcepcioner():
    def __init__(self):
        self.rules = [
            {
                "name" : "OfficeClickToRun",
                "conditions" : {
                    "EventID" : 12,
                    "Image" : re.compile('^C:\\\\Program Files\\\\Common Files\\\\Microsoft Shared\\\\ClickToRun\\\\Updates\\\\(?:[0-9\\.]+)\\\\OfficeClickToRun.exe$')
                }
            }
        ]

    def is_false_positive(self, log_event):
        for rule in self.rules:
            if matches_rule(rule,log_event):
                return True
        return False

def matches_rule(rule,log_event):
    conditions = rule["conditions"]
    for attr in conditions:
        try:
            if attr in log_event:
                if isinstance(conditions[attr],retype):
                    if not re.match(conditions[attr],log_event[attr]):
                        return False
                else:
                    if log_event[attr] != conditions[attr]:
                        return False
        except:
            print("Error in rule: " + rule["name"])
            print(attr + " " + log_event[attr])
    print("Matches rule: " + rule["name"])
    return True