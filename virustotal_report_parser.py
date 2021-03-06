import json, os

class Parser :
    def __init__(self, path) :
        self.path = path
        with open(path, 'r') as f :
            self.json_obj = json.loads(f.read())
    def md5(self) :
        try :
            return self.json_obj['md5']
        except :
            return 'no-result'
    def sha256(self):
        try :
            return self.json_obj['sha256']
        except :
            return 'no-result'
    def sha1(self):
        try:
            return self.json_obj['sha1']
        except :
            return 'no-result'
    def result(self, antivirus_name):
        try :
            return self.json_obj['scans'][antivirus_name]['result']
        except :
            return 'no-result'
    def positives(self):
        try :
            return self.json_obj['positives']
        except :
            return 'no-result'
    def total(self):
        try :
            return self.json_obj['total']
        except :
            return 'no-result'
    def scan_date(self):
        try :
            return self.json_obj['scan_date']
        except :
            return 'no-result'
    def positive_engine_list(self) :
        try :
            ret_list = []
            for engine, result in self.json_obj['scans'].items() :
                if result['detected'] :
                    ret_list.append(engine)
            return ret_list
        except :
            return []
    def negative_engine_list(self) :
        try :
            ret_list = []
            for engine, result in self.json_obj['scans'].items() :
                if not result['detected'] :
                    ret_list.append(engine)
            return ret_list
        except :
            return []

if __name__ == '__main__' :
    json_paths = []
    for path, dirs, files in os.walk('json') :
        for file in files :
            ext = os.path.splitext(file)[-1]
            if ext == '.json' :
                json_paths.append(os.path.join(path, file))
    for json_path in json_paths :
        parser = Parser(json_path)
        print("-------------------------------------------------------------------------")
        print("MD5 : {md5}".format(md5 = parser.md5()))
        print("SHA1 : {sha1}".format(sha1 = parser.sha1()))
        print("SHA256 : {sha256}".format(sha256 = parser.sha256()))
        print("SCAN DATE : {scan_date}".format(scan_date = parser.scan_date()))
        print("TOTAL : {total}".format(total=parser.total()))
        print("POSITIVES : {positives}".format(positives = parser.positives()))
        print("AhnLab-V3 : {result}".format(result = parser.result('AhnLab-V3')))
        print("POSITIVE ENGINE LIST : {positive_engine_list}".format(positive_engine_list = parser.positive_engine_list()))
        print("NEGATIVE ENGINE LIST : {negative_engine_list}".format(negative_engine_list = parser.negative_engine_list()))
        print("-------------------------------------------------------------------------")
