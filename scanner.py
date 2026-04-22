import yara
import os

class YaraScanner:
    def __init__(self, rules_dir="rules"):
        self.rules_dir = rules_dir
        self.rules = self._load_rules()

    def _load_rules(self):
        rule_files = {}
        for root, _, files in os.walk(self.rules_dir):
            for file in files:
                if file.endswith(".yar") or file.endswith(".yara"):
                    rel_path = os.path.relpath(os.path.join(root, file), self.rules_dir)
                    rule_files[rel_path] = os.path.join(root, file)
        
        if not rule_files:
            return None
        
        try:
            return yara.compile(filepaths=rule_files)
        except yara.Error as e:
            print(f"Error compiling YARA rules: {e}")
            return None

    def scan_file(self, file_path):
        if not self.rules:
            self.rules = self._load_rules()
            if not self.rules:
                return []
        
        matches = self.rules.match(file_path)
        results = []
        for match in matches:
            for string_match in match.strings:
                for instance in string_match.instances:
                    results.append({
                        "rule": match.rule,
                        "offset": instance.offset,
                        "identifier": string_match.identifier,
                        "length": len(instance.matched_data),
                        "data": instance.matched_data
                    })
        return results

if __name__ == "__main__":
    scanner = YaraScanner("rules")
    with open("test_bin.txt", "w") as f:
        f.write("Some prefix code test_detection some suffix code")
    
    hits = scanner.scan_file("test_bin.txt")
    print(f"Found {len(hits)} matches:")
    for hit in hits:
        print(hit)
    
    if os.path.exists("test_bin.txt"):
        os.remove("test_bin.txt")
