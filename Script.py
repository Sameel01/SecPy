import os
import hashlib
import ssdeep
import subprocess
import magic
import math

class StringDump:
    def __init__(self, file_path, output_folder):
        self.file_path = file_path
        self.output_folder = output_folder
        self.output_file = os.path.join(self.output_folder, 'stringDump.txt')

    def dump_strings(self):
        # Use the strings utility to extract printable character sequences
        result = subprocess.run(["strings", self.file_path], capture_output=True, text=True)
        
        # Write the extracted strings to the output file
        with open(self.output_file, 'w') as f:
            f.write(result.stdout)

        print(f"Strings dumped to: {self.output_file}")

class SearchPattern:
    def __init__(self, input_file, pattern_file):
        self.input_file = input_file
        self.pattern_file = pattern_file

    def search_patterns(self):
        # Read the patterns from the pattern_file
        with open(self.pattern_file, 'r', errors='ignore') as f:
            patterns = [pattern.strip() for pattern in f.readlines()]

        # Search for any of the patterns within the input_file
        with open(self.input_file, 'r', errors='ignore') as f:
            content = f.read()
            if any(pattern in content for pattern in patterns):
                print("Pattern found in the suspicious file.")
            else:
                print("No patterns found in the file.")


class FileSignature:
    def __init__(self, file_path):
        self.file_path = file_path

    def check_signature(self):
        with open(self.file_path, 'rb') as f:
            signature = f.read(4)
            mime_type = magic.Magic()
            file_type = mime_type.from_file(self.file_path)

            print(f"\nFile Type: {file_type}")

            # Add more file signatures as needed
            if signature == b'\x4D\x5A':
                print("Signature matches: This is a DOS executable (MZ)")
            elif signature == b'\x7F\x45\x4C\x46':
                print("Signature matches: This is an ELF executable")
            elif signature == b'\x4D\x5A\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xFF\xFF':
                print("Signature matches: This is a known ransomware file")
            elif signature == b'\x4D\x5A\xE8\x0D':
                print("Signature matches: This is a known trojan file")
            # Add more signatures based on the file types you want to check

def calculate_md5(file_path):
    hash_md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

def calculate_sha256(file_path):
    hash_sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_sha256.update(chunk)
    return hash_sha256.hexdigest()

def calculate_ssdeep(file_path):
    with open(file_path, 'rb') as f:
        content = f.read()
    return ssdeep.hash(content)

def calculate_entropy(file_path):
    with open(file_path, 'rb') as f:
        data = f.read()

    # Calculate the Shannon entropy
    entropy = 0
    if data:
        for x in range(256):
            p_x = float(data.count(x)) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)
    return entropy

def generate_yara_rule(rule_name, file_path, pattern_file, fuzzy_threshold=80, entropy_threshold=6.0):
    md5_hash = calculate_md5(file_path)
    sha256_hash = calculate_sha256(file_path)
    ssdeep_hash = calculate_ssdeep(file_path)
    entropy = calculate_entropy(file_path)

    # Convert entropy and threshold to integers
    entropy_int = int(entropy)
    entropy_threshold_int = int(entropy_threshold)

    # Dump strings to a file
    string_dumper = StringDump(file_path, os.path.dirname(file_path))
    string_dumper.dump_strings()

    # Search for patterns within the extracted strings
    pattern_searcher = SearchPattern(string_dumper.output_file, pattern_file)
    pattern_searcher.search_patterns()

    # Check file signature
    file_signature = FileSignature(file_path)
    file_signature.check_signature()

    # Read the patterns from the pattern_file
    with open(pattern_file, 'r', errors='ignore') as f:
        patterns = [pattern.strip() for pattern in f.readlines()]

    # Format the YARA rule with correct string syntax
    yara_rule = (
        f"rule {rule_name}\n"
        f"{{\n"
        f"    meta:\n"
        f"        pattern_file = \"{pattern_file}\"\n"
        f"    strings:\n"
        f"        $md5 = \"{md5_hash}\"\n"
        f"        $sha256 = \"{sha256_hash}\"\n"
        f"        $ssdeep = \"{ssdeep_hash}\"\n"
    )

    for index, pattern in enumerate(patterns, start=1):
        yara_rule += f'        $string{index} = "{pattern}"\n'

    yara_rule += f"""
    condition:
         any of them 
    }}
"""

    print("\nGenerated YARA rule:\n")
    print(yara_rule)
    print(f"Entropy: {entropy}% (Threshold: {entropy_threshold}%)")

    return yara_rule



def save_yara_rule(rule_name, rule_content, output_directory="."):
    output_file = os.path.join(output_directory, f"{rule_name}.yar")
    with open(output_file, "w") as f:
        f.write(rule_content)
    print(f"YARA rule saved to: {output_file}")
    return output_file




def scan_file_with_yara(yara_rule_file, scan_file):
    print(f"Scanning file '{scan_file}' with YARA rule '{yara_rule_file}'...\n")
    result = subprocess.run(["yara", "-r", yara_rule_file, scan_file], capture_output=True, text=True)

    if result.returncode == 0:
        print("*****  YARA rule matched  ***** \n")
        print(result.stdout)
    else:
        print("No YARA rule matches found.")

def print_banner():
    print(r"""
 ███████╗███████╗ ██████╗██████╗ ██╗   ██╗
 ██╔════╝██╔════╝██╔════╝██╔══██╗╚██╗ ██╔╝
 ███████╗█████╗  ██║     ██████╔╝ ╚████╔╝ 
 ╚════██║██╔══╝  ██║     ██╔═══╝   ╚██╔╝  
 ███████║███████╗╚██████╗██║        ██║   
 ╚══════╝╚══════╝ ╚═════╝╚═╝        ╚═╝   
                    AutoYar
    """)

def main():
    print_banner()
    print("Automated YARA Rule Generator\n")
    malware_file = "/home/kali/Desktop/Forensics/ransomware.exe"
    rule_name = "MalwareRule"
    pattern_file = "pattern.txt"

    # Generate YARA rule with MD5, SHA256, ssdeep, and pattern string
    yara_rule = generate_yara_rule(rule_name, malware_file, pattern_file)

    # Specify the output directory where the YARA rule will be saved
    output_directory = "/home/kali/Desktop/Forensics"

    # Save the YARA rule to a file
    output_file = save_yara_rule(rule_name, yara_rule, output_directory)

    # Use YARA to scan a file for matches
    scan_file_with_yara(output_file, malware_file)

if __name__ == "__main__":
    main()
