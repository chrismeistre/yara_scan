import yara
import os
import sys
import argparse

def get_yara_rule_files(directory, recursive):
    rule_files = []
    if recursive:
        for root, dirs, files in os.walk(directory):
            for file in files:
                if file.endswith(".yar"):
                    rule_files.append(os.path.join(root, file))
    else:
        for file in os.listdir(directory):
            if file.endswith(".yar"):
                rule_files.append(os.path.join(directory, file))
    return rule_files

def compile_yara_rules(yara_files):
    try:
        rules = yara.compile(filepaths={str(i): file for i, file in enumerate(yara_files)})
        print(f"[DEBUG] Successfully compiled YARA rules")
        return rules
    except yara.Error as e:
        print(f"Error compiling YARA rules: {e}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description='Scan a file with YARA rules.')
    parser.add_argument('target_file', help='Path to the target executable file')
    parser.add_argument('-y', '--yarafile', help='Path to a single YARA rule file')
    parser.add_argument('-d', '--directory', help='Path to a directory of YARA rule files')
    parser.add_argument('-r', '--recursive', action='store_true', help='Recursively search for YARA files in the specified directory')

    args = parser.parse_args()

    if not args.yarafile and not args.directory:
        print("Error: You must specify either a YARA file (-y) or a directory (-d).")
        parser.print_help()
        sys.exit(1)

    yara_rule_files = []

    if args.yarafile:
        yara_rule_files.append(args.yarafile)
        print(f"[DEBUG] Using single YARA file: {args.yarafile}")

    if args.directory:
        yara_rule_files.extend(get_yara_rule_files(args.directory, args.recursive))
        print(f"[DEBUG] Found {len(yara_rule_files)} YARA rule files in directory: {args.directory}")

    if not yara_rule_files:
        print(f"No YARA rule files found.")
        sys.exit(1)

    rules = compile_yara_rules(yara_rule_files)

    target_file = args.target_file
    print(f"[DEBUG] Target file set to: {target_file}")

    try:
        with open(target_file, "rb") as f:
            file_data = f.read()
        print(f"[DEBUG] Successfully read the target file")
    except FileNotFoundError:
        print(f"Error: File '{target_file}' not found.")
        sys.exit(1)
    except IOError as e:
        print(f"Error: Unable to read file '{target_file}'. {e}")
        sys.exit(1)

    try:
        matches = rules.match(data=file_data)
        print(f"[DEBUG] Successfully scanned the file with YARA rules")
    except yara.Error as e:
        print(f"Error scanning the file with YARA rules: {e}")
        sys.exit(1)

    if matches:
        print(f"[DEBUG] Matches found: {len(matches)}")
        for match in matches:
            print(f"Rule: {match.rule}")
            print(f"Tags: {match.tags}")
            print(f"Meta: {match.meta}")
            print(f"Strings: {match.strings}")
            print("="*50)
    else:
        print("[DEBUG] No matches found")

if __name__ == "__main__":
    main()
