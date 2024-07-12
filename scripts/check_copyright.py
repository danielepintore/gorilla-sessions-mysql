"""
// Copyright 2024 Daniele Pintore. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
"""
import os
from datetime import datetime

# Define the expected license header
EXPECTED_HEADER = """// Copyright [YEAR] [YOUR NAME]. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
"""


def check_license_header(file_path, expected_header):
    with open(file_path, 'r') as file:
        content = file.read()
        if expected_header in content:
            return True
    return False


def check_files_in_directory(directory, expected_header):
    missing_header_files = []
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith('.go') or file.endswith('.py'):
                file_path = os.path.join(root, file)
                if not check_license_header(file_path, expected_header):
                    missing_header_files.append(file_path)
    return missing_header_files


if __name__ == "__main__":
    project_directory = "."  # Change this to your project directory
    current_year = str(datetime.now().year)
    expected_header = EXPECTED_HEADER.replace("[YEAR]", current_year).replace("[YOUR NAME]", "Daniele Pintore")
    
    missing_header_files = check_files_in_directory(project_directory, expected_header)
    
    if missing_header_files:
        print("The following files are missing the license header:")
        for file in missing_header_files:
            print(file)
    else:
        print("All files have the correct license header.")
