###############################################################################
#                                                                             #
# Copyright 2026 Weidsom Nascimento - SNAKE Security                          #
#                                                                             #
# Licensed under the Apache License, Version 2.0 (the "License");             #
# you may not use this file except in compliance with the License.            #
# You may obtain a copy of the License at                                     #
#                                                                             #
#     http://www.apache.org/licenses/LICENSE-2.0                              #
#                                                                             #
# Unless required by applicable law or agreed to in writing, software         #
# distributed under the License is distributed on an "AS IS" BASIS,           #
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.    #
# See the License for the specific language governing permissions and         #
# limitations under the License.                                              #
#                                                                             #
###############################################################################

import os
import sys
import argparse
import yaml
import json
import shutil

GENERAL_ICON_DIR = "/opt/DCO/ICONS/"

def main():
    parser = argparse.ArgumentParser(
        description="Parse AFOS-NG's tool YAML file to generate DCO entry."
    )
    parser.add_argument(
        "target", help="The directory containing the YAML and icon files"
    )
    args = parser.parse_args()

    target_dir = args.target

    if not os.path.isdir(target_dir):
        print(f"Error: The directory '{target_dir}' does not exist!")
        sys.exit(1)

    yaml_files = [
        f
        for f in os.listdir(target_dir)
        if f.endswith((".yaml", ".yml")) and os.path.isfile(os.path.join(target_dir, f))
    ]

    if not yaml_files:
        print(f"Error: No AFOS-NG YAML file found in '{target_dir}'.")
        sys.exit(1)
    elif len(yaml_files) > 1:
        print(f"Error: Found multiple YAML files in '{target_dir}'. Expected only one!")
        sys.exit(1)

    yaml_path = os.path.join(target_dir, yaml_files[0])

    try:
        with open(yaml_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except Exception as e:
        print(f"Error reading AFOS-NG YAML file: {e}")
        sys.exit(1)

    tool_name = data.get("name")
    categories = data.get("categories", [])
    icon_filename = data.get("icon")

    if not tool_name:
        print("Error: 'name' field is missing in the YAML file.")
        sys.exit(1)

    if icon_filename:
        icon_source_path = os.path.join(target_dir, icon_filename)
        if os.path.exists(icon_source_path):
            os.makedirs(GENERAL_ICON_DIR, exist_ok=True)
            icon_dest_path = os.path.join(GENERAL_ICON_DIR, icon_filename)
            shutil.copy2(icon_source_path, icon_dest_path)
            print(f"{tool_name} icon copied to: {icon_dest_path}")
        else:
            print(f"Error: Icon file '{icon_filename}' specified in YAML was not found in '{target_dir}'.")
            sys.exit(1)
    else:
        print("Error: No 'icon' field specified in the YAML.")
        sys.exit(1)

    data.pop("categories", None)

    if not categories:
        print("Error: No categories found in the YAML array.")
        sys.exit(1)

    json_filename = f"{tool_name}.json"
    
    for category in categories:
        os.makedirs("/opt/DCO/CATEGORIES/" + category, exist_ok=True)
        json_dest_path = os.path.join("/opt/DCO/CATEGORIES/" + category, json_filename)
        
        with open(json_dest_path, "w", encoding="utf-8") as json_file:
            json.dump(data, json_file, indent=4, ensure_ascii=False)
            
        print(f"JSON DCO entry created for category '{category}': {json_dest_path}")

    print("\nAll DCO entries have been satisfied!")

if __name__ == "__main__":
    main()