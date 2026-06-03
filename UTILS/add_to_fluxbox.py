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

import sys
import os
import re

def natural_sort_key(s):
    return [int(text) if text.isdigit() else text.lower() for text in re.split(r'(\d+)', s)]

def add_tool_to_menu(menu_path, category, tool_name, command):
    if not os.path.exists(menu_path):
        print(f"Error: File '{menu_path}' not found.")
        sys.exit(1)

    with open(menu_path, 'r') as f:
        lines = f.readlines()

    cleaned_lines = [line.strip() for line in lines]

    target_app_menu = "[submenu] (CyberSecurity Tools) {}"
    category_submenu = f"[submenu] ({category}) {{}}"
    
    if target_app_menu not in cleaned_lines:
        print("Error: Could not find '[submenu] (CyberSecurity Tools) {}' in the menu file.")
        sys.exit(1)

    category_exists = False
    category_idx = -1
    for idx, line in enumerate(cleaned_lines):
        if line == category_submenu:
            category_exists = True
            category_idx = idx
            break

    new_tool_line = f"            [exec] ({tool_name}) {{ {command} }} <>\n"
    target_tool_strip = new_tool_line.strip()

    if category_exists:
        category_tools = []
        end_idx = -1
        
        for i in range(category_idx + 1, len(cleaned_lines)):
            current_line = cleaned_lines[i]
            
            if current_line == "[end]":
                end_idx = i
                break
                
            if current_line == target_tool_strip:
                print(f"Tool '{tool_name}' already exists in category '{category}'. Skipping.")
                return
                
            if current_line.startswith("[exec]"):
                category_tools.append(lines[i])

        category_tools.append(new_tool_line)

        def get_tool_name(line):
            match = re.search(r'\[exec\]\s*\((.*?)\)', line)
            return match.group(1) if match else line

        category_tools.sort(key=lambda x: natural_sort_key(get_tool_name(x)))

        del lines[category_idx + 1:end_idx]
        
        for offset, sorted_tool in enumerate(category_tools):
            lines.insert(category_idx + 1 + offset, sorted_tool)
            
        print(f"Added and sorted '{tool_name}' into category '{category}'.")
        
    else:
        app_idx = cleaned_lines.index(target_app_menu)
        
        new_category_block = [
            f"      [submenu] ({category}) {{}}\n",
            new_tool_line,
            "      [end]\n"
        ]
        
        for offset, block_line in enumerate(new_category_block):
            lines.insert(app_idx + 1 + offset, block_line)
        print(f"Created new category '{category}' and added tool '{tool_name}'.")

    with open(menu_path, 'w') as f:
        f.writelines(lines)

def main():
    if len(sys.argv) < 5:
        print("Usage: python3 add_to_fluxbox.py <menu_file_path> <category> <tool_name> <command>")
        print("Example: python3 add_to_fluxbox.py ~/.fluxbox/menu Scanning Nmap 'nmap --help'")
        sys.exit(1)

    menu_path = sys.argv[1]
    category = sys.argv[2]
    tool_name = sys.argv[3]
    command = sys.argv[4]

    add_tool_to_menu(menu_path, category, tool_name, command)

if __name__ == '__main__':
    main()