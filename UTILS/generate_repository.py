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

import yaml

class Tool:
    def __init__(self, name, version, description, categories, repo, min_andrax=1003, orig_repo=None):
        self.name = name
        self.version = version
        self.description = description
        self.categories = [categories] if isinstance(categories, str) else categories
        self.repo_url = f"github.com/{repo}"
        self.original_repo_url = f"github.com/{orig_repo}" if orig_repo else f"github.com/{repo}"
        self.min_andrax = min_andrax

    def to_dict(self):
        return self.__dict__

# "pkg_name", "pkg_version", "pkg_description", ["categories"], "afos_git_repo", orig_repo="official_tool_repo", min_andrax=2001)
tools_list = [
    
    Tool("andrax-base-files", "0.0.9", "ANDRAX-NG base files", "System", "snakesec/andrax-base-files"),
    
]

final_data = [tool.to_dict() for tool in tools_list]

with open("afos.yaml", "w", encoding="utf-8") as f:
    yaml.dump(final_data, f, default_flow_style=False, sort_keys=False)

print("New afos.yaml generated!")