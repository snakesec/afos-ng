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
    def __init__(self, name, version, description, categories, repo, min_andrax=2001, orig_repo=None):
        self.name = name
        self.version = version
        self.description = description
        self.categories = [categories] if isinstance(categories, str) else categories
        self.repo_url = f"github.com/{repo}"
        self.original_repo_url = f"{orig_repo}" if orig_repo else f"github.com/{repo}"
        self.min_andrax = min_andrax

    def to_dict(self):
        return self.__dict__

# "pkg_name", "pkg_version", "pkg_description", ["categories"], "afos_git_repo", orig_repo="official_tool_repo", min_andrax=2001)
tools_list = [
    
    Tool("andrax-base-files", "0.0.9", "ANDRAX-NG base files", ["System"], "snakesec/andrax-base-files", orig_repo="github.com/snakesec/andrax-base-files", min_andrax=2001),
    Tool("afos", "1.0.7", "ANDRAX-NG Package Manager", ["System"], "snakesec/afos-ng", orig_repo="github.com/snakesec/afos-ng", min_andrax=2001),
    Tool("rust-lang", "1.98.1", "Rust Programming Language", ["System"], "snakesec/rust-lang", orig_repo="www.rust-lang.org", min_andrax=2001),
    Tool("geckodriver", "0.37.1", "WebDriver for Firefox", ["System"], "snakesec/geckodriver", orig_repo="github.com/mozilla/geckodriver", min_andrax=2001),
    Tool("golang", "1.27.1", "Go Programming Language", ["System"], "snakesec/golang", orig_repo="go.dev/dl/", min_andrax=2001),
    Tool("pipx", "1.8.0", "PIPX for ANDRAX-NG", ["System"], "snakesec/pipx", orig_repo="github.com/pypa/pipx", min_andrax=2001),
    Tool("micro", "2.0.15-301", "Modern and intuitive terminal-based text editor", ["System"], "snakesec/micro", orig_repo="github.com/zyedidia/micro", min_andrax=2001),
    
]

final_data = [tool.to_dict() for tool in tools_list]

with open("../repository/afos.yaml", "w", encoding="utf-8") as f:
    yaml.dump(final_data, f, default_flow_style=False, sort_keys=False)

print("New afos.yaml generated!")
