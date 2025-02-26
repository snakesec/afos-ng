
###############################################################################
#                                                                             #
# Copyright 2025 Weidsom Nascimento - SNAKE Security                          #
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


.PHONY: afos-ng

afos-ng:
	clang -g -fsanitize=address -o afos afos.c semver.c lower.c sql.c help.c update.c curl.c get_pkgs.c repo_list.c install.c not_installed.c -I. -lcurl -lsqlite3 -lyaml
	clang -o insert insert.c -lsqlite3

clean:
	echo "Cleaning AFOS-ng"
	rm afos-ng
	rm insert
