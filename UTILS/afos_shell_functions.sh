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


########################################
#                                      #
# Some functions to help AFOS packages #
#     in the ANDRAX-NG environment     #
#                                      #
########################################

AFOS_DB="/opt/ANDRAX/opt/AFOS/pkg.db"

#########################################################
#                                                       #
# A very simple function to check whether a package has #
# already been installed.                               #
#                                                       #
# Should be used by the AFOS package to check if a      #
# dependency has been satisfied.                        #
#                                                       #
#########################################################
check_package_installed() {

    # In theory, this command should be "safe"
    RESULT=$(sqlite3 "$AFOS_DB" <<EOF
.parameter set :pkg_name "$1"
SELECT 1 FROM PACKAGES WHERE NAME = :pkg_name LIMIT 1;
EOF
)

    if [ -n "$RESULT" ]; then
        return 1
    fi

    return 0

}