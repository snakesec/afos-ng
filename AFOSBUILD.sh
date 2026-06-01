cd src

make

if [ $? -eq 0 ]
then
  # Result is OK! Just continue...
  echo "Make AFOS-NG... PASS!"
else
  # houston we have a problem
  exit 1
fi

cp -Rf ../UTILS/afos_shell_functions.sh /opt/AFOS/

if [ $? -eq 0 ]
then
  # Result is OK! Just continue...
  echo "Copy afos_shell_functions... PASS!"
else
  # houston we have a problem
  exit 1
fi

chown -R root:root /opt/AFOS/afos_shell_functions.sh

if [ $? -eq 0 ]
then
  # Result is OK! Just continue...
  echo "Set afos_shell_functions owner... PASS!"
else
  # houston we have a problem
  exit 1
fi

chmod 755 /opt/AFOS/afos_shell_functions.sh

if [ $? -eq 0 ]
then
  # Result is OK! Just continue...
  echo "Set afos_shell_functions permissions... PASS!"
else
  # houston we have a problem
  exit 1
fi