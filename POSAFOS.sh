sleep 05

cp -Rf /opt/AFOS/afos/src/afos /opt/ANDRAX/bin/afos

if [ $? -eq 0 ]
then
  # Result is OK! Just continue...
  echo "Copy package... PASS!"
else
  # houston we have a problem
  exit 1
fi