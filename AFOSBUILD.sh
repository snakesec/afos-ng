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

cp -Rf afos /opt/ANDRAX/bin/afos

if [ $? -eq 0 ]
then
  # Result is OK! Just continue...
  echo "Copy package... PASS!"
else
  # houston we have a problem
  exit 1
fi
