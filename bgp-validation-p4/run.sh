echo "Compiling..."
p4c -Xp4c="--emit-externs" --target bmv2 --arch v1model --std p4-16 -o p4src p4src/monitor.p4
if [ "$?" -ne "0" ]; then 
    echo "There are compilation errors in p4c - please resolve before continuing."
    exit 1
fi
p4c -Xp4c="--emit-externs" --target bmv2 --arch v1model --std p4-16 -o p4src p4src/sentinel.p4
if [ "$?" -ne "0" ]; then 
    echo "There are compilation errors in p4c - please resolve before continuing."
    exit 1
fi
echo "OK!"
python bgp-multiple-controllers.py
