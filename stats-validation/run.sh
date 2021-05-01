echo "Compiling..."
p4c --target bmv2 --arch v1model --std p4-16 -o p4src p4src/bench.p4
if [ "$?" -ne "0" ]; then 
    echo "There are compilation errors in p4c - please resolve before continuing."
    exit 1
fi
echo "OK!"
python topology.py
