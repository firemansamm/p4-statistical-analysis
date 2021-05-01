command -v thrift || { echo >&2 "thrift was not found in PATH. script cannot continue."; exit 1; }
command -v simple_switch || { echo >&2 "simple_switch was not found in PATH. script cannot continue."; exit 1; }

VERSION="$(simple_switch --version)"
OIFS=$IFS
IFS='.'
read -r -a verarr <<< "$VERSION"
IFS=$OIFS
verarr[-1]="x"

# get the corresponding branch to the version of simple_switch installed
BRANCH=${verarr[0]}
for x in ${verarr[@]:1}
do
    BRANCH="$BRANCH.$x"
done

echo "cloning bmv2..."
git clone git@github.com:p4lang/behavioral-model.git || { echo >&2 "an error ocurred when checking out the bmv2 repository."; exit 1; }

cd behavioral-model

echo "getting branch $BRANCH."
git checkout $BRANCH

echo "generating standard..."
thrift -o .. --gen py -r ./thrift_src/standard.thrift
thrift -o .. --gen py -r ./thrift_src/simple_pre.thrift
thrift -o .. --gen py -r ./thrift_src/simple_pre_lag.thrift

echo "generating simple_switch..."
thrift -o .. --gen py -r ./targets/simple_switch/thrift/simple_switch.thrift

cd ..

echo "cleaning up and moving stuff around..."
rm -rf behavioral-model
rm -rf sswitch_runtime
rm -rf bm_runtime

rm gen-py/__init__.py
mv gen-py/* ./
rm -rf gen-py

echo "done!"


