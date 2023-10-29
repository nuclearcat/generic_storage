#!/bin/bash
go build generic_storage.go

# Test 1
# Launch generic_storage, save temporary pid, fork
TMPCFG=$(mktemp)
TMPDIR=$(mktemp -d)
TMPOUTFILE=$(mktemp)
TMPUPFILE=$(mktemp)

function cleanup {
    kill $pid
    rm -f $TMPCFG
    rm -f $TMPOUTFILE
    rm -f $TMPUPFILE
    rm -f $TMPUPFILE.md5
    rm -rf $TMPDIR

}

YAML="users:
  - username: \"user1\"
    token: \"password1\"
filedir: \"$TMPDIR\""


function start_server {
    echo "$YAML" > $TMPCFG
    ./generic_storage -port="8081" -cfg=$TMPCFG &
    pid=$!
    sleep 1
}

# output YAML config to temporary file
#users:
#  - username: "user1"
#    token: "password1"
#filedir: "/tmp/tmpdir"

start_server

# test by curl
curl -X POST -d '{"username":"user1","password":"password1"}' http://localhost:8081/login > $TMPOUTFILE
# Expected to see Unauthorized
grep "Unauthorized" $TMPOUTFILE
if [ $? -ne 0 ]; then
    echo "Test 1 failed"
    cleanup
    exit 1
else
    echo "Test 1 passed"
    cleanup
fi

# Test 2
# curl -X POST -H "Authorization: Bearer password1" -F file0=@1/test.zip http://host:port/upload
# Verify file upload in designated directory and file integrity

start_server

dd if=/dev/urandom bs=1M count=1 of=$TMPUPFILE
md5sum $TMPUPFILE | awk '{print $1}' > $TMPUPFILE.md5

# upload file
curl -X POST -H "Authorization: Bearer password1" -F file0=@$TMPUPFILE http://localhost:8081/upload > $TMPOUTFILE
# Expected to see {"status": "ok"}
grep "{\"status\": \"ok\"}" $TMPOUTFILE
if [ $? -ne 0 ]; then
    echo "Test 2 failed (upload response)"
    cleanup
    exit 1
fi
ls -la $TMPDIR/user1

# basename of TMPUPFILE
TMPUPFILEBASE=$(basename $TMPUPFILE)

# verify uploaded file in the directory
md5sum $TMPDIR/user1/$TMPUPFILEBASE | awk '{print $1}' | diff $TMPUPFILE.md5 -
if [ $? -ne 0 ]; then
    echo "Test 2 failed (md5sum)"
    cleanup
    exit 1
else
    echo "Test 2 passed (md5sum)"
    cleanup
fi

# TODO
# Verify if path is specified
# Verify overwrite parameter respected