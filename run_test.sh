#!/bin/bash
set -x
./icmptunnel server --config test/server.toml --log-level debug > server.log 2>&1 &
SERVER_PID=$!
python3 -m http.server 8000 > fileserver.log 2>&1 &
FILE_PID=$!
sleep 3
./icmptunnel client --config test/forward_test.toml --log-level debug > client.log 2>&1 &
CLIENT_PID=$!
sleep 5
curl -v http://127.0.0.1:8001/test_10mb.bin -o download_10mb.bin --max-time 60
CURLE_RES=$?
echo "Curl returned $CURLE_RES"
kill $CLIENT_PID $FILE_PID $SERVER_PID
