#!/bin/zsh
# r2 driver, 2026-11-18. Starts each server config, runs rp2.py, stops it.
# Records each command and its direct exit code in logs/driver.log.
cd ~/scanwork-1118/lab/r2 || exit 2
mkdir -p out logs
L=logs/driver.log
OFGA=../ofga/openfga; SDB=../sdb/spicedb; PMF=../pmf/permify
PGB=~/scanwork-1117/lab/pg/bin17/bin
PG1="postgres://postgres@127.0.0.1:55432/postgres?sslmode=disable"
PG2="postgres://postgres@127.0.0.1:55433/postgres?sslmode=disable"
TOL=0.5
log() { echo "$(date -u +%FT%TZ) $*" >> $L; }
waitport() { for i in {1..40}; do nc -z 127.0.0.1 $1 2>/dev/null && return 0; sleep 0.5; done; return 1; }
run() { log "RUN $*"; python3 -I rp2.py "$@" > logs/run-$2.txt 2>&1; log "EXIT $? $2"; }
srv() { log "SERVER $*"; (nohup "$@" > logs/server-$LBL.log 2>&1 &); }
stop() { pkill -f "$1"; sleep 1.5; pgrep -fl "$1" >> $L && log "STILL RUNNING $1"; }

log "selftest"; python3 -I selftest.py rp2.py > logs/selftest.txt 2>&1; log "EXIT $? selftest"

COMMON=(run --datastore-engine memory --playground-enabled=false --metrics-enabled=false)
CACHE=(--check-query-cache-enabled --check-iterator-cache-enabled --list-objects-iterator-cache-enabled)
LBL=r2-c0; srv $OFGA $COMMON; waitport 8080
run openfga r2-c0-nocache --bound 0 --tolerance $TOL --bound-class documented --bound-source "openfga-consistency.mdx: caching disabled means strong consistency" --server-pattern "ofga/openfga run"
stop "ofga/openfga run"
LBL=r2-c1; srv $OFGA $COMMON $CACHE; waitport 8080
run openfga r2-c1-cache-ttl10 --bound 10 --tolerance $TOL --bound-class configured-setting --bound-source "run --help: check-query-cache values cleared after the configured TTL (10s default); iterator caches TTL 10s" --server-pattern "ofga/openfga run"
log "RUN cx"; python3 -I rp_cond2.py r2-c1-cache > logs/run-cx.txt 2>&1; log "EXIT $? cx"
stop "ofga/openfga run"
LBL=r2-c2; srv $OFGA $COMMON $CACHE --check-query-cache-ttl 60s --check-iterator-cache-ttl 60s --list-objects-iterator-cache-ttl 60s --cache-controller-enabled --cache-controller-ttl 10s; waitport 8080
run openfga r2-c2-ttl60-controller10 --bound 60 --tolerance $TOL --bound-class configured-setting --bound-source "cache TTL 60s; cache-controller-ttl 10s is a minimum invalidation-trigger interval, observed only" --server-pattern "ofga/openfga run"
stop "ofga/openfga run"

S=($SDB serve --grpc-preshared-key rplabkey --http-enabled --metrics-enabled=false --telemetry-endpoint=)
LBL=r2-s0; srv $S --datastore-engine memory; waitport 8443
run spicedb r2-s0-memory --bound 5.5 --tolerance $TOL --bound-class submitter-derived --bound-source "interval 5s x (1 + max staleness 0.1), submitter reading of read-after-write page" --server-pattern "sdb/spicedb serve"
stop "sdb/spicedb serve"
$PGB/pg_ctl -D ../pgdata -o "-p 55432 -k /tmp" -l logs/pg1.log start >> $L 2>&1; sleep 2
$SDB datastore migrate head --datastore-engine postgres --datastore-conn-uri $PG1 > logs/migrate.log 2>&1; log "EXIT $? migrate"
LBL=r2-s1; srv $S --datastore-engine postgres --datastore-conn-uri $PG1; waitport 8443
run spicedb r2-s1-postgres-q5 --bound 5.5 --tolerance $TOL --bound-class submitter-derived --bound-source "interval 5s x 1.1" --server-pattern "sdb/spicedb serve"
stop "sdb/spicedb serve"
LBL=r2-s2; srv $S --datastore-engine postgres --datastore-conn-uri $PG1 --datastore-revision-quantization-interval 20s; waitport 8443
run spicedb r2-s2-postgres-q20 --bound 22 --tolerance $TOL --bound-class submitter-derived --bound-source "interval 20s x 1.1" --server-pattern "sdb/spicedb serve"
stop "sdb/spicedb serve"
LBL=r2-s3; srv $S --datastore-engine postgres --datastore-conn-uri $PG1 --experimental-full-relation-cache=enabled --experimental-full-relation-cache-materialize-threshold 1; waitport 8443
run spicedb r2-s3-postgres-fullrelcache --bound 5.5 --tolerance $TOL --bound-class submitter-derived --bound-source "interval 5s x 1.1, experimental full relation cache on" --server-pattern "sdb/spicedb serve"
stop "sdb/spicedb serve"
$PGB/pg_ctl -D ../pgdata stop >> $L 2>&1

P=($PMF serve --distributed-port 5099 --meter-enabled=false)
LBL=r2-m0; srv $P --database-engine memory; waitport 3476
run permify r2-m0-memory --bound 0 --tolerance $TOL --bound-class documented --bound-source "snap-tokens.mdx: no snap token reads the latest transaction id; sequential single-node reading" --server-pattern "pmf/permify serve"
stop "pmf/permify serve"
$PGB/pg_ctl -D ../pgdata2 -o "-p 55433 -k /tmp" -l logs/pg2.log start >> $L 2>&1; sleep 2
LBL=r2-p1; srv $P --database-engine postgres --database-uri $PG2; sleep 4; waitport 3476
run permify r2-p1-postgres --bound 0 --tolerance $TOL --bound-class documented --bound-source "same as m0" --server-pattern "pmf/permify serve"
stop "pmf/permify serve"
$PGB/pg_ctl -D ../pgdata2 stop >> $L 2>&1
log "DONE"
