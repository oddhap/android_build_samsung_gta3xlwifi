# Frozen-bank accept/install/ACK transaction

This inactive poller uses actual StatsAccess and the durable journal on the
caller's existing factory lock. It resumes a pending frozen bank or performs one
exact SWAP, reads real records/loss, restores the committed complete consumer
state, prepares a new complete state, durably accepts it, installs it, and only
then ACKs. A recovered accepted receipt restores its state without appending the
delta again. No operation/session recovery is automatically retried.

Missing, regressed or gapped acceptance history is an error rather than an
invented zero baseline. Genuine loss, preparation/install failure or uncertain
journal writing withholds ACK. Lost SWAP/ACK replies retire the actual token;
explicit new-session/full-policy recovery can resume pending data or move to a
new real empty bank without double counting prior acceptance.

Actual four-source compilation against original Connectivity SDK classpaths,
unchanged native prerequisite binding and1243/17 audits pass. Host fixtures replay
1467 policy/stats client checks and pass48 poll-flow checks. These cover normal
multiple polls, acceptance-before-ACK ordering, write-before/write-after faults,
consumer preparation/installation faults, loss/read errors, missing baseline and
all four before/after SWAP/ACK reply failures with explicit session recovery.
The consumer/kernel/Binder/store models are explicit fixtures: this is not the
actual Android NetworkStatsFactory consumer or hardware IPC/power-loss proof.

Prerequisite: stats-journal-20261115-01. Before real factory routing, implement its
complete serializer and interface-name history, counterset/UID cleanup and durable
consumer-state amendments. Journal restore must never undo UID lifecycle cleanup.
NetworkStatsService also still constructs six real BPF maps and its cookie destroy
listener in selected stock source; all those consumers/dump/cleanup branches need
explicit private routing rather than fake maps. TrafficStats, loopback events,
privileged CLAT, complete Soong/APEX and strict policy integration, full ROM and
installation checks remain. Selected Android source/prebuilts and rollback/signing
material are unchanged. No flash-ready package or networking Ready is claimed.
