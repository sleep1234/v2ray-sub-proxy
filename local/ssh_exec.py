#!/usr/bin/env python3
"""Reusable paramiko runner.
Env: SH_HOST, SH_PORT, SH_USER, SH_PASS
Usage:
  python ssh_exec.py mkdir <remote_dir>
  python ssh_exec.py put <local_file> <remote_path>
  python ssh_exec.py get <remote_file> <local_path>
  python ssh_exec.py exec <command...>
"""
import os, sys, paramiko

HOST = os.environ.get("SH_HOST","")
PORT = int(os.environ.get("SH_PORT","22"))
USER = os.environ.get("SH_USER","")
PASS = os.environ.get("SH_PASS","")

def client():
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(HOST, port=PORT, username=USER, password=PASS, timeout=20,
              allow_agent=False, look_for_keys=False)
    return c

def main():
    if len(sys.argv) < 2:
        print("need subcommand"); return 2
    cmd = sys.argv[1]
    c = client()
    try:
        if cmd == "exec":
            _, out, err = c.exec_command(" ".join(sys.argv[2:]), timeout=60)
            so = out.read().decode("utf-8","replace")
            se = err.read().decode("utf-8","replace")
            print(so, end="")
            if se.strip(): print("[stderr]", se, end="", file=sys.stderr)
            return out.channel.recv_exit_status()
        if cmd == "mkdir":
            c.exec_command("mkdir -p " + sys.argv[2])[0].read()
            print("mkdir ok:", sys.argv[2]); return 0
        if cmd == "put":
            sftp = c.open_sftp()
            sftp.put(sys.argv[2], sys.argv[3])
            print("put ok:", sys.argv[3]); return 0
        if cmd == "get":
            sftp = c.open_sftp()
            sftp.get(sys.argv[2], sys.argv[3])
            print("get ok:", sys.argv[3]); return 0
        print("unknown subcommand", cmd); return 2
    finally:
        c.close()

if __name__ == "__main__":
    sys.exit(main())
