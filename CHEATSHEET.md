# CipherGate — Linux / Docker Cheat Sheet

A quick reference for running CipherGate inside the colima Linux VM + Docker
container. Written for a Mac host. Plain commands, copy-paste ready.

---

## 1. The lay-out (what's where)

There are THREE layers. Don't mix them up:

    [ Your Mac ]  ── the real machine, your files at /Volumes/Secure/private_api_vault
         │
         └── [ The VM (colima) ]  ── a Linux machine (Ubuntu 24.04) running ON your Mac.
              │                      Its files live at ~/.colima  (internal disk)
              │
              └── [ The container (ciphergate) ]  ── a disposable box INSIDE the VM.
                                                Holds /cg.py and the COPIED vault at /.vault

- The container's `/` is its OWN root — NOT your Mac's `/`.
- `/cg.py` and `/.vault` sit at the top of the CONTAINER's filesystem.
- Your real vault on the Mac is never touched; the container gets a COPY.

---

## 2. Space / sizes (measured)

| Thing                                   | Where            | Size        |
|-----------------------------------------|------------------|-------------|
| VM disk image (`disk`)                  | Mac: `~/.colima/_lima/colima/disk` | **1.4 GB** |
| colima total footprint on the Mac       | Mac: `~/.colima` | **1.6 GB**  |
| VM root filesystem (inside)             | inside VM (`df -h /`) | 6.8 GB size, **1.2 GB used**, 5.6 GB free |
| Base image `python:3.12-slim`           | Docker           | **191 MB**  |
| Container `ciphergate` (writable layer)     | Docker           | **2.4 MB** (virtual 145 MB) |
| Container's inner OS (Debian 13)        | inside container | **127 MB**  |
| Docker total (images+containers)        | Docker           | **~196 MB** |
| `ciphergate.py`                         | Mac repo         | **93 KB**   |
| Real `.vault/` (encrypted store)        | Mac repo         | **352 KB**  |
| Mac internal disk free                  | Mac              | **42 GB**   |

Vault breakdown: `ledger.jsonl` 331 KB, `keys.json` 6.9 KB, `access.json` 284 B,
`leases.json` 93 B, `pending.json` 93 B.

**Bottom line:** the whole docker/VM test setup costs ~1.6 GB on the Mac, almost
all of it the VM disk image. CipherGate itself is ~450 KB.

---

## 3. Peek inside the VM (the Linux machine)

Enter it:                       `colima ssh`
Leave it:                       `exit`

One-liners (no entering):
    colima ssh -- cat /etc/os-release      # what Linux it is
    colima ssh -- ls -la /                 # VM's root
    colima ssh -- df -h /                  # VM disk usage

VM control:
    colima status        # is it running?
    colima start         # boot it  (needed after a Mac reboot)
    colima stop          # shut it down
    colima list          # all VMs

---

## 4. Peek inside the container (where CipherGate lives)

Enter it:                       `docker exec -it ciphergate bash`
Leave it:                       `exit`

Inside the container:
    ls -la /                 # see cg.py + /.vault at the top
    ls -la /.vault           # the copied vault files
    cat /etc/os-release      # Debian GNU/Linux 13 (trixie)

One-liners:
    docker exec ciphergate ls -la /
    docker exec ciphergate ls -la /.vault

---

## 5. Run CipherGate commands (in the container)

From the Mac, open a shell inside:      `docker exec -it ciphergate bash`
Then:
    cd /
    python3 /cg.py list              # asks for the passphrase (hidden)
    python3 /cg.py status
    python3 /cg.py ledger
    python3 /cg.py --help            # full command list

Leave with `exit`.

---

## 6. Run the CipherGate server (in the container)

From a shell inside the container:
    VAULT_BIND=0.0.0.0 python3 /cg.py run --port 18200

- It asks for the passphrase, then it is live.
- `VAULT_BIND=0.0.0.0` is what lets the OUTSIDE reach it (required in a container).
- Your Mac reaches it at:  http://127.0.0.1:18200   (same address as always)
- Need CLI while it runs? Open a SECOND terminal:  `docker exec -it ciphergate bash`

---

## 7. Copy files in / out (Mac <-> container)

Mac -> container:
    docker cp /Volumes/Secure/private_api_vault/ciphergate.py ciphergate:/cg.py
    docker cp /Volumes/Secure/private_api_vault/.vault        ciphergate:/.vault

Container -> Mac:
    docker cp ciphergate:/.vault/ledger.jsonl /tmp/ledger-from-container.jsonl

Note: the container vault is a SNAPSHOT. Change the Mac vault -> re-copy.

---

## 8. Docker housekeeping

    docker ps                       # running containers
    docker ps -a                    # ALL containers (incl. stopped)
    docker ps -s                    # + sizes
    docker images                   # images (+ sizes)
    docker system df                # total disk used by docker

Clean up the test box (deletes the container AND its copied vault):
    docker rm -f ciphergate

Free the whole docker sandbox (images too):
    docker system prune -a

Shut the VM down entirely:
    colima stop

---

## 9. Rebuilding the test box from scratch

    colima start                                       # if the VM is off
    docker run -d --name ciphergate -p 127.0.0.1:18200:18200 python:3.12-slim sleep infinity
    docker cp /Volumes/Secure/private_api_vault/ciphergate.py ciphergate:/cg.py
    docker cp /Volumes/Secure/private_api_vault/.vault        ciphergate:/.vault
    docker exec -it ciphergate bash                        # then run things inside

---

## 10. Notes / gotchas

- The container runs as **root**; your Mac user is **501**. Copied files show
  owner `501` inside — harmless.
- `openssl` IS already in the base image (used for the AES). No install needed.
- The server refuses to start if `VAULT_PASS` is set in the environment (leak
  guard). Type the passphrase at the prompt, or (tests only) add
  `VAULT_ALLOW_ENV_PASS=1`.
- The container's `/` is not the Mac's `/`. Nothing here touches your real files.
