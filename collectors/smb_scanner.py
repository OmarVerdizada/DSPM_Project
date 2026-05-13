from smb.SMBConnection import SMBConnection
import socket

SYSTEM_SHARES = ["print$", "IPC$", "ADMIN$"]


def scan_smb(ip, username="", password="", domain="WORKGROUP"):
    results = []

    try:
        conn = SMBConnection(
            username,
            password,
            "dspm-client",
            socket.gethostname(),
            domain=domain,
            use_ntlm_v2=True,
            is_direct_tcp=True
        )

        if not conn.connect(ip, 445):
            print("[!] Connection failed")
            return []

        print("[+] Connected to SMB")

        shares = conn.listShares()

        for share in shares:
            name = share.name

            if name in SYSTEM_SHARES:
                print(f"[-] Skipping {name}")
                continue

            print(f"[+] Scanning {name}")

            try:
                for f in conn.listPath(name, "/"):
                    if f.filename in [".", ".."]:
                        continue

                    results.append({
                        "share": name,
                        "path": f"/{f.filename}",
                        "size": getattr(f, "file_size", 0),
                        "is_dir": f.isDirectory
                    })

                    print("   -", f.filename)

            except Exception as e:
                print(f"[!] Error in {name}: {e}")

        conn.close()

    except Exception as e:
        print(f"[!] SMB ERROR: {e}")

    return results
