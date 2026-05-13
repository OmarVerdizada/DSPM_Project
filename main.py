from collectors.smb_scanner import scan_smb


def main():
    print("[+] DSPM STARTED")

    files = scan_smb("127.0.0.1")

    print("\n[+] SUMMARY")
    print(f"Total files: {len(files)}")

    for f in files:
        print(f"{f['share']}{f['path']} ({f['size']})")


if __name__ == "__main__":
    main()
