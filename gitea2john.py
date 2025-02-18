#! /usr/bin/env python3

import sqlite3
import base64
import argparse

def main():
    parser = argparse.ArgumentParser(description = "Converter gitea.db credentials in HashCat format",\
                                     epilog = "Author: CyberRavenMan")
    parser.add_argument("--path", help="path to 'gitea.db' file", required = True)
    parser.add_argument("--outfile", help="name of file to save hashes", required = False)
    args = parser.parse_args()
    try:
        cursor = (sqlite3.connect(args.path)).cursor()
        cursor.execute("SELECT name,passwd_hash_algo,salt,passwd FROM user")
        print(f"[!]: Usage with hashcat mode (-m) 10900 for attack")
        print("-" * 45)
        for row in cursor.fetchall():
            if "pbkdf2" in row[1]:
                algo, iterations, keylen = row[1].split("$")
                name = row[0]
            else:
                raise Exception("Unknown Algorithm")
            salt = bytes.fromhex(row[2])
            passwd = bytes.fromhex(row[3])
            salt_base64 = base64.b64encode(salt).decode("utf-8")
            passwd_base64 = base64.b64encode(passwd).decode("utf-8")
            hash_value = f"{name}:sha256:{iterations}:{salt_base64}:{passwd_base64}\n"
            if args.outfile:
                with open(args.outfile, "a") as fd:
                    fd.write(hash_value)
            print(f"[+]: {hash_value}", end = "")
        print("-" * 45)
        print("[+]: Done! Good luck!")
    except Exception as err:
        print("-" * 45)
        print(f"[-]: Alert! Error: {err}")
        exit(1)

if __name__ == "__main__":
    main()
