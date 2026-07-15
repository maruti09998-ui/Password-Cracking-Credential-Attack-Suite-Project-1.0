import argparse
import csv
import json
from dataclasses import asdict
from pathlib import Path

from modules.dictionary_generator import generate_wordlist
from modules.bruteforce_simulator import simulate_bruteforce
from modules.hash_extractor import inspect_windows_hives, parse_shadow
from modules.offensive_lab import crack_dictionary, crack_mask, simulate_credential_replay
from modules.optional_tools import (
    export_windows_hives,
    passlib_hash,
    passlib_verify,
    reg_export_commands,
    run_hashcat,
    run_john,
    tool_status,
    write_json,
)
from modules.password_analyzer import analyze_password
from modules.report_generator import write_report

def _load_dictionary(path: Path | None) -> set[str]:
    if not path:
        return set()
    return {line.strip().lower() for line in path.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip()}

def main() -> int:
    parser = argparse.ArgumentParser(description="Password audit suite for controlled lab environments.")
    sub = parser.add_subparsers(dest="command", required=True)

    gen = sub.add_parser("generate-wordlist", help="Generate custom dictionary candidates.")
    gen.add_argument("--name", action="append", default=[])
    gen.add_argument("--dob", action="append", default=[], help="Date tokens such as DD-MM-YYYY.")
    gen.add_argument("--extra", action="append", default=[])
    gen.add_argument("--no-common", action="store_true")
    gen.add_argument("-o", "--output", type=Path, required=True)

    ana = sub.add_parser("analyze", help="Analyze password strength.")
    ana.add_argument("passwords", nargs="+")
    ana.add_argument("--dictionary", type=Path)
    ana.add_argument("-o", "--output", type=Path)

    ext = sub.add_parser("extract-hashes", help="Inventory lab hash sources.")
    ext.add_argument("--shadow", type=Path)
    ext.add_argument("--sam", type=Path)
    ext.add_argument("--system", type=Path)
    ext.add_argument("-o", "--output", type=Path)

    sim = sub.add_parser("simulate", help="Estimate brute-force keyspace and time.")
    sim.add_argument("--mode", default="lower,upper,digits", help="Comma-separated: lower,upper,digits,symbols.")
    sim.add_argument("--min-length", type=int, default=1)
    sim.add_argument("--max-length", type=int, default=8)
    sim.add_argument("--gps", type=float, default=1_000_000, help="Guesses per second.")
    sim.add_argument("-o", "--output", type=Path)

    crack = sub.add_parser("crack-lab", help="Offline lab cracking against user-supplied hash fixtures.")
    crack.add_argument("--hashes", type=Path, required=True, help="File containing hash or label:hash lines.")
    crack.add_argument("--algorithm", choices=["md5", "sha1", "sha256", "sha512"], required=True)
    crack.add_argument("--wordlist", type=Path, help="Dictionary file for dictionary mode.")
    crack.add_argument("--mask", help="Small mask such as ?l?l?d?d. Tokens: ?l ?u ?d ?s.")
    crack.add_argument("--max-attempts", type=int, default=100_000)
    crack.add_argument("-o", "--output", type=Path)

    replay = sub.add_parser("replay-lab", help="Local-only credential replay simulation using fixture files.")
    replay.add_argument("--credentials", type=Path, required=True, help="Candidate username:password file.")
    replay.add_argument("--allowed-users", type=Path, required=True, help="Lab allow-list username:password file.")
    replay.add_argument("-o", "--output", type=Path)

    opt = sub.add_parser("optional-tools", help="Check and use optional lab tools.")
    opt_sub = opt.add_subparsers(dest="optional_command", required=True)

    opt_status = opt_sub.add_parser("status", help="Show optional tool availability.")
    opt_status.add_argument("-o", "--output", type=Path)

    opt_hash = opt_sub.add_parser("passlib-hash", help="Generate a Linux crypt-style hash with passlib.")
    opt_hash.add_argument("password")
    opt_hash.add_argument("--scheme", choices=["md5-crypt", "sha256-crypt", "sha512-crypt"], default="sha512-crypt")
    opt_hash.add_argument("-o", "--output", type=Path)

    opt_verify = opt_sub.add_parser("passlib-verify", help="Verify a password against a passlib-supported hash.")
    opt_verify.add_argument("password")
    opt_verify.add_argument("hash")
    opt_verify.add_argument("-o", "--output", type=Path)

    opt_reg = opt_sub.add_parser("reg-hives", help="Generate or run authorized Windows SAM/SYSTEM hive export.")
    opt_reg.add_argument("--output-dir", type=Path, required=True)
    opt_reg.add_argument("--execute", action="store_true", help="Run reg.exe save commands on this Windows lab host.")
    opt_reg.add_argument("-o", "--output", type=Path)

    opt_john = opt_sub.add_parser("john", help="Run John the Ripper against an explicit local hash fixture.")
    opt_john.add_argument("--hashes", type=Path, required=True)
    opt_john.add_argument("--wordlist", type=Path)
    opt_john.add_argument("--format")
    opt_john.add_argument("--show", action="store_true")
    opt_john.add_argument("-o", "--output", type=Path)

    opt_hashcat = opt_sub.add_parser("hashcat", help="Run Hashcat against explicit local hash and wordlist fixtures.")
    opt_hashcat.add_argument("--hashes", type=Path, required=True)
    opt_hashcat.add_argument("--wordlist", type=Path, required=True)
    opt_hashcat.add_argument("--mode", type=int, required=True, help="Hashcat hash mode, e.g. 0=MD5, 100=SHA1.")
    opt_hashcat.add_argument("--attack-mode", type=int, default=0)
    opt_hashcat.add_argument("--extra", action="append", default=[])
    opt_hashcat.add_argument("-o", "--output", type=Path)

    rep = sub.add_parser("report", help="Create a JSON report from inputs.")
    rep.add_argument("--password", action="append", default=[])
    rep.add_argument("--dictionary", type=Path)
    rep.add_argument("--simulation-json", type=Path)
    rep.add_argument("--hash-json", type=Path)
    rep.add_argument("--crack-json", action="append", type=Path, default=[])
    rep.add_argument("--replay-json", action="append", type=Path, default=[])
    rep.add_argument("-o", "--output", type=Path, required=True)

    args = parser.parse_args()

    if args.command == "generate-wordlist":
        words = generate_wordlist(args.name, args.dob, args.extra, not args.no_common)
        args.output.write_text("\n".join(words) + "\n", encoding="utf-8")
        print(f"Wrote {len(words)} candidates to {args.output}")

    elif args.command == "analyze":
        dictionary = _load_dictionary(args.dictionary)
        results = [analyze_password(password, dictionary) for password in args.passwords]
        if args.output:
            with args.output.open("w", newline="", encoding="utf-8") as fh:
                writer = csv.DictWriter(fh, fieldnames=list(asdict(results[0]).keys()))
                writer.writeheader()
                for result in results:
                    writer.writerow(asdict(result))
            print(f"Results written to {args.output}")
        else:
            print(json.dumps([asdict(result) for result in results], indent=2))

    elif args.command == "extract-hashes":
        rows = []
        if args.shadow:
            rows.extend(parse_shadow(args.shadow))
        if args.sam or args.system:
            if not (args.sam and args.system):
                parser.error("--sam and --system must be provided together for offline Windows hive inventory")
            rows.extend(inspect_windows_hives(args.sam, args.system))
        if args.output:
            args.output.write_text(json.dumps(rows, indent=2), encoding="utf-8")
            print(f"Wrote hash inventory to {args.output}")
        else:
            print(json.dumps(rows, indent=2))

    elif args.command == "simulate":
        result = simulate_bruteforce(args.mode.split(","), args.min_length, args.max_length, args.gps)
        if args.output:
            args.output.write_text(json.dumps(result, indent=2), encoding="utf-8")
            print(f"Wrote simulation results to {args.output}")
        else:
            print(json.dumps(result, indent=2))

    elif args.command == "crack-lab":
        if bool(args.wordlist) == bool(args.mask):
            parser.error("Choose exactly one cracking mode: --wordlist or --mask")
        if args.wordlist:
            result = crack_dictionary(args.hashes, args.wordlist, args.algorithm, args.max_attempts)
        else:
            result = crack_mask(args.hashes, args.mask, args.algorithm, args.max_attempts)
        if args.output:
            args.output.write_text(json.dumps(result, indent=2), encoding="utf-8")
            print(f"Wrote lab cracking results to {args.output}")
        else:
            print(json.dumps(result, indent=2))

    elif args.command == "replay-lab":
        result = simulate_credential_replay(args.credentials, args.allowed_users)
        if args.output:
            args.output.write_text(json.dumps(result, indent=2), encoding="utf-8")
            print(f"Wrote replay simulation results to {args.output}")
        else:
            print(json.dumps(result, indent=2))

    elif args.command == "optional-tools":
        if args.optional_command == "status":
            result = tool_status()
        elif args.optional_command == "passlib-hash":
            result = passlib_hash(args.password, args.scheme)
        elif args.optional_command == "passlib-verify":
            result = passlib_verify(args.password, args.hash)
        elif args.optional_command == "reg-hives":
            result = export_windows_hives(args.output_dir) if args.execute else reg_export_commands(args.output_dir)
        elif args.optional_command == "john":
            result = run_john(args.hashes, args.wordlist, args.format, args.show)
        elif args.optional_command == "hashcat":
            result = run_hashcat(args.hashes, args.wordlist, args.mode, args.attack_mode, args.extra)
        else:
            parser.error("Unknown optional-tools command")

        if args.output:
            write_json(args.output, result)
            print(f"Wrote optional tool result to {args.output}")
        else:
            print(json.dumps(result, indent=2))

    elif args.command == "report":
        dictionary = _load_dictionary(args.dictionary)
        results = [analyze_password(password, dictionary) for password in args.password]
        simulations = json.loads(args.simulation_json.read_text(encoding="utf-8")) if args.simulation_json else []
        hashes = json.loads(args.hash_json.read_text(encoding="utf-8")) if args.hash_json else []
        cracking = [json.loads(path.read_text(encoding="utf-8")) for path in args.crack_json]
        replay = [json.loads(path.read_text(encoding="utf-8")) for path in args.replay_json]
        write_report(
            args.output,
            results,
            simulations if isinstance(simulations, list) else [simulations],
            hashes,
            cracking,
            replay,
        )
        print(f"Wrote report to {args.output}")

    return 0

if __name__ == "__main__":
    raise SystemExit(main())
