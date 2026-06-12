#!/usr/bin/env python3
# Copyright (C) 2026 Stuart Pook
# SPDX-License-Identifier: GPL-3.0-or-later
import os
import re
import subprocess
import sys
import json
import logging
import argparse
import pathlib
import shlex
import typing
import time
import datetime
import random
import stat
import tempfile
import collections

logger = logging.getLogger(pathlib.Path(__file__).stem)


def set_logging_level(loglevel: int) -> None:
    script_name = pathlib.Path(sys.argv[0]).name
    logging.basicConfig(
        level=logging.WARNING,
        format=f"{script_name}:%(levelname)s:%(name)s:%(message)s",
        force=True,
    )
    logger.setLevel(loglevel)


class AppConfig(typing.TypedDict):
    domain: str
    ignore: str
    prefix: str
    unalias: str
    ignored_dirs: list[str]


class CacheEntry(typing.TypedDict):
    mtime_ns: int
    size: int
    used: list[str]
    unalias: list[str]


AliasCache = dict[str, CacheEntry]


class LazyQuote:
    """Only evaluates shlex.quote() when the logger formats the string."""
    __slots__ = ['_val']

    def __init__(self, val: str | pathlib.Path):
        self._val = val

    def __str__(self) -> str:
        return shlex.quote(str(self._val))


def load_config(config_path: pathlib.Path) -> AppConfig:
    try:
        with open(config_path, 'r') as f:
            if os.fstat(f.fileno()).st_mode & (stat.S_IRGRP | stat.S_IROTH):
                logger.critical("Insecure permissions: file %s is group or public readable", LazyQuote(config_path))
                sys.exit(45)
            json_data = json.load(f)
    except FileNotFoundError as e:
        logger.critical("Config file not found: %s", e)
        sys.exit(29)
    except json.JSONDecodeError as e:
        logger.critical("Malformed JSON in config file %s: %s", LazyQuote(config_path), e)
        sys.exit(1)
    return typing.cast(AppConfig, json_data)


def run_self_tests(domain: str) -> re.Pattern[str]:
    lookahead = r"(?![a-z0-9.])"
    pattern = re.compile(
        rf"^[ \t]*(.*?)[ \t]*([a-z0-9._%+-]+)@{re.escape(domain)}{lookahead}",
        re.IGNORECASE | re.MULTILINE,
    )
    test_cases = [
        # Single matches
        (f"anything@{domain}", [("", "anything")]),
        (f"Alias: anything@{domain}", [("Alias:", "anything")]),
        # Multi-line string with multiple valid emails
        (
            f"login: my.name+tag@{domain}\n"
            f"Some random text\n"
            f"   Email is :  random123@{domain}",
            [("login:", "my.name+tag"), ('Email is :', "random123")]
        ),
        # Multi-line string with mixed valid/invalid emails
        (
            f"user_name.123-abc@{domain}\n"
            f"ignoreme@{domain}.com\n"
            f"secondary: backup@{domain}",
            [("", "user_name.123-abc"), ("secondary:", "backup")]
        ),
        # Completely invalid matches return an empty list
        (f"anything@{domain}.com", []),
        ('just some text\nmore text', []),
        (
            f"  unalias:  spaced-out@{domain}",
            [("unalias:", "spaced-out")]
        ),
    ]
    for text, expected in test_cases:
        result = pattern.findall(text)
        if result != expected:
            logger.critical(f"SELF-TEST FAILED:\nText:\n'{text}'\nExpected: {expected}\nGot: {result}")
            sys.exit(1)
    return pattern


def filename_is_bad(text: str) -> bool:
    return any(char.isspace() and char != ' ' for char in text)


def _is_cache_valid(full_path: pathlib.Path, entry: CacheEntry) -> bool:
    try:
        file_stat = full_path.stat()
    except FileNotFoundError:
        return False
    return file_stat.st_mtime_ns == entry['mtime_ns'] and file_stat.st_size == entry['size']


def prune_cache(cache: AliasCache, pass_store: pathlib.Path) -> AliasCache:
    """Returns a new AliasCache containing only entries that match the filesystem."""
    return {
        pass_name: entry
        for pass_name, entry in cache.items()
        if _is_cache_valid(pass_store / f"{pass_name}.gpg", entry)
    }


def add_cache_entry(
        cache: AliasCache, pass_name: str,
        used: set[str],
        unalias: set[str],
        file_stat: os.stat_result,
) -> None:
    e: CacheEntry = {
        'mtime_ns': file_stat.st_mtime_ns,
        'size': file_stat.st_size,
        'used': list(used),
        'unalias': list(unalias)
    }
    cache[pass_name] = e


def process_single_password(
        cache: AliasCache,
        full_path: pathlib.Path,
        pass_name: str,
        pattern: re.Pattern[str],
        unalias_tag: str,
) -> None:
    file_stat = full_path.stat()
    try:
        result = subprocess.run(['gpg', '--decrypt', '--quiet', str(full_path)], capture_output=True, check=True)
        cleartext = result.stdout.decode('utf-8', errors='replace')
    except subprocess.CalledProcessError as e:
        logger.critical("Failed to decrypt %s: %s", pass_name, e.stderr.decode('utf-8', errors='replace'))
        sys.exit(1)
    matches = pattern.findall(cleartext)
    used: set[str] = set()
    unalias: set[str] = set()
    for prefix, email in matches:
        if prefix == unalias_tag:
            unalias.add(email)
        else:
            used.add(email)
    if used & unalias:
        logger.critical("password %s has overlapping aliases used %s unalias %s", LazyQuote(pass_name), used, unalias)
        sys.exit(12)
    add_cache_entry(file_stat=file_stat, used=used, unalias=unalias, cache=cache, pass_name=pass_name)


def get_files_to_decrypt(
        pass_store: pathlib.Path,
        ignored_dirs: list[str],
        cache: AliasCache
) -> list[tuple[pathlib.Path, str]]:
    """
    Walks the password store and returns a list of (full_path, pass_name)
    only for files that are missing from the valid cache.
    """
    files_to_decrypt: list[tuple[pathlib.Path, str]] = []
    for root, dirs, files in pass_store.walk():
        # Handle ignored directories at the root level
        if root == pass_store:
            for skip in ignored_dirs:
                if skip in dirs:
                    dirs.remove(skip)
        relative_root = root.relative_to(pass_store)
        for f in files:
            if not f.endswith('.gpg') or f.startswith('.'):
                continue
            if filename_is_bad(f):
                logger.critical("filename %s/%s contains bad characters", LazyQuote(root), LazyQuote(f))
                sys.exit(77)
            pass_name = str((relative_root / f).with_suffix(''))
            if pass_name not in cache:
                files_to_decrypt.append((root / f, pass_name))
    return files_to_decrypt


def update_cache_with_decryptions(
        pass_store: pathlib.Path,
        ignored_dirs: list[str],
        cache: AliasCache,
        pattern: re.Pattern[str],
        unalias_tag: str
) -> None:
    files_to_decrypt = get_files_to_decrypt(pass_store=pass_store, cache=cache, ignored_dirs=ignored_dirs)
    total = len(files_to_decrypt)
    if not total:
        return
    logger.info("Decrypting %d modified/new files...", total)
    start_time = time.time()
    old_message = ''
    show_progress = logger.getEffectiveLevel() <= logging.INFO
    for i, (full_path, pass_name) in enumerate(files_to_decrypt, start=1):
        process_single_password(
            cache=cache, full_path=full_path, pass_name=pass_name, pattern=pattern, unalias_tag=unalias_tag)
        if show_progress:
            percent = (i * 100) // total
            message = f"\r{percent}% of {total} password files decrypted "
            if message != old_message:
                print(end=message, flush=True, file=sys.stderr)
                old_message = message
    if old_message:
        print(end='\r' + ' ' * len(old_message) + '\r', flush=True, file=sys.stderr)
    logger.info("Cache updated with %d decryptions in %.1fs", total, time.time() - start_time)


def read_cache(cache_path: pathlib.Path) -> AliasCache:
    try:
        with cache_path.open('r') as f:
            cache = json.load(f)
    except FileNotFoundError:
        logger.warning("no cache found at %s", LazyQuote(cache_path))
        return {}
    logger.debug("cache with %d entries found at %s", len(cache), LazyQuote(cache_path))
    return cache


def write_cache(cache: AliasCache, cache_path: pathlib.Path) -> None:
    temp_path = cache_path.with_name(cache_path.name + '.tmp')
    try:
        with temp_path.open('w') as f:
            json.dump(cache, f, indent=4, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
        temp_path.replace(cache_path)
    finally:
        temp_path.unlink(missing_ok=True)
    logger.info("wrote %d cache entries to %s", len(cache), LazyQuote(cache_path))


def print_entries(aliases: dict[str, list[str]], prefix: str = '') -> None:
    for known, passwords in aliases.items():
        print(prefix, shlex.quote(known), ' ', shlex.join(passwords), sep='')


def create_entry(
        cache: AliasCache, cache_path: pathlib.Path,
        used: dict[str, list[str]], unaliased: dict[str, list[str]], domain: str, prefix: str, pass_store: pathlib.Path,
) -> None:
    known = used.keys() | unaliased.keys()
    while True:
        random_number = random.randint(1, 999999)
        alias = f"{prefix}{random_number:06d}"
        if alias not in known:
            break
    ts = datetime.datetime.now().strftime("%y%m%d%H")
    pass_name = f"unused/x{ts}-{alias}"
    full_path = pass_store / f"{pass_name}.gpg"
    email = f"{alias}@{domain}"
    logger.info(
        "create password %s with email %s for alias %s in %s", LazyQuote(pass_name), email, alias, LazyQuote(full_path))
    content = f"\nemail: {email}\n"
    subprocess.run(
        ['pass', 'insert', '--multiline', pass_name],
        input=content, text=True, check=True, stdout=subprocess.DEVNULL)
    add_cache_entry(
        cache=cache,
        pass_name=pass_name,
        used=set([alias]),
        unalias=set(),
        file_stat=full_path.stat(),
    )
    used[alias] = [pass_name]
    write_cache(cache=cache, cache_path=cache_path)
    subprocess.run(['pass', 'git', 'push', '--quiet'], check=True)


def get_summaries(cache: AliasCache) -> tuple[dict[str, list[str]], dict[str, list[str]]]:
    unalias: dict[str, list[str]] = {}
    used: dict[str, list[str]] = {}
    for password, v in cache.items():
        for alias in v['unalias']:
            unalias.setdefault(alias, []).append(password)
        for alias in v['used']:
            used.setdefault(alias, []).append(password)
    overlap = used.keys() & unalias.keys()
    if overlap:
        logger.critical("aliases used and unaliased: %s", overlap)
        for alias in overlap:
            logger.critical("alias %s used in %s, unaliased in %s", alias, used[alias], unalias[alias])
        sys.exit(10)
    return used, unalias


def run_sync(local_parts: collections.abc.KeysView[str], cfg_file: pathlib.Path) -> None:
    cfg_filename = cfg_file.as_posix()
    if ',' in cfg_filename:
        logger.critical("error: the configuration filename contains a comma: %s", LazyQuote(cfg_filename))
        sys.exit(98)
    with tempfile.TemporaryFile(mode="w+t", encoding="utf-8") as f:
        count = 0
        for local_part in local_parts:
            print(local_part, file=f)
            count += 1
        f.seek(0)
        os.dup2(f.fileno(), sys.stdin.fileno())
        os.set_inheritable(sys.stdin.fileno(), True)
        mount_point = '/app/config.json'
        cmd = 'podman'
        arguments = [
            cmd, 'run', '--interactive', '--rm',
            f"--mount=type=bind,target={mount_point},readonly,source={cfg_filename}",
            'ovh-syncer', f"--config={mount_point}", f"--count={count}", f"--loglevel={logger.getEffectiveLevel()}",
        ]
        logger.debug("running: %s", shlex.join(arguments))
        os.execvp(cmd, arguments)
    logger.critical("execvp of %s failed", LazyQuote(cmd))
    sys.exit(6)


def run_manage(
        cfg_file: pathlib.Path, print_known: bool, print_used: bool, create_alias: bool,
        print_unaliased: bool,
        cache_path: pathlib.Path) -> None:
    cfg = load_config(cfg_file)
    ignored_dirs = cfg['ignored_dirs']
    unalias_tag = cfg['unalias']
    domain = cfg['domain']
    prefix = cfg['prefix']
    alias_pattern = run_self_tests(domain)
    pass_store = pathlib.Path('~').expanduser() / '.password-store'
    original_cache = read_cache(cache_path)
    cache = prune_cache(cache=original_cache, pass_store=pass_store)
    update_cache_with_decryptions(
        pass_store=pass_store, cache=cache, ignored_dirs=ignored_dirs, pattern=alias_pattern, unalias_tag=unalias_tag)
    if cache != original_cache:
        write_cache(cache=cache, cache_path=cache_path)
    used, unalias = get_summaries(cache)
    if print_known:
        print_entries(used, prefix='+ ')
        print_entries(unalias, prefix='- ')
        return
    if print_used:
        print_entries(used)
        return
    if print_unaliased:
        print_entries(unalias)
        return
    if create_alias:
        create_entry(
            cache=cache, cache_path=cache_path, used=used, unaliased=unalias,
            domain=domain, prefix=prefix, pass_store=pass_store)
    run_sync(local_parts=used.keys(), cfg_file=cfg_file)


def manage() -> None:
    program_name = 'ovh-alias-manager'
    parser = argparse.ArgumentParser(
        description='Sync email aliases from password files to OVH',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument(
        '--config', type=pathlib.Path, help='Path to config',
        default=pathlib.Path('~') / '.config' / program_name / 'config.json')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-v', '--verbose', '--debug', action='store_true', help='Set level to DEBUG')
    group.add_argument("-q", "--quiet", action="store_true", help="Set level to WARNING")
    group.add_argument(
        "-l", "--level", help="Set explicit console logging level",
        choices=["debug", "info", "warning", "error", "critical"])
    function = parser.add_mutually_exclusive_group()
    function.add_argument('--known', action='store_true', help='print all known aliases')
    function.add_argument('--used', action="store_true", help='print all used aliases')
    function.add_argument('--unaliased', action="store_true", help='print all unaliased aliases')
    function.add_argument('-c', '--create', action="store_true", help='create a new alias')

    parser.add_argument(
        '--alias-cache', type=pathlib.Path, help='cache of email alias',
        default=pathlib.Path('~') / '.cache' / program_name)

    args = parser.parse_args()
    if args.level:
        log_level = getattr(logging, args.level.upper())
    elif args.verbose:
        log_level = logging.DEBUG
    elif args.quiet:
        log_level = logging.WARNING
    else:
        log_level = logging.INFO
    set_logging_level(log_level)

    run_manage(
        print_known=args.known, cfg_file=args.config.expanduser(),
        print_used=args.used, print_unaliased=args.unaliased, create_alias=args.create,
        cache_path=args.alias_cache.expanduser())


if __name__ == "__main__":
    manage()
