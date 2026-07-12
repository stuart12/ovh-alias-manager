#!/usr/bin/env python3
# https://eu.api.ovh.com/console/?section=%2Femail%2Fmxplan&branch=v1#get-/email/mxplan/-service-/account/-email-/alias
# Copyright (C) 2026 Stuart Pook
# SPDX-License-Identifier: GPL-3.0-or-later
import sys
import json
import logging
import argparse
import time
import ovh  # type: ignore
import pathlib
import shlex
import typing
import re
import os

logger = logging.getLogger(pathlib.Path(__file__).stem)


def loglevel_type(value: str) -> int:
    if value.isdigit():
        return int(value)
    mapping = logging.getLevelNamesMapping()
    name = value.upper()
    if name in mapping:
        return mapping[name]
    raise argparse.ArgumentTypeError(f"Invalid log level: {value}")


def add_loglevel_arguments(parser: argparse.ArgumentParser) -> None:
    parser.set_defaults(loglevel=logging.INFO)

    target_levels = [
        logging.DEBUG,
        logging.INFO,
        logging.WARNING,
        logging.ERROR,
        logging.CRITICAL,
    ]
    for level_int in target_levels:
        name = logging.getLevelName(level_int)
        aliases = [f"--{name.lower()}"]
        if level_int == logging.DEBUG:
            aliases.extend(['-v', '--verbose'])
        elif level_int == logging.CRITICAL:
            aliases.append('--quiet')
        parser.add_argument(
            *aliases, dest='loglevel', action='store_const',
            const=level_int, help=f"Set log level to {name}",
        )

    parser.add_argument(
        '--loglevel', dest='loglevel', type=loglevel_type,
        help='Set log level by name (e.g., DEBUG) or integer (e.g., 10)',
    )


def set_logging_level(options: argparse.Namespace) -> None:
    script_name = pathlib.Path(sys.argv[0]).name
    logging.basicConfig(
        level=logging.WARNING,
        format=f"{script_name}:%(levelname)s:%(name)s:%(message)s",
        force=True,
    )
    logger.setLevel(options.loglevel)


class LazyQuote:
    """Lazily evaluates shlex.quote() only when the logger actually formats the string."""
    __slots__ = ['_val']

    def __init__(self, val: str | pathlib.Path):
        self._val = val

    def __str__(self) -> str:
        return shlex.quote(str(self._val))


class AppConfig(typing.TypedDict):
    service: str
    target_user: str
    domain: str
    ovh_config: dict[str, str]  # Assuming this is just strings
    minimum_length: int
    maximum_creations: int
    maximum_deletions: int


class OvhClient:
    def __init__(self, cfg: AppConfig, per_second: float):
        self._client = ovh.Client(**cfg['ovh_config'])
        self._per_second = per_second
        self._delay = 1.0 / self._per_second
        self._request_count = 0
        base = f"/email/mxplan/{cfg['service']}/account/{cfg['target_user']}@{cfg['domain']}"
        self._task_url = f"{base}/task"
        self._endpoint = f"{base}/alias"

    def _wait(self):
        if self._request_count >= self._per_second:
            time.sleep(self._delay)
        else:
            self._request_count += 1

    def list(self):
        self._wait()
        return self._client.get(self._endpoint)

    def create(self, alias: str):
        self._wait()
        return self._client.post(self._endpoint, alias=alias)

    def delete(self, alias: str):
        self._wait()
        return self._client.delete(f"{self._endpoint}/{alias}")

    def status(self, task: int):
        self._wait()
        return self._client.get(f"{self._task_url}/{task}")


def load_config(config_path: pathlib.Path) -> AppConfig:
    path_str = config_path.as_posix()
    fd_prefix = '/dev/fd/'
    if path_str.startswith(fd_prefix):
        fd_number = int(path_str[len(fd_prefix):])
        f = os.fdopen(fd_number, 'r')
    else:
        try:
            f = open(config_path, 'r')
        except FileNotFoundError as ex:
            logger.critical("Config file %s not found: %s", LazyQuote(config_path), ex)
            sys.exit(2)
    with f:
        return typing.cast(AppConfig, json.load(f))


def _validate_suffix(word: str, minimum_length: int, maximum_length: int) -> str:
    """Validates the suffix or halts the script."""
    if not (minimum_length <= len(word) <= maximum_length):
        logger.critical(
            "Invalid alias: %s. Must be between %d and %d characters",
            LazyQuote(word), minimum_length, maximum_length,
        )
        sys.exit(3)
    if word.strip('.') != word:
        logger.critical("Invalid alias: %s. no leading or trailing dots", LazyQuote(word))
        sys.exit(4)
    if not word.replace('.', '').isalnum():
        logger.critical("Invalid alias: %s. Must be alphanumeric (dots allowed inside)", LazyQuote(word))
        sys.exit(5)
    return word


def assert_ends_with_newline(line: str) -> str:
    if not line:
        logger.critical("Invalid line: %s", LazyQuote(line))
        sys.exit(4)
    if not line.endswith('\n'):
        logger.critical("line does not end with a newline: %s", LazyQuote(line))
        sys.exit(4)
    return line


def get_words_from_stdin(cfg: AppConfig) -> set[str]:
    minimum_length = cfg['minimum_length']
    maximum_length = 32
    word_list = [
        _validate_suffix(word=word, minimum_length=minimum_length, maximum_length=maximum_length)
        for line in sys.stdin
        for word in assert_ends_with_newline(line).split()
    ]
    words = set(word_list)
    if len(word_list) != len(words):
        logger.critical("duplicate local_parts (found %d words but %d distinct words)", len(word_list), len(words))
        sys.exit(46)
    logger.debug("%d words on stdin", len(words))
    return words


def get_local_part(address: str, end: str) -> str:
    if address.endswith(end):
        return address[:-len(end)]
    logger.critical("alias %s found on server did not end with %s", LazyQuote(address),  LazyQuote(end))
    sys.exit(7)


def get_aliases(client: OvhClient, domain: str) -> set[str]:
    try:
        on_server = set(client.list())
    except ovh.exceptions.APIError as ex:
        logger.critical('failed to get aliases [%s]', str(ex))
        sys.exit(6)
    domain_part = f"@{domain}"
    aliases = [get_local_part(address, domain_part) for address in on_server]
    logger.debug("%d aliases found on server: %s", len(aliases), shlex.join(aliases))
    return set(aliases)


def full_alias(alias_suffix: str, domain: str) -> str:
    return f"{alias_suffix}@{domain}"


def create_alias(client: OvhClient, alias_suffix: str, domain: str) -> int | None:
    alias = full_alias(alias_suffix, domain)
    try:
        r = client.create(alias=alias)
    except (ovh.exceptions.BadParametersError, ovh.exceptions.ResourceConflictError) as ex:
        logger.critical("%s creating alias %s: %s", type(ex).__name__, LazyQuote(alias), str(ex))
        sys.exit(7)
    logger.debug("requested creation of alias %s: %s", LazyQuote(alias), r)
    if isinstance(r, dict):
        return r.get('id')
    logger.warning("creating alias %s did not return a dict!: %s", LazyQuote(alias), r)
    return None


def create_aliases(client: OvhClient, to_create: set[str], domain: str) -> list[int]:
    logger.debug("need to create %d entries: %s",  len(to_create), to_create)
    return [
        task_id
        for alias_suffix in to_create
        if (task_id := create_alias(client=client, domain=domain, alias_suffix=alias_suffix))
    ]


def get_task_status(client: OvhClient, task_id: int) -> tuple[str, str]:
    """Fetches the current status of an OVH task."""
    try:
        task_info = client.status(task=task_id)
        logger.warning("task info %d status: %s", task_id, task_info)
        status = task_info.get('status', 'unknown')
        reason = (
            task_info.get('message') or
            task_info.get('comment') or
            task_info.get('todoDate') or    # Often repurposed by OVH for crash timestamps/logs
            task_info.get('function') or    # Tells us the literal system function that crashed
            'No reason provided'
        )
        return status, reason
    except ovh.exceptions.APIError as ex:
        logger.warning("Exception checking task %d status: %s", task_id, str(ex))
        return 'api_error', 'failed to reach OVH API'


TASK_ID_REGEX = re.compile(r"have pending task\s*:\s*(\d+)")


def handle_failed_operation(client: OvhClient, ex: ovh.exceptions.APIError, alias_email: str) -> None:
    error_msg = str(ex)
    match = TASK_ID_REGEX.search(error_msg)
    if match:
        task_id = int(match.group(1))
        current_status, reason = get_task_status(client, task_id)
    else:
        current_status = reason = '???'
    logger.error(
        "failed to delete alias %s: %s [%s, %s]",
        LazyQuote(alias_email), error_msg.replace('\n', ' '), current_status, reason)


def is_task_done(client: OvhClient, task_id: int, start: float) -> bool:
    try:
        task_info = client.status(task=task_id)
        status = task_info.get('status', 'unknown')
        if status == 'done':
            return True
        if status in ('error', 'cancelled'):
            logger.critical("OVH failed to process task %d. Status: %s", task_id, status)
            sys.exit(9)
    except ovh.exceptions.APIError as ex:
        logger.warning("Exception checking task %d status: %s", task_id, str(ex))
    return False


def wait_for_task(client: OvhClient, task_id: int, start: float, warn_after: float, long_delay: float) -> None:
    waited = False
    while not is_task_done(client=client, task_id=task_id, start=start):
        waited = True
        elapsed = time.time() - start
        if elapsed > warn_after:
            logger.warning("Task %d still not complete after %0.1fs (waiting %0.1fs)", task_id, elapsed, long_delay)
            time.sleep(long_delay)
        else:
            time.sleep(1.01)
    if waited:
        logger.debug("Task %d completed after %0.1fs", task_id, time.time() - start)
    else:
        logger.debug("Task %d completed", task_id)


def delete_alias(client: OvhClient, alias_suffix: str, domain: str) -> int | None:
    alias = full_alias(alias_suffix, domain=domain)
    try:
        r = client.delete(alias=alias)
    except ovh.exceptions.APIError as ex:
        handle_failed_operation(client=client, ex=ex, alias_email=alias)
        return None
    logger.debug("Successfully deleted alias %s: %s", LazyQuote(alias), r)
    if isinstance(r, dict):
        return r.get('id')
    logger.warning("deleting alias %s did not return a dict!: %s", LazyQuote(alias), r)
    return None


def delete_aliases(client: OvhClient, to_delete: set[str], domain: str) -> list[int]:
    logger.debug("need to delete %d entries: %s", len(to_delete), to_delete)
    return [
        task_id
        for alias_suffix in to_delete
        if (task_id := delete_alias(client=client, domain=domain, alias_suffix=alias_suffix))
    ]


def wait_for_tasks(client: OvhClient, tasks: list[int], warn_after: float, long_delay: float) -> None:
    start = time.time()
    logger.debug("waiting for %d tasks warning after %0.1fs: %s", len(tasks), warn_after, tasks)
    for task_id in tasks:
        wait_for_task(client=client, task_id=task_id, start=start, warn_after=warn_after, long_delay=long_delay)


def check_not_too_many(changes: set[str], limit: int, op: str) -> None:
    if changes:
        count = len(changes)
        if count > limit:
            logger.critical(
                "refusing %s of %d aliases as more than the limit of %d: %s",
                op, count, limit, shlex.join(changes))
            sys.exit(87)
        logger.debug("accepting %d %s as not greater than limit of %d", count, op, limit)


def run_sync() -> bool:
    parser = argparse.ArgumentParser(description="Create and delete email aliases on OVH")
    add_loglevel_arguments(parser=parser)
    parser.add_argument('-c', '--config', type=pathlib.Path, required=True, help='JSON configuration for OVH')
    parser.add_argument('--long-delay', type=float, default=30, help='per request delay after warning timeout')
    parser.add_argument('--per-second', type=float, default=10, help='requests to issue per second')
    parser.add_argument('--warn-after', type=float, default=30, help='delay before warning')
    parser.add_argument('--count', type=int, help='assert input contains this many aliases')
    options = parser.parse_args()

    set_logging_level(options=options)
    cfg: AppConfig = load_config(config_path=options.config.expanduser())

    domain = cfg['domain']
    desired_aliases = get_words_from_stdin(cfg)
    if options.count is not None and options.count != len(desired_aliases):
        logger.critical("expected %d aliases but read %d", options.count, len(desired_aliases))
        sys.exit(63)
    desired_aliases.discard(cfg['target_user'])

    client = OvhClient(cfg, per_second=options.per_second)
    start = time.time()
    existing_aliases = get_aliases(client=client, domain=domain)

    to_create = desired_aliases - existing_aliases
    to_delete = existing_aliases - desired_aliases
    check_not_too_many(changes=to_create, limit=cfg['maximum_creations'], op='creation')
    check_not_too_many(changes=to_delete, limit=cfg['maximum_deletions'], op='deletion')
    create_tasks = create_aliases(client=client, to_create=to_create, domain=domain)
    delete_tasks = delete_aliases(client=client, to_delete=to_delete, domain=domain)
    wait_for_tasks(
        client=client, tasks=create_tasks + delete_tasks, warn_after=options.warn_after, long_delay=options.long_delay)
    status = len(to_create) + len(to_delete) == len(create_tasks) + len(delete_tasks)
    logger.info(
        "Sync of email aliases to OVH %s in %.1fs: %d created %d deleted %d total",
        "OK" if status else "FAILED", time.time() - start, len(to_create), len(to_delete), len(desired_aliases))
    return status


if __name__ == "__main__":
    sys.exit(0 if run_sync() else 79)
