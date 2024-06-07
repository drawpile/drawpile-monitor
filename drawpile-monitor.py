#!/usr/bin/env python
# SPDX-License-Identifier: MIT
import argparse
import better_profanity
import configparser
import contextlib
import enum
import functools
import logging
import os
import random
import re
import requests
import signal
import sqlite3
import sys
import time

logging.basicConfig(
    level=getattr(logging, os.environ.get("DRAWPILE_MONITOR_LOG_LEVEL", "WARNING"))
)


def init_profanity_checker(wordlist_path, nsfm_wordlist_path):
    better_profanity.profanity.load_censor_words()
    for path in [wordlist_path, nsfm_wordlist_path]:
        if path:
            logging.debug("Loading wordlist %s", path)
            better_profanity.profanity.add_censor_words(
                list(better_profanity.utils.read_wordlist(path))
            )


def init_filter_allowed(allowlist_path):
    global filter_allowed

    filter_allowed = lambda s: s

    if allowlist_path:
        logging.debug("Loading allowlist %s", allowlist_path)
        allowed_words = list(better_profanity.utils.read_wordlist(allowlist_path))
        if allowed_words:
            escaped_words = "|".join(map(re.escape, allowed_words))
            allowed_re = re.compile(
                f"(?:\\b|(?<=_))(?:{escaped_words})(?:\\b|(?=_))", re.IGNORECASE
            )
            logging.debug("Allowed re: /%s/", allowed_re)

            def filter_allowed_fn(s):
                return re.sub(allowed_re, "", s)

            filter_allowed = filter_allowed_fn


def init_is_offensive(min_offensive_probability):
    global is_offensive

    @functools.lru_cache(maxsize=16384)
    def is_offensive_fn(s):
        logging.debug("Checking profanity of '%s'", s)
        filtered = filter_allowed(s)
        return (
            is_offensive_better_profanity(filtered)
            or is_offensive_profanity_check(filtered) >= min_offensive_probability
        )

    is_offensive = is_offensive_fn


def init_is_offensive_nsfm(nsfm_wordlist_path):
    global is_offensive_nsfm

    is_offensive_nsfm = lambda s: False
    if nsfm_wordlist_path:
        logging.debug("Loading nsfm wordlist %s", nsfm_wordlist_path)
        words = list(better_profanity.utils.read_wordlist(nsfm_wordlist_path))
        if words:
            nsfm_profanity = better_profanity.Profanity(words)

            @functools.lru_cache(maxsize=16384)
            def is_offensive_nsfm_fn(s):
                logging.debug("Checking nsfm profanity of '%s'", s)
                filtered = filter_allowed(s)
                return nsfm_profanity.contains_profanity(s)

            is_offensive_nsfm = is_offensive_nsfm_fn


def is_offensive_better_profanity(s):
    return better_profanity.profanity.contains_profanity(s)


def is_offensive_profanity_check(s):
    import profanity_check

    return profanity_check.predict_prob([s])[0]


def init_is_offensive_silent(silent_wordlist_path):
    global is_offensive_silent

    is_offensive_silent = lambda s: False
    if silent_wordlist_path:
        logging.debug("Loading silent wordlist %s", silent_wordlist_path)
        words = list(better_profanity.utils.read_wordlist(silent_wordlist_path))
        if words:
            silent_profanity = better_profanity.Profanity(words)

            @functools.lru_cache(maxsize=16384)
            def is_offensive_silent_fn(s):
                logging.debug("Checking silent profanity of '%s'", s)
                return silent_profanity.contains_profanity(s)

            is_offensive_silent = is_offensive_silent_fn
            return True

    return False


class HandleNsfm(enum.Enum):
    FULL = 1
    RELAXED = 2

    @classmethod
    def convert_from_string(cls, s):
        sc = s.casefold()
        if sc == "full":
            return cls.FULL
        elif sc == "relaxed":
            return cls.RELAXED
        else:
            raise ValueError(f"Unknown handle_nsfm value '{s}'")


class NoticeFlags(enum.IntEnum):
    OUTDATED = 0x1


def _convert_bool(s):
    return s.casefold() not in ["false", "f", "no", "0", ""]


def _convert_discord_ids(s):
    if s:
        if re.search(r"\A\s*[0-9]+\s*(?:,\s*[0-9]+\s*)*\Z", s):
            return [id.strip() for id in s.split(",")]
        else:
            raise ValueError(f"Invalid id list: {s}")


class Config:
    def __init__(self, config_path, test_profanity_only=False):
        if not config_path:
            config_path = self._relative_to_script("config.ini")
        self._has_error = False
        parser = configparser.ConfigParser()
        if not parser.read(config_path):
            raise ValueError(f"Can't parse config '{config_path}'")

        if not test_profanity_only:
            self._read(parser, "config", "base_url", "base_url")
            self._read(
                parser, "config", "discord_webhook_url", "discord_webhook_url", None
            )
            self._read(
                parser,
                "config",
                "database_path",
                "database_path",
                self._relative_to_script("drawpile-monitor.db"),
            )
            self._read(
                parser,
                "config",
                "handle_nsfm",
                "handle_nsfm",
                HandleNsfm.FULL,
                lambda s: HandleNsfm.convert_from_string(s),
            )
            self._read(
                parser,
                "config",
                "nsfm_users_in_passworded_sessions",
                "nsfm_users_in_passworded_sessions",
                False,
                convert=_convert_bool,
            )
            self._read(
                parser,
                "config",
                "silent_user_mentions",
                "silent_user_mentions",
                [],
                convert=_convert_discord_ids,
            )
            self._read(
                parser,
                "config",
                "silent_role_mentions",
                "silent_role_mentions",
                [],
                convert=_convert_discord_ids,
            )
            self._read(
                parser,
                "config",
                "max_error_streak_before_report",
                "reportable_error_streak",
                convert=int,
            )
            self._read(
                parser,
                "config",
                "warn_outdated_sessions",
                "warn_outdated_sessions",
                False,
                convert=_convert_bool,
            )

            message_keys = [
                "session_name_first_warning",
                "session_name_second_warning",
                "session_name_terminate",
                "session_alias_terminate",
                "session_founder_terminate",
                "user_kick",
                "session_outdated",
            ]
            for message_key in message_keys:
                message_attr = f"message_{message_key}"
                self._read(parser, "messages", message_key, message_attr)
                self._read(
                    parser,
                    "messages",
                    message_key + "_nsfm",
                    message_attr + "_nsfm",
                    getattr(self, message_attr),
                )

        self._read(parser, "config", "wordlist_path", "wordlist_path", None)
        self._read(parser, "config", "nsfm_wordlist_path", "nsfm_wordlist_path", None)
        self._read(parser, "config", "allowlist_path", "allowlist_path", None)
        self._read(
            parser, "config", "silent_wordlist_path", "silent_wordlist_path", None
        )
        self._read(
            parser,
            "config",
            "min_offensive_probability",
            "min_offensive_probability",
            0.9,
            convert=lambda v: float(v) / 100.0,
        )

        if self._has_error:
            raise ValueError("Invalid configuration")

    @staticmethod
    def _relative_to_script(file):
        return os.path.join(os.path.dirname(os.path.realpath(__file__)), file)

    def _read(
        self, parser, config_section, config_key, attr_key, fallback=..., convert=...
    ):
        try:
            value = parser[config_section][config_key]
            if len(value) > 0:
                if convert is not Ellipsis:
                    value = convert(value)
                setattr(self, attr_key, value)
            else:
                raise KeyError()
        except KeyError:
            if fallback is Ellipsis:
                logging.critical(
                    "[%s][%s] not found in config", config_section, config_key
                )
                self._has_error = True
            else:
                logging.debug(
                    "[%s][%s] not found in config, using fallback %s",
                    config_section,
                    config_key,
                    repr(fallback),
                )
                setattr(self, attr_key, fallback)

    def get_message(self, key, nsfm=False):
        return getattr(self, f"message_{key}_nsfm" if nsfm else f"message_{key}")


class Api:
    def __init__(self, dry, config, username, password):
        self._dry = dry
        self._base_url = config.base_url
        self._discord_webhook_url = config.discord_webhook_url
        self._auth = (username, password)

    def _make_url(self, *args):
        path = "/".join(requests.utils.quote(str(s)) for s in args)
        return f"{self._base_url}/api/{path}"

    def get_sessions(self):
        return requests.get(self._make_url("sessions"), auth=self._auth).json()

    def get_users(self):
        return requests.get(self._make_url("users"), auth=self._auth).json()

    def update_session(self, session_id, body):
        if not self._dry:
            return requests.put(
                self._make_url("sessions", session_id), auth=self._auth, json=body
            ).json()

    def terminate_session(self, session_id):
        if not self._dry:
            return requests.delete(
                self._make_url("sessions", session_id), auth=self._auth
            ).json()

    def kick_user(self, session_id, user_id):
        if not self._dry:
            return requests.delete(
                self._make_url("sessions", session_id, user_id), auth=self._auth
            ).json()

    def can_send_reports(self):
        return bool(self._discord_webhook_url)

    def send_report(self, message):
        if self.can_send_reports():
            self.send_notification(message)
        else:
            logging.debug("No Discord webhook url, not reporting anything")

    def send_notification(self, message, user_mentions=None, role_mentions=None):
        requests.post(
            self._discord_webhook_url,
            json={
                "content": message,
                "flags": 1 << 2,  # suppress embeds
                "allowed_mentions": {
                    "parse": [],
                    "users": user_mentions if user_mentions else [],
                    "roles": role_mentions if role_mentions else [],
                },
            },
        )


class Database:
    def __init__(self, dry, config):
        self._dry = dry
        path = config.database_path
        logging.debug("Opening database '%s'", path)
        self._con = sqlite3.connect(path)
        self._create_tables()
        self._apply_migrations()

    def _create_tables(self):
        with self._con as con:
            con.execute(
                """
                create table if not exists session_offense (
                    id integer primary key not null,
                    inserted_at text not null default current_timestamp,
                    session_id text not null,
                    offense text not null,
                    mitigation text not null)
                """
            )
            con.execute(
                """
                create index if not exists
                    session_offense_session_id_idx
                    on session_offense (session_id)
                """
            )
            con.execute(
                """
                create table if not exists user_offense (
                    id integer primary key not null,
                    inserted_at text not null default current_timestamp,
                    name text not null,
                    ip text not null,
                    offense text not null,
                    mitigation text not null)
                """
            )
            con.execute(
                """
                create table if not exists session_notices (
                    session_id text not null,
                    flags integer not null)
                """
            )
            con.execute(
                """
                create table if not exists session_silent_notification (
                    id integer primary key not null,
                    inserted_at text not null default current_timestamp,
                    session_id text not null,
                    offense text not null)
                """
            )
            con.execute(
                """
                create unique index if not exists
                    session_silent_notification_session_id_offense_idx
                    on session_silent_notification (session_id, offense)
                """
            )
            con.execute(
                """
                create table if not exists migrations (
                    id integer primary key not null)
                """
            )

    def _apply_migrations(self):
        migrations = [
            (
                1,
                [
                    """
                    alter table user_offense
                        add column sid text
                    """,
                    """
                    alter table user_offense
                        add column is_registered integer not null default 0
                    """,
                ],
            ),
        ]
        for migration_id, sqls in migrations:
            with self._con as con:
                cur = con.execute("begin")
                cur.execute("select 1 from migrations where id = ?", (migration_id,))
                if not cur.fetchone():
                    for sql in sqls:
                        cur.execute(sql)
                    cur.execute(
                        "insert into migrations (id) values (?)", (migration_id,)
                    )

    def count_session_offenses(self):
        with contextlib.closing(self._con.cursor()) as cur:
            cur.execute("select count (*) from session_offense")
            return cur.fetchone()[0]

    def count_session_offenses_by_session_id(self, session_id):
        with contextlib.closing(self._con.cursor()) as cur:
            cur.execute(
                "select count (*) from session_offense where session_id = ?",
                (session_id,),
            )
            return cur.fetchone()[0]

    def insert_session_offense(self, session_id, offense, mitigation):
        if not self._dry:
            with self._con as con:
                con.execute(
                    """
                    insert into session_offense(session_id, offense, mitigation)
                    values (?, ?, ?)
                    """,
                    (session_id, offense, mitigation),
                )

    def insert_user_offense(
        self, user_name, user_ip, user_sid, user_is_registered, offense, mitigation
    ):
        if not self._dry:
            with self._con as con:
                con.execute(
                    """
                    insert into user_offense(name, ip, sid, is_registered, offense, mitigation)
                    values (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        user_name,
                        user_ip,
                        user_sid,
                        1 if user_is_registered else 0,
                        offense,
                        mitigation,
                    ),
                )

    def has_session_silent_notification(self, session_id, offense):
        with contextlib.closing(self._con.cursor()) as cur:
            cur.execute(
                """
                select 1 from session_silent_notification
                where session_id = ? and offense = ?
                """,
                (session_id, offense),
            )
            return bool(cur.fetchone())

    def insert_session_silent_notification(self, session_id, offense):
        if not self._dry:
            with self._con as con:
                con.execute(
                    """
                    insert into session_silent_notification (session_id, offense)
                    values (?, ?)
                    """,
                    (session_id, offense),
                )

    def get_session_notices(self):
        session_notices = {}
        with contextlib.closing(self._con.cursor()) as cur:
            cur.execute("select session_id, flags from session_notices")
            while row := cur.fetchone():
                session_notices[row[0]] = row[1]
        return session_notices

    def replace_session_notices(self, session_notices):
        if not self._dry:
            params = []
            for session_id, notice_flags in session_notices.items():
                params.append({"session_id": session_id, "flags": notice_flags})
            with self._con as con:
                cur = con.execute("begin")
                cur.execute("delete from session_notices")
                cur.executemany(
                    """
                    insert into session_notices (session_id, flags)
                    values (:session_id, :flags)
                    """,
                    params,
                )


class InterruptDisabled:
    def __init__(self):
        self._received_interrupt = False

    def _handle_signal(self, *args):
        self._received_interrupt = True
        logging.critical("Ate interrupt signal, terminating soon")

    def __enter__(self, *args):
        signal.signal(signal.SIGINT, self._handle_signal)
        return self

    def __exit__(self, *args):
        signal.signal(signal.SIGINT, signal.SIG_DFL)
        if self._received_interrupt:
            raise KeyboardInterrupt("Finally interrupting")


class Monitor:
    def __init__(self, dry, config, api, db, have_silent_wordlist):
        self._dry = dry
        self._config = config
        self._api = api
        self._db = db
        self._have_silent_notifications = (
            have_silent_wordlist and api.can_send_reports()
        )
        self._reports = []
        self._error_streak = 0
        if dry:
            self._reports_dedupe = set()

    def _append_report(self, message):
        if dry:
            if message in self._reports_dedupe:
                logging.debug("Skipping duplicate notification: %s", message)
                return
            self._reports_dedupe.add(message)

        if self._reports:
            new_report = self._reports[-1] + "\n" + message
            if len(new_report.encode()) > 1500:
                self._reports.append(message)
            else:
                self._reports[-1] = new_report
        else:
            self._reports.append(message)

    def _get_offensive_fn(self, nsfm):
        if nsfm and self._config.handle_nsfm == HandleNsfm.RELAXED:
            return is_offensive_nsfm
        else:
            return is_offensive

    # Sessions

    def _send_session_silent_notification(self, session_id, offense):
        if self._db.has_session_silent_notification(session_id, offense):
            logging.debug("Session already has silent notification, skipping")
        else:
            prefix = ""
            if self._dry:
                if offense in self._reports_dedupe:
                    logging.debug("Skipping duplicate silent notification: %s", offense)
                    return
                self._reports_dedupe.add(offense)
                prefix += "**DRY RUN** "

            user_mentions = self._config.silent_user_mentions
            for user_mention in user_mentions:
                prefix += f"<@{user_mention}> "

            role_mentions = self._config.silent_role_mentions
            for role_mention in role_mentions:
                prefix += f"<@&{role_mention}> "

            self._api.send_notification(
                f"{prefix}**Attention required:** {offense}, session id `{session_id}`",
                user_mentions=user_mentions,
                role_mentions=role_mentions,
            )

            self._db.insert_session_silent_notification(session_id, offense)

    def _check_session_silent_notification(
        self, session_id, session_title, session_alias, session_founder
    ):
        if self._have_silent_notifications:
            if is_offensive_silent(session_title):
                self._send_session_silent_notification(
                    session_id,
                    f"title of session '{session_title}'",
                )
                return True
            elif session_alias and is_offensive_silent(session_alias):
                self._send_session_silent_notification(
                    session_id,
                    f"alias '{session_alias}' of session '{session_title}'",
                )
                return True
            elif session_founder and is_offensive_silent(session_founder):
                self._send_session_silent_notification(
                    session_id,
                    f"founder '{session_founder}' of session '{session_title}'",
                )
                return True
        return False

    def _generate_clean_title(self):
        # The number of offenses is a reasonably unique and small number.
        return f"Session #{self._db.count_session_offenses()}"

    def _manipulate_offensive_session(
        self, session_id, offense, mitigation, alert, terminate
    ):
        logging.warning("session %s: %s", session_id, mitigation)
        self._db.insert_session_offense(session_id, offense, mitigation)
        self._api.update_session(
            session_id,
            {
                "alert": alert,
                "title": self._generate_clean_title(),
            },
        )
        if terminate:
            self._api.terminate_session(session_id)
        self._append_report(f"Session {session_id}: {offense} - {mitigation}")

    def _handle_offensive_session_name(self, session_id, offense, nsfm):
        past_offenses = self._db.count_session_offenses_by_session_id(session_id)
        if past_offenses == 0:
            self._manipulate_offensive_session(
                session_id,
                offense,
                "warn nicely, rename session",
                self._config.get_message("session_name_first_warning", nsfm),
                False,
            )
        elif past_offenses == 1:
            self._manipulate_offensive_session(
                session_id,
                offense,
                "warn threateningly, rename session",
                self._config.get_message("session_name_second_warning", nsfm),
                False,
            )
        else:
            self._manipulate_offensive_session(
                session_id,
                offense,
                "terminate session",
                self._config.get_message("session_name_terminate", nsfm),
                True,
            )

    def _check_session(self, session):
        session_id = session["id"]
        logging.debug("Check session %s", session_id)

        if session.get("protocol") in ("dp:4.21.2", "dp:4.22.2", "dp:4.23.0"):
            notice_flags = NoticeFlags.OUTDATED
        else:
            notice_flags = 0

        session_title = session["title"]
        session_alias = session.get("alias", "")
        session_founder = session.get("founder", "")
        nsfm = session.get("nsfm", False)
        passworded = session.get("hasPassword", False)
        if not self._check_session_silent_notification(
            session_id, session_title, session_alias, session_founder
        ):
            offense_suffix = " (nsfm)" if nsfm else ""
            check_offensive = self._get_offensive_fn(nsfm)
            if session_alias and check_offensive(session_alias):
                logging.warning("Session alias is offensive: %s", session)
                self._manipulate_offensive_session(
                    session_id,
                    f"offensive alias '{session_alias}'{offense_suffix}",
                    "terminate session",
                    self._config.get_message("session_alias_terminate", nsfm),
                    True,
                )
            elif session_founder and check_offensive(session_founder):
                logging.warning("Session founder is offensive: %s", session)
                self._manipulate_offensive_session(
                    session_id,
                    f"offensive founder '{session_founder}'{offense_suffix}",
                    "terminate session",
                    self._config.get_message("session_founder_terminate", nsfm),
                    True,
                )
            elif check_offensive(session_title):
                logging.warning("Session is offensive: %s", session)
                self._handle_offensive_session_name(
                    session_id,
                    f"offensive title '{session_title}'{offense_suffix}",
                    nsfm,
                )
            else:
                logging.debug(
                    "Session title '%s', alias '%s', founder '%s' are okay%s",
                    session_title,
                    session_alias,
                    session_founder,
                    offense_suffix,
                )

        return (session_id, nsfm, passworded, notice_flags)

    def _notify_session(self, session_id, notice_flags):
        if (notice_flags & int(NoticeFlags.OUTDATED)) != 0:
            logging.warning("Notifying outdated session %s", session_id)
            self._api.update_session(
                session_id, {"alert": self._config.get_message("session_outdated")}
            )
            self._append_report(f"Session {session_id} on old version, notifying")

    # Users

    def _handle_offensive_user(self, user, offense, mitigation, nsfm):
        user_name = user["name"]
        user_ip = user["ip"]
        user_id = user["id"]
        session_id = user["session"]
        logging.warning("user %s at %s: %s", user_name, user_ip, mitigation)
        self._db.insert_user_offense(
            user_name, user_ip, user.get("s"), user.get("auth"), offense, mitigation
        )
        self._api.update_session(
            session_id,
            {"alert": self._config.get_message("user_kick", nsfm)},
        )
        self._api.kick_user(session_id, user_id)
        self._append_report(f"User {user_name}: {offense} - {mitigation}")

    def _check_user(self, user, nsfm_sessions):
        user_name = user["name"]
        if user.get("mod"):
            logging.debug("User '%s' is mod, skipping", user_name)
            return

        session_id = user.get("session")
        if not session_id:
            logging.debug("User '%s' is not in any session, skipping", user_name)
            return

        nsfm = nsfm_sessions.get(session_id)
        if nsfm is None:
            logging.warning(
                "User '%s' is in unknown session '%s', treating as NSFM",
                user_name,
                session_id,
            )
            nsfm = True

        offense_suffix = " (nsfm)" if nsfm else ""
        check_offensive = self._get_offensive_fn(nsfm)

        if check_offensive(user_name):
            logging.warning("User is offensive: %s", user)
            self._handle_offensive_user(
                user,
                f"offensive name '{user_name}'{offense_suffix}",
                "warn in session, kick user",
                nsfm,
            )
        else:
            logging.debug("User name '%s' is okay%s", user_name, offense_suffix)

    # Main entry

    def check(self):
        have_error = False
        report_errors = self._error_streak == self._config.reportable_error_streak
        logging.debug(
            "Checking; report_errors=%s error_streak=%s reportable_error_streak=%s",
            report_errors,
            self._error_streak,
            self._config.reportable_error_streak,
        )

        warn_outdated_sessions = self._config.warn_outdated_sessions
        if warn_outdated_sessions:
            prev_session_notices = self._db.get_session_notices()
        else:
            prev_session_notices = {}

        try:
            sessions = self._api.get_sessions()
        except Exception:
            sessions = []
            logging.exception("Error retrieving sessions altogether")
            have_error = True
            if report_errors:
                self._append_report("Error retrieving sessions")

        nsfm_sessions = {}
        session_notices = {}
        for session in sessions:
            with InterruptDisabled():
                try:
                    session_id, nsfm, passworded, notice_flags = self._check_session(
                        session
                    )
                    nsfm_sessions[str(session_id)] = nsfm or (
                        passworded and self._config.nsfm_users_in_passworded_sessions
                    )
                    if notice_flags != 0:
                        session_notices[str(session_id)] = int(notice_flags)
                except Exception:
                    logging.exception("Error checking session %s", session)
                    have_error = True
                    if report_errors:
                        self._append_report(f"Error checking session {session}")
        try:
            users = self._api.get_users()
        except Exception:
            users = []
            logging.exception("Error retrieving users altogether")
            have_error = True
            if report_errors:
                self._append_report("Error retrieving users")

        for user in users:
            with InterruptDisabled():
                try:
                    self._check_user(user, nsfm_sessions)
                except Exception:
                    logging.exception("Error checking user %s", user)
                    have_error = True
                    if report_errors:
                        self._append_report(f"Error checking user {user}")

        if warn_outdated_sessions and not have_error:
            with InterruptDisabled():
                for session_id, notice_flags in session_notices.items():
                    try:
                        if session_id in prev_session_notices:
                            logging.debug("Session %s already notified", session_id)
                        else:
                            self._notify_session(session_id, notice_flags)
                    except Exception:
                        logging.exception("Error notifying session %s", session_id)
                        have_error = True
                        if report_errors:
                            self._append_report(f"Error notifying session {session_id}")
                if prev_session_notices or session_notices:
                    self._db.replace_session_notices(session_notices)

        if report_errors and have_error:
            self._append_report(
                f"There have been {self._error_streak + 1} errors in a row. "
                + "Something might be wrong with your server. "
                + "Will report when getting a good run again."
            )
        elif (
            not have_error and self._error_streak > self._config.reportable_error_streak
        ):
            self._append_report(
                "Got a good run, looks like your server is healthy again."
            )

        if have_error:
            self._error_streak += 1
        else:
            self._error_streak = 0

    def report(self):
        while self._reports:
            with InterruptDisabled():
                try:
                    message = self._reports[0]
                    if self._dry:
                        message = "**DRY RUN:** " + message
                    logging.debug("Send report %s", message)
                    self._api.send_report(message)
                    self._reports.pop(0)
                except Exception:
                    logging.exception("Error sending report to webhook")
                    break


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="Drawpile Monitor", description="Monitors sessions on a Drawpile server."
    )
    parser.add_argument(
        "-c",
        "--config",
        help="Where to find the config file",
    )
    parser.add_argument(
        "-n",
        "--dryrun",
        action=argparse.BooleanOptionalAction,
        help="Don't actually change anything, only print logs and report to Discord",
        default=False,
    )
    parser.add_argument(
        "-i",
        "--interval",
        type=int,
        help="How many seconds to wait between each request, 0 means to only do one",
        default=0,
    )
    parser.add_argument(
        "-j",
        "--jitter",
        type=int,
        help="Up to how many seconds to randomly add to the interval",
        default=0,
    )
    args = parser.parse_args()

    username = os.environ.get("DRAWPILE_MONITOR_USER")
    if not username:
        logging.critical("DRAWPILE_MONITOR_USER environment variable not set")

    password = os.environ.get("DRAWPILE_MONITOR_PASS")
    if not password:
        logging.critical("DRAWPILE_MONITOR_PASS environment variable not set")

    if not username or not password:
        logging.critical("Don't have a web admin username and password, stopping")
        sys.exit(2)

    config = Config(args.config)
    init_profanity_checker(config.wordlist_path, config.nsfm_wordlist_path)
    init_filter_allowed(config.allowlist_path)
    init_is_offensive(config.min_offensive_probability)
    init_is_offensive_nsfm(config.nsfm_wordlist_path)
    have_silent_wordlist = init_is_offensive_silent(config.silent_wordlist_path)

    dry = args.dryrun
    api = Api(dry, config, username, password)
    if have_silent_wordlist and not api.can_send_reports():
        raise ValueError("Silent wordlist given, but no URL to send notifications to")

    interval = args.interval
    jitter = args.jitter
    db = Database(dry, config)
    monitor = Monitor(dry, config, api, db, have_silent_wordlist)
    while True:
        monitor.check()
        monitor.report()
        if interval > 0:
            sleep_time = interval + random.randint(0, jitter)
            logging.debug("Sleeping for %d second(s)", sleep_time)
            time.sleep(sleep_time)
        else:
            break
