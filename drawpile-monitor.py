#!/usr/bin/env python
# Copyright (c) 2023 askmeaboutloom
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
import argparse
import better_profanity
import configparser
import contextlib
import functools
import logging
import os
import random
import requests
import signal
import sqlite3
import sys
import time

logging.basicConfig(
    level=getattr(logging, os.environ.get("DRAWPILE_MONITOR_LOG_LEVEL", "WARNING"))
)


@functools.lru_cache(maxsize=1024)
def is_offensive(s):
    import profanity_check

    logging.debug("Checking profanity of '%s'", s)
    return profanity_check.predict([s])[
        0
    ] or better_profanity.profanity.contains_profanity(s)


class Config:
    def __init__(self, config_path):
        if not config_path:
            config_path = self._relative_to_script("config.ini")
        self._has_error = False
        parser = configparser.ConfigParser()
        if not parser.read(config_path):
            raise ValueError(f"Can't parse config '{config_path}'")

        self._read(parser, "config", "base_url", "base_url")
        self._read(parser, "config", "discord_webhook_url", "discord_webhook_url", None)
        self._read(
            parser,
            "config",
            "database_path",
            "database_path",
            self._relative_to_script("drawpile-monitor.db"),
        )
        self._read(parser, "config", "wordlist_path", "wordlist_path", None)
        self._read(
            parser,
            "config",
            "max_error_streak_before_report",
            "reportable_error_streak",
            convert=int,
        )
        self._read(
            parser,
            "messages",
            "session_name_first_warning",
            "message_session_name_first_warning",
        )
        self._read(
            parser,
            "messages",
            "session_name_second_warning",
            "message_session_name_second_warning",
        )
        self._read(
            parser,
            "messages",
            "session_name_terminate",
            "message_session_name_terminate",
        )
        self._read(
            parser,
            "messages",
            "session_alias_terminate",
            "message_session_alias_terminate",
        )
        self._read(parser, "messages", "user_kick", "message_user_kick")

        if self._has_error:
            raise ValueError("Invalid configuration")

    @staticmethod
    def _relative_to_script(file):
        return os.path.join(os.path.dirname(os.path.realpath(__file__)), file)

    def _read(self, parser, config_section, config_key, attr_key, fallback=..., convert=...):
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

    def send_report(self, message):
        if self._discord_webhook_url:
            requests.post(
                self._discord_webhook_url,
                json={
                    "content": message,
                    "flags": 1 << 2,  # suppress embeds
                },
            )
        else:
            logging.debug("No Discord webhook url, not reporting anything")


class Database:
    def __init__(self, dry, config):
        self._dry = dry
        path = config.database_path
        logging.debug("Opening database '%s'", path)
        self._con = sqlite3.connect(path)
        self._create_tables()

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
                create table if not exists user_offense (
                    id integer primary key not null,
                    inserted_at text not null default current_timestamp,
                    name text not null,
                    ip text not null,
                    offense text not null,
                    mitigation text not null)
                """
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

    def insert_user_offense(self, user_name, user_ip, offense, mitigation):
        if not self._dry:
            with self._con as con:
                con.execute(
                    """
                    insert into user_offense(name, ip, offense, mitigation)
                    values (?, ?, ?, ?)
                    """,
                    (user_name, user_ip, offense, mitigation),
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
    def __init__(self, dry, config, api, db):
        self._dry = dry
        self._config = config
        self._api = api
        self._db = db
        self._reports = []
        self._error_streak = 0

    def _append_report(self, message):
        if self._reports:
            new_report = self._reports[-1] + "\n" + message
            if len(new_report.encode()) > 1500:
                self._reports.append(message)
            else:
                self._reports[-1] = new_report
        else:
            self._reports.append(message)

    # Sessions

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

    def _handle_offensive_session_name(self, session_id, offense):
        past_offenses = self._db.count_session_offenses_by_session_id(session_id)
        if past_offenses == 0:
            self._manipulate_offensive_session(
                session_id,
                offense,
                "warn nicely, rename session",
                self._config.message_session_name_first_warning,
                False,
            )
        elif past_offenses == 1:
            self._manipulate_offensive_session(
                session_id,
                offense,
                "warn threateningly, rename session",
                self._config.message_session_name_second_warning,
                False,
            )
        else:
            self._manipulate_offensive_session(
                session_id,
                offense,
                "terminate session",
                self._config.message_session_name_terminate,
                True,
            )

    def _check_session(self, session):
        session_id = session["id"]
        logging.debug("Check session %s", session_id)

        session_title = session["title"]
        session_alias = session.get("alias")
        if session_alias and is_offensive(session_alias):
            logging.warning("Session alias is offensive: %s", session)
            self._manipulate_offensive_session(
                session_id,
                f"offensive alias '{session_alias}'",
                "terminate session",
                self._config.message_session_alias_terminate,
                True,
            )

        if is_offensive(session_title):
            logging.warning("Session is offensive: %s", session)
            self._handle_offensive_session_name(
                session_id, f"offensive title '{session_title}'"
            )
        else:
            logging.debug("Session title '%s' is okay", session_title)

    # Users

    def _handle_offensive_user(self, user, offense, mitigation):
        user_name = user["name"]
        user_ip = user["ip"]
        user_id = user["id"]
        session_id = user["session"]
        logging.warning("user %s at %s: %s", user_name, user_ip, mitigation)
        self._db.insert_user_offense(user_name, user_ip, offense, mitigation)
        self._api.update_session(
            session_id,
            {"alert": self._config.message_user_kick},
        )
        self._api.kick_user(session_id, user_id)
        self._append_report(f"User {user_name}: {offense} - {mitigation}")

    def _check_user(self, user):
        user_name = user["name"]
        if user.get("mod"):
            logging.debug("User '%s' is mod", user_name)
        elif is_offensive(user_name):
            logging.warning("User is offensive: %s", user)
            self._handle_offensive_user(
                user, f"offensive name '{user_name}'", "warn in session, kick user"
            )
        else:
            logging.debug("User name '%s' is okay", user_name)

    # Main entry

    def check(self):
        have_error = False
        report_errors = self._error_streak == self._config.reportable_error_streak
        logging.debug("%s %s %s", report_errors, self._error_streak, self._config.reportable_error_streak)

        try:
            sessions = self._api.get_sessions()
        except Exception:
            sessions = []
            logging.exception("Error retrieving sessions altogether")
            have_error = True
            if report_errors:
                self._append_report("Error retrieving sessions")

        for session in sessions:
            with InterruptDisabled():
                try:
                    self._check_session(session)
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
                    self._check_user(user)
                except Exception:
                    logging.exception("Error checking user %s", user)
                    have_error = True
                    if report_errors:
                        self._append_report(f"Error checking user {user}")

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
    username = os.environ.get("DRAWPILE_MONITOR_USER")
    if not username:
        log.critical("DRAWPILE_MONITOR_USER environment variable not set")

    password = os.environ.get("DRAWPILE_MONITOR_PASS")
    if not password:
        log.critical("DRAWPILE_MONITOR_PASS environment variable not set")

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

    if not username or not password:
        logging.critical("Don't have a web admin username and password, stopping")
        sys.exit(2)

    config = Config(args.config)

    better_profanity.profanity.load_censor_words()
    if config.wordlist_path:
        logging.debug("Loading wordlist %s", config.wordlist_path)
        better_profanity.profanity.add_censor_words(
            list(better_profanity.utils.read_wordlist(config.wordlist_path))
        )

    dry = args.dryrun
    interval = args.interval
    jitter = args.jitter
    api = Api(dry, config, username, password)
    db = Database(dry, config)
    monitor = Monitor(dry, config, api, db)
    while True:
        monitor.check()
        monitor.report()
        if interval > 0:
            sleep_time = interval + random.randint(0, jitter)
            logging.debug("Sleeping for %d second(s)", sleep_time)
            time.sleep(sleep_time)
        else:
            break
