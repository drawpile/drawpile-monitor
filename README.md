# NAME

drawpile-monitor - automod for Drawpile servers

[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

# SYNOPSIS

Set up an environment and install the dependencies into it:

```sh
python -m venv env
. env/bin/activate
pip install -r requirements.txt
```

Copy the config file template:

```sh
cp config.template.ini config.ini
```

Open the config file and fill in the required information. There's comments
inside the file to guide you.

Now you can run this thing:

```sh
. env/bin/activate
export DRAWPILE_MONITOR_USER='<WEB ADMIN USERNAME GOES HERE>'
export DRAWPILE_MONITOR_PASS='<WEB ADMIN PASSWORD GOES HERE>'

# To do a dry-run (makes checks and reports to Discord, but does not act):
./drawpile-monitor.py --dryrun

# To run it once:
./drawpile-monitor.py

# To check every 10 seconds:
./drawpile-monitor.py --interval=10

# To check randomly between 20 and 60 seconds (to avoid counter-scripting)
./drawpile-monitor.py --interval=20 --jitter=40
```

# DESCRIPTION

This will hit drawpile-srv's web admin API and check for profanity and other
banned words in session titles, session aliases and usernames.

Sessions with bad titles will get two warnings and their tile will be changed
to a generic "Session #<number>". On the third infraction, they will be
terminated.

Sessions with bad aliases will get terminated immediately, since those can't be
changed after the fact.

Users with bad names will get kicked and the session they're in will be
notified about it.

It optionally reports the stuff it did to a Discord webhook.

## Testing Profanity

You can check what drawpile-monitor would consider offensive by running
`./test-offensive.py` and typing in the stuff you want to check. It will give
you a breakdown of the profanity check along with the final verdict based on
those.

If something is getting falsely flagged, you can use this to figure out where
it's going wrong so that you can adjust the right knobs.

## Remote Configuration

If you specify the config file to reside at a http(s) URL via the
`-c`/`--config` command-line option or the `DRAWPILE_MONITOR_CONFIG`
environment variable, the configuration will be fetched from that URL instead.
The testing script supports this as well.

The response must be a JSON object. There must be `config` and `messages` keys
at top-level. Both of them must contain objects that only contain strings as
values, matching the configuration in the INI file of those sections.

Word lists are specified as arrays of strings under the `wordlist`,
`nsfm_wordlist`, `allowlist` and `silent_wordlist` keys at top-level, all of
which are optional.

The above replace `wordlist_path`, `nsfm_wordlist_path`, `allowlist_path` or
`silent_wordlist_path` under `config`. Those will be ignored if present.

# LICENSE

Licensed under the MIT license, see [the LICENSE file](LICENSE) for details.

# SEE ALSO

Drawpile: <https://drawpile.net/>
