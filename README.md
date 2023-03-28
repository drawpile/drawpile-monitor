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

# LICENSE

Licensed under the MIT license, see [the LICENSE file](LICENSE) for details.

# SEE ALSO

Drawpile: <https://drawpile.net/>
