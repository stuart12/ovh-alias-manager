# Sync email aliases from password files to OVH

Python tools to manage email aliases using a [pass](https://www.passwordstore.org/) (password-store) backend
and the [OVH](https://www.ovhcloud.com) API.
The ovh-alias-mananger decrypts your passwords looking for jqp\d\d\d\d\d\d\d@example.net.
If the email address is preceeded by `unalias` the alias address is noted as having being withdrawn and will not be reused.
Otherwise an alias is created on OVH.  The `--create` option is used to create new aliases.  New aliases take a while
to become active so create them in advance.

## configuration file
An example configuration file for John Q. Public:
```json
{
    "prefix": "jqp",
    "ignore": "john",
    "unalias": "unalias:",
    "domain": "example.net",
    "target_user": "john",
    "ignored_dirs": ["Recycle-Bin", "Wifi-AP"],
    "service": "mxplan-xxxxxxx-1",
    "minimum_length": 3,
    "maximum_deletions": 36,
    "maximum_creations": 24,
    "ovh_config": {
        "endpoint": "ovh-us",
        "application_key": "xxxxxxxxxxxxxxxx",
        "application_secret": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        "consumer_key": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    }
}
```

---
Copyright (C) 2026 Stuart Pook — licensed under [GPLv3](LICENSE).
