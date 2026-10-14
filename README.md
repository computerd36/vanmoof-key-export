# vanmoof-key-export

Exports the Bluetooth encryption key of VanMoof S3 and X3 e-bikes from your VanMoof
account.

Tools that talk to the bike directly over Bluetooth, such as the Home Assistant
integration [ha-vanmoof](https://github.com/BobMcGlobus/ha-vanmoof) or
[pymoof](https://github.com/quantsini/pymoof), need two values per bike:
`encryptionKey` and `userKeyId`. This script logs in with your normal VanMoof app
credentials and prints them.

## Why this exists

The existing key exporters use `https://my.vanmoof.com/api/v8`. That host no longer
resolves, so they all fail with a DNS or connection error.

The same v8 endpoints are still served from `https://api.vanmoof-api.com/v8`, which is
the host the current official app uses. Login works there with your app credentials,
including accounts that were migrated to VanMoof's new login. This script uses that
host and only falls back to the old one if the new one cannot be reached.

## Usage

Requires Python 3.9 or newer. No dependencies beyond the standard library.

```
curl -O https://raw.githubusercontent.com/computerd36/vanmoof-key-export/main/vanmoof_key_export.py
python3 vanmoof_key_export.py
```

You are asked for your email address and password. The password is read without
echo, is only sent to the VanMoof API, and is never stored or logged.

Example output:

```
Found 1 bike(s):

  Name:          My S3
  Model:         S3
  Frame number:  ASY1234567
  encryptionKey: 00112233445566778899aabbccddeeff
  userKeyId:     7
  Account MAC:   F8:8A:5E:00:11:22
```

### Options

| Option         | Description                                                         |
|----------------|---------------------------------------------------------------------|
| `--email EMAIL` | Account email address. Prompted for if omitted.                     |
| `--json FILE`  | Also write the result to `FILE`, created with permissions `0600`.   |
| `--raw`        | With `--json`, write the full `bikeDetails` from the API instead of the summary. |
| `--version`    | Print the version and exit.                                         |

The password cannot be passed as an argument on purpose, so it does not end up in your
shell history or process list.

### Exit codes

| Code | Meaning                                    |
|------|--------------------------------------------|
| 0    | Success                                    |
| 1    | Error (wrong credentials, network, etc.)   |
| 2    | Logged in, but no bikes on the account     |

## What to do with the key

- Store `encryptionKey` and `userKeyId` in your password manager. If VanMoof's API
  goes away completely, this is the only way to keep using these tools.
- ha-vanmoof: choose manual key entry during setup and enter both values.
- pymoof: pass the key and user key ID when creating the bike client.

The `macAddress` stored in the account can differ from the address the bike actually
advertises over Bluetooth. If a tool cannot find your bike by MAC, scan for it instead.

## Security

The encryption key is effectively the physical key to your bike. Anyone who has it can
unlock it and change its settings over Bluetooth.

- Never paste it into GitHub issues, forums, chats or screenshots.
- Delete JSON exports once the key is stored somewhere safe. The included `.gitignore`
  excludes `*.json` so an export cannot be committed by accident.

## Limitations

- S3 and X3 only. Other models do not use this key scheme and may have no key on the
  account.
- This uses an unofficial, undocumented API that can change or disappear at any time.

## Development

```
python3 -m unittest discover -s tests
```

The tests mock all HTTP calls and need no network access or credentials.

## Disclaimer

This project is not affiliated with, endorsed by or connected to VanMoof in any way.

## License

MIT, see [LICENSE](LICENSE).
