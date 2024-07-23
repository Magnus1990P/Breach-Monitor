# Breach-Monitor
Utilises HaveIBeenPwnd API with a subscription to query a set of email addresses.

Emails can be sourced from multiple MS365 using graph API with cert based auth or manually supplied.

The utility maintains its state during runtime and after completed scan, as to not report multiple times.  
It is also possible to create tickets to a freshservice instance.

NB! incomplete scan status is stored as `.runtime-`-files.  
NB! Previous scan state is stored as `.backup-` files

The [./report.ipynb] exports the current state file to Excel formatted spreadsheet with two worksheets.
It also depicts a chart of the more critical exposures discovered.

## Usage
Example usage command  
```
python3 monitor.py -d "../data" --fresh-domain=DOMAIN.TLD \
                    --hibp-key "HAVE_I_BEEN_PWND_API_KEY" \
                    --passphrase "PRIVATE_KEY_PASSPHRASE" \
                    --fresh-key "FRESHSERVICE_API_KEY" \
                    --quiet --force
```

Help menu  
```
$ python3 monitor.py --help
Usage: monitor.py [OPTIONS]
Options:
  -d, --directory TEXT  Path of data directory
  --fresh-domain TEXT   FQDN of ticketing system endpoint
  --passphrase TEXT     Passphrase for private key
  --hibp-key TEXT       API key for HIBP
  --fresh-key TEXT      API key for FreshService instance
  -q, --quiet           Skip ticket generation
  -f, --force           Force lookup, ignoring last scanned time
  --help                Show this message and exit.
```