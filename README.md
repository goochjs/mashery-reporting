mashery-reporting
=================

Script to query a Mashery account and list users, applications, key usage statistics, etc

Written and tested with Python v3.4.0

```
usage: python3 MasheryReporting.py [-h]
                           [--proxy PROXY] [--id ID] [--password PASSWORD]
                           --mode {getapp,listkeys,usage}
                           [--from_date FROM_DATE] [--to_date TO_DATE]
                           [--key KEY]
```

Configuration
-------------

Alongside the main script file (`MasheryReporting.py`) you will find a configuration file (`Config.py`).  This should reside in the same directory as the main script.  The minimum elements you will need to set are:-
* APIKEY - this is your API key for the Mashery reporting API
* SECRET - this is the shared secret for your API key
* SERVICEID - this is your Mashery account's service ID.  It is found in your Mashery portal, on the *Overview* tab of the service's API configuration.

I think that the other configuration items are self-explanatory and very probably won't need to be changed.

Authorisation
-------------

Depending on the mode you want to run, the Mashery user ID associated with the API key you're running the script under will need to have the appropriate role in your portal (e.g. *Administrator*, *Community Manager*, *Reports User*, *API Manager*).

Running from inside a corporate network
---------------------------------------

If running from behind a corporate proxy firewall, you can set your proxy server via the `--proxy` parameter.  Or, if you want to configure once for your site to make sharing configuration between users easier, you can set the proxy IP and port within the Config script file and then set `--proxy=default` on the command line.  Note that the parameters `--id` and `--password` are for your credentials to get through the proxy server, if necessary.

And if you're not running from behind a corporate proxy, you can ignore the above paragraph.

Mode - getapp
-------------

In this mode, you also specify the parameter `--key` and the script will retrieve the username and application associated with the key.

Mode - listkeys
---------------

In this mode, the script will retrieve a list of all keys and their associated users and applications.

Mode - usage
------------

In this mode, the script will return some usage statistics for a particular service (as set in the Config file) across the given date range (from `--from_date` to `--to-date`).  If the date parameters are not set, the script will return details for yesterday.

The dates should take the format - `YYYY-MM-DDThh:mm:ssZ`.

Obfuscation
-----------

Because I don't like exposing keys if at all possible, note that all keys written to the script's output have only the last six characters shown.  This should be enough to match them for reporting purposes.
  
