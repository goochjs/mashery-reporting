'''
Editable configuration items

Created on 5 Sep 2014

@author: GOOCHJ
'''

## Mashery keys
## - need to be for Mashery's own API
## - need to be associated with a user with appropriate rights in the Mashery portal
APIKEY             = "YOURKEY"
SECRET             = "YOURSECRET"

## Mashery service ID
SERVICEID          = "YOURSERVICEID"

## Maximum number of calls per second that Mashery will allow
THROTTLE           = 2

## Length of API keys issued to consumers and length we will show in output reports
APIKEY_LEN         = 24
APIKEY_DISPLAY_LEN = 6

## Delimiter and format used in calls to Mashery's API
DELIMITER          = ","
FORMAT             = "json"

## Pagination settings to use to page through large API resultsets
ITEMS_PER_PAGE     = 1000

## default proxy IP address and port (if needed)
PROXY              = "YOURCORPORATEPROXY:PORT"

## Base URLs for the API calls to Mashery
MASHERY_URL_CALLS  = "https://api.mashery.com/v2/rest/244/reports/calls/developer_activity/service/"
MASHERY_URL_QUERY  = "https://api.mashery.com/v2/json-rpc/244"

## How unknown consumers are named in Mashery output reports
UNKNOWN            = "unknown"

