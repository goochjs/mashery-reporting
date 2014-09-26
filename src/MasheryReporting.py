'''
Created on 5 Sep 2014

@author: GOOCHJ
'''
import Config
import urllib.request
from urllib.error import URLError
import argparse
import datetime, calendar, time
import sys
import hashlib
import json
from json import JSONEncoder


class mashery(object):
    
    def __init__(self, proxy_server):
        self.proxy_server = proxy_server
        self.call_counter = -1
        
        
    def check_throttle(self):
        '''Internal method to slow API call rate to within allowable throttle (calls per second)'''
        
        # if it's the first call, then set up the initial throttle timer
        if self.call_counter == -1:
            self.timer = datetime.datetime.utcnow()
            self.call_counter = 0

        self.call_counter = self.call_counter + 1
        
        # calculate the time elapsed since the timer was last started
        temp_time = datetime.datetime.utcnow()
        time_diff = temp_time - self.timer
        
        # if it's more than a second since the last call, reset the counter and store the time
        if time_diff.total_seconds() > 1:
            self.call_counter = 0
            self.timer = datetime.datetime.utcnow()
        else:
            # if the throttle has been exceeded then pause for a second
            if self.call_counter > Config.THROTTLE:
                log("Call rate (" +
                    str(self.call_counter) +
                    " calls in " +
                    str(time_diff.total_seconds()) +
                    " seconds) over throttle, pausing briefly")
                time.sleep(1)
                self.call_counter = 0
        


    def call(self, url, json_request, headers):
        self.check_throttle()
        
        # TODO check config when proxy not required
        if self.proxy_server is not None:
            proxy = urllib.request.ProxyHandler({"http": self.proxy_server})
            auth = urllib.request.HTTPBasicAuthHandler()
            opener = urllib.request.build_opener(proxy, auth, urllib.request.HTTPHandler)
            urllib.request.install_opener(opener)

        req = urllib.request.Request(
                                 url,
                                 data=json_request.encode('utf-8'),
                                 headers=headers
                                 )
        try:        
            connection = urllib.request.urlopen(req)
            return(json.loads(connection.read().decode('utf8')))
        except URLError as e:
            log("Error accessing " + url)
            stop("%s" % e, -1)


def process_options():
    '''Processes command line options
    
    Returns proxy_server, from_date, to_date, mode, apikey'''
    
    opts = argparse.ArgumentParser(description="Mashery reporting script")

    opts.add_argument("--id", "-i",
                      required=False,
                      help="user ID for proxy authentication")
    opts.add_argument("--password", "-p",
                      required=False,
                      help="password for proxy authentication")
    opts.add_argument("--proxy", "-x",
                      required=False,
                      help="proxy ip:port (may be set to ""default"" if pre-configured")
    opts.add_argument("--mode", "-m",
                      required=True,
                      choices=["getapp", "listkeys", "usage"],
                      help="getapp|listkeys|usage")
    opts.add_argument("--from_date", "-f",
                      required=False,
                      help="yyyy-mm-ddThh:mm:ssZ - defaults to midnight")
    opts.add_argument("--to_date", "-t",
                      required=False,
                      help="yyyy-mm-ddThh:mm:ssZ - defaults to midnight the day before")
    opts.add_argument("--key", "-k",
                      required=False,
                      help="API key to query for ""getapp"" mode")
    options = opts.parse_args()

    # set up the proxy server, if specified
    if options.proxy:
        if options.proxy == "default":
            proxy_server = Config.PROXY
        else:
            proxy_server = options.proxy
    
        if options.id and options.password:
            proxy_server = "http://" + options.id + ":" + options.password + "@" + proxy_server
        else:
            proxy_server = "http://" + proxy_server
    else:
        proxy_server = None
    
    # set up the from and to dates, if specified    
    today = datetime.date.today()
    yesterday = today - datetime.timedelta( 1 )
    
    if options.from_date:
        from_date = options.from_date
    else:
        from_date = yesterday.strftime("%Y-%m-%d") + "T00:00:00Z"
    
    if options.to_date:
        to_date = options.to_date
    else:
        to_date = today.strftime("%Y-%m-%d") + "T00:00:00Z"
        
    return(proxy_server, from_date, to_date, options.mode, options.key)


def log(log_message):
    '''Prints a timestamped log message
    '''
    
    time_stamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
    print (time_stamp + " " + log_message)


def stop(log_message, exit_code):
    '''Stops the script, logging an output message and setting a return code
    '''
    
    log(log_message)
    log("Exiting with return code " + str(exit_code))
    sys.exit(exit_code)

    
def obfuscate_key(api_key):
    '''Takes an API key and removes all but the last six characters'''
    return api_key[-6:]
    
            
def get_sig():
    '''Calculates the sig required to call the Mashery API'''
    unhashed_sig = Config.APIKEY + Config.SECRET + str(calendar.timegm(time.gmtime()))
    
    # calculate the MD5 hash, returning it in hex
    hashed_sig = hashlib.md5()
    hashed_sig.update(unhashed_sig.encode('utf-8'))
    return hashed_sig.hexdigest()
    
            
def query_mashery(mashery_caller, query, page_number, items_per_page):
    '''run something against Mashery's query API
    
    Takes proxy_server, query
    Returns a list of Mashery items'''
    
    mashery_url = Config.MASHERY_URL_QUERY + "?apikey=" + Config.APIKEY + "&sig=" + get_sig()
    
    log("Calling " + mashery_url)
    log("Query " + query + " PAGE " + str(page_number) + " ITEMS " + str(items_per_page))
    
    json_payload = JSONEncoder().encode({
                        "method": "object.query",
                        "params": [query + " PAGE " + str(page_number) + " ITEMS " + str(items_per_page)],
                        "id":     "1",
                        })
    
    headers = {
               "Content-Type":   "application/json",
               "Accept":         "text/plain",
               "Content-Length": repr(len(json_payload))
               }
    
    json_response = mashery_caller.call(mashery_url, json_payload, headers)
    
    # check for errors
    if json_response['error'] is not None:
        print(json.dumps(json_response, sort_keys=True, indent=4))
        stop("Error calling Mashery", -1)

    
    # see if the resultset covers more than one page
    # if so, call the API repeatedly until all pages have been returned
    if json_response['result']['current_page'] < json_response['result']['total_pages']:
        json_response['result']['items'].extend(
                query_mashery(
                              mashery_caller,
                              query,
                              page_number+1,
                              items_per_page
                              ))

    return json_response['result']['items']


def get_app(proxy_server, api_key):
    '''get details of the application(s) relating to a given key
    
    Takes proxy_server, api_key
    Returns a list of application names'''
    
    query = "SELECT application.name, username FROM keys WHERE apikey = '" + api_key + "'"

    item_list = query_mashery(proxy_server, query, 1, Config.ITEMS_PER_PAGE)

    # some users have the same key across multiple services
    # the following "previous" variable will be used as comparison
    previous = ""
        
    for consumer in item_list:
        # get the username
        if consumer['username'] is None:
            username = "UNKNOWN"
        else:
            username = consumer['username']

        # get the application name
        if consumer['application'] is None:
            app_name = "UNNAMED"
        else:
            if consumer['application']['name'] is None:
                app_name = "UNNAMED"
            else:
                app_name = consumer['application']['name']

        current = username + "," + app_name
        
        if current != previous:
            # spit it out
            log("Username    = " + username)
            log("Application = " + app_name)
        
        previous = current


def list_keys(proxy_server):
    '''list all active Mashery keys and associated apps
    
    Takes proxy_server
    Returns a list of keys, application names and usernames'''
    
    query = "SELECT apikey, application.name, username FROM keys"

    item_list = query_mashery(proxy_server, query, 1, Config.ITEMS_PER_PAGE)
    
    # some users have the same key across multiple services
    # the following "previous" variable will be used as comparison
    previous = ""
        
    for consumer in item_list:
        # get the username
        if consumer['username'] is None:
            username = "UNKNOWN"
        else:
            username = consumer['username']

        # get the key
        if consumer['apikey'] is None:
            api_key = "UNKNOWN"
        else:
            api_key = obfuscate_key(consumer['apikey'])

        # get the application name
        if consumer['application'] is None:
            app_name = "UNNAMED"
        else:
            if consumer['application']['name'] is None:
                app_name = "UNNAMED"
            else:
                app_name = consumer['application']['name']

        current = username + "," + api_key + "," + app_name
        
        if current != previous:
            # spit it out
            print(username + "," + api_key + "," + app_name)
        
        previous = current


def main():
    (proxy_server, from_date, to_date, mode, api_key) = process_options()
    
    log("Started in " + mode + " mode")
    
    mashery_caller = mashery(proxy_server) 
    
    if mode == "getapp":
        if api_key is None:
            stop("Must specify API key parameter for getapp mode", -1)
            
        get_app(mashery_caller, api_key)
        
    elif mode == "listkeys":
        list_keys(mashery_caller)
                
    elif mode == "usage":
        print ("TODO: USAGE REPORT STUFF")
        

    stop("Finished", 0)


if __name__ == "__main__":
    main()