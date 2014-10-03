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


class script_logger(object):
    def __init__(self, log_flag):
        '''
        Script control class for logging messages (if required) and stopping execution
        '''
        
        self.log_flag = log_flag


    def log(self, log_message):
        '''
        Prints a timestamped log message
        '''
    
        if self.log_flag:
            time_stamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
            print (time_stamp + " " + log_message)


    def stop(self, log_message, exit_code, override_flag):
        '''
        Stops the script, logging an output message and setting a return code
        
        The override flag parameter will force a log message, even if the script has been called in non-logging mode
        '''
    
        if override_flag:
            self.log_flag = True

        self.log(log_message)
        self.log("Exiting with return code " + str(exit_code))
        sys.exit(exit_code)

    
class mashery(object):
    
    def __init__(self, proxy_server, mashery_url, api_key, shared_secret, throttle, max_items_per_page, logger):
        '''
        Constructor method
        
        Takes:-
            proxy server details,
            Mashery URL for query API calls,
            API key,
            shared secret,
            maximum allowable calls per second (throttle),
            maximum allowable items per page
        '''
        
        self.proxy_server = proxy_server
        self.mashery_url = mashery_url
        self.api_key = api_key
        self.shared_secret = shared_secret
        self.throttle = throttle
        self.max_items_per_page = max_items_per_page
        self.call_counter = -1
        self.logger = logger
        
        
    def _check_throttle(self):
        '''
        Private method to slow API call rate to within allowable throttle (calls per second)
        '''
        
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
            if self.call_counter > self.throttle:
                self.logger.log("Call rate (" +
                    str(self.call_counter) +
                    " calls in " +
                    str(time_diff.total_seconds()) +
                    " seconds) over throttle, pausing briefly")
                time.sleep(1)
                self.call_counter = 0
        

    def call(self, url, json_request, headers):
        self._check_throttle()
        
        if self.proxy_server is not None:
            proxy = urllib.request.ProxyHandler({"http": self.proxy_server})
            auth = urllib.request.HTTPBasicAuthHandler()
            opener = urllib.request.build_opener(proxy, auth, urllib.request.HTTPHandler)
            urllib.request.install_opener(opener)

        # add the header and payload body into the call if provided
        if json_request is None and headers is None:
            req = urllib.request.Request(url)
        else:
            req = urllib.request.Request(
                                 url,
                                 data=json_request.encode('utf-8'),
                                 headers=headers
                                 )

        try:        
            connection = urllib.request.urlopen(req)
            return(json.loads(connection.read().decode('utf8')))
        except URLError as e:
            self.logger.log("Error accessing " + url)
            self.logger.stop("%s" % e, -1, True)


    def query(self, query):
        '''
        Run something against Mashery's query API
    
        Takes query string 
        Returns a list of Mashery items
        '''
        return self._exec_query(query, 1, self.max_items_per_page)

    
    def _exec_query(self, query, page_number, items_per_page):
        '''
        Private method to run something against Mashery's query API
    
        Takes query string,starting page number, items per page 
        Returns a list of Mashery items
        '''
    
        mashery_url = self.mashery_url + "?apikey=" + self.api_key + "&sig=" + self.get_sig()
    
        self.logger.log("Calling " + mashery_url)
        self.logger.log("Query " + query + " PAGE " + str(page_number) + " ITEMS " + str(items_per_page))
    
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
    
        json_response = self.call(mashery_url, json_payload, headers)
    
        # check for errors
        if json_response['error'] is not None:
            print(json.dumps(json_response, sort_keys=True, indent=4))
            self.logger.stop("Error calling Mashery", -1, True)

        # if the result set covers more than one page
        # then call the API repeatedly until all pages have been returned
        if json_response['result']['current_page'] < json_response['result']['total_pages']:
            json_response['result']['items'].extend(
                 self._exec_query(
                            query,
                            page_number+1,
                            items_per_page
                            ))

        return json_response['result']['items']


    def get_sig(self):
        '''
        Calculates the sig required to call the Mashery API
        '''
        unhashed_sig = self.api_key + self.shared_secret + str(calendar.timegm(time.gmtime()))
    
        # calculate the MD5 hash, returning it in hex
        hashed_sig = hashlib.md5()
        hashed_sig.update(unhashed_sig.encode('utf-8'))
        return hashed_sig.hexdigest()
    
            
class apps_for_key(object):
    
    def __init__(self, mashery_caller, api_key, logger):
        '''
        Constructor method
        
        Builds an object of application names and owners relating to a given key value
    
        Takes mashery_caller, api_key
        '''
    
        self.logger = logger
        self.app = []
        query = "SELECT application.name, username FROM keys WHERE apikey LIKE '" + api_key + "'"

        item_list = mashery_caller.query(query)

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
                app_name = Config.UNKNOWN
            else:
                if consumer['application']['name'] is None:
                    app_name = Config.UNKNOWN
                else:
                    app_name = consumer['application']['name']

            current = username + "," + app_name
        
            if current != previous:
                self.app.append({
                         "name":     app_name,
                         "username": username})
                # spit it out
                self.logger.log("Username = " + username + ", Application = " + app_name)
        
            previous = current


    def print(self):
        print("USERNAME,APP_NAME")
        for app in self.app:
            print(app["username"] + "," + app["name"])



class usage(object):
    
    def __init__(self, mashery_caller, from_date, to_date, logger):
        '''
        get statistics around call volumes between two dates
    
        Takes mashery_caller and from/to dates
        Returns an object with usage statistics for the given dates
        '''

        self.logger = logger
        usage_report = []
    
        mashery_url = mashery_caller.mashery_url + "?apikey=" + mashery_caller.api_key + "&sig=" + mashery_caller.get_sig() \
            + "&format=" + Config.FORMAT + "&start_date=" + from_date + "&end_date=" + to_date
    
        self.logger.log("Calling " + mashery_url)

        item_list = mashery_caller.call(mashery_url, None, None)
    
        mashery_app_caller = mashery(
                             mashery_caller.proxy_server,
                             Config.MASHERY_URL_QUERY,
                             Config.APIKEY,
                             Config.SECRET,
                             Config.THROTTLE,
                             Config.ITEMS_PER_PAGE,
                             logger) 

        for item in item_list:
            api_key = obfuscate_key(item["serviceDevKey"])
        
            if (item["serviceDevKey"] == Config.UNKNOWN):
                username = Config.UNKNOWN
                app_name = Config.UNKNOWN
            else:
                apps = apps_for_key(mashery_app_caller, item["serviceDevKey"], logger)
            
                # currently assumes that the first app returned is the right one
                # TODO think this through and perhaps check if multiple apps are
                # returned for the same key and send a warning
                username = apps.app[0]["username"]
                app_name = apps.app[0]["name"]
        
            successful_calls = item["callStatusSuccessful"]
            unsuccessful_calls = item["callStatusOther"]
            blocked_calls = item["callStatusBlocked"]
    
            usage_report.append({
                        "api_key" :           api_key,
                        "username":           username,
                        "app_name":           app_name,
                        "successful_calls":   successful_calls,
                        "unsuccessful_calls": unsuccessful_calls,
                        "blocked_calls":      blocked_calls
                            })
        
        self.usage_report = usage_report


    def print(self):
        '''
        Print a comma separated version of the usage report
        '''
        
        # print column headers
        print("USERNAME,APPLICATION,APIKEY_EXTRACT,SUCCESSFUL_CALLS,UNSUCCESSFUL_CALLS,BLOCKED_CALLS")
        
        for usage in self.usage_report:
            print(
                  usage["username"] + "," +
                  usage["app_name"] + "," +
                  obfuscate_key(usage["api_key"]) + "," +
                  str(usage["successful_calls"]) + "," +
                  str(usage["unsuccessful_calls"]) + "," +
                  str(usage["blocked_calls"])
                  )

    
def process_options():
    '''
    Processes command line options
    
    Returns proxy_server, from_date, to_date, mode, apikey
    '''
    
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
                      help="API key to query for ""getapp"" mode. Can include wildcards (%% to match any string, _ to match any single character).")
    opts.add_argument("--log", "-l",
                      required=False,
                      default=False,
                      action="store_true",
                      help="Send log messages to sysout")
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
        
    return(proxy_server, from_date, to_date, options.mode, options.key, options.log)


def obfuscate_key(api_key):
    '''
    Takes an API key and removes all but the last six characters
    '''
    return api_key[-6:]
    

def list_keys(mashery_caller, logger):
    '''
    List all active Mashery keys and associated apps
    
    Takes mashery_caller
    Returns a list of keys, application names and usernames
    '''
    
    query = "SELECT apikey, application.name, username FROM keys"

    item_list = mashery_caller.query(query)
    
    # some users have the same key across multiple services
    # the following "previous" variable will be used as comparison
    previous = ""
    
    logger.log("List of all keys follows: (USERNAME,KEY_EXTRACT,APPLICATION)")
    print("USERNAME,APIKEY_EXTRACT,APPLICATION")
        
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
    (proxy_server, from_date, to_date, mode, api_key, log_flag) = process_options()
    
    logger = script_logger(log_flag)
    logger.log("Started in " + mode + " mode")
    
    if mode == "getapp":
        if api_key is None:
            logger.stop("Must specify API key parameter for getapp mode", -1, True)
            
        mashery_caller = mashery(
                             proxy_server,
                             Config.MASHERY_URL_QUERY,
                             Config.APIKEY,
                             Config.SECRET,
                             Config.THROTTLE,
                             Config.ITEMS_PER_PAGE,
                             logger) 

        apps = apps_for_key(mashery_caller, api_key, logger)
        apps.print()            

    elif mode == "listkeys":
        mashery_caller = mashery(
                             proxy_server,
                             Config.MASHERY_URL_QUERY,
                             Config.APIKEY,
                             Config.SECRET,
                             Config.THROTTLE,
                             Config.ITEMS_PER_PAGE,
                             logger) 
        
        list_keys(mashery_caller, logger)
                
    elif mode == "usage":
        mashery_caller = mashery(
                             proxy_server,
                             Config.MASHERY_URL_CALLS + Config.SERVICEID,
                             Config.APIKEY,
                             Config.SECRET,
                             Config.THROTTLE,
                             Config.ITEMS_PER_PAGE,
                             logger) 
        
        usage_stats = usage(mashery_caller, from_date, to_date, logger)
        usage_stats.print()

    logger.stop("Finished", 0, False)


if __name__ == "__main__":
    main()