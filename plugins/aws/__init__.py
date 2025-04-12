import requests
import utils.utils as utils
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

def validate(pluginargs, args):
    #
    # Plugin Args
    #
    # --account <account_id>   -->  Account you are targeting
    # --aws_region_spray --> <region> region to target
    # --root -> Trying signing in with the root credentials
    
    if 'account' not in pluginargs.keys():
        error = "Missing url argument, specify as --account <account_id> "
        return False, error, None

    if 'aws_region_spray' in pluginargs.keys():

        region_spray = pluginargs['aws_region_spray']
        pluginargs["url"] = f"https://{region_spray}.signin.aws.amazon.com"

    else:
        # Default to us-east-1 if not supplied
        pluginargs["url"] = f"https://us-east-1.signin.aws.amazon.com"
    
    
    return True, None, pluginargs
    
def testconnect(pluginargs, args, api_dict, useragent):

    url = api_dict['proxy_url']

    success = True
    headers = {
        'User-Agent' : useragent,
        "X-My-X-Forwarded-For" : utils.generate_ip(),
        "x-amzn-apigateway-api-id" : utils.generate_id(),
        "X-My-X-Amzn-Trace-Id" : utils.generate_trace_id(),
    }

    headers = utils.add_custom_headers(pluginargs, headers)

    resp = requests.get(api_dict['proxy_url'], headers=headers, verify=False)

    if resp.status_code == 504:
        output = "Testconnect: Connection failed, endpoint timed out, exiting"
        success = False
    else:
        output = "Testconnect: Connection success, continuing"

    return success, output, pluginargs
