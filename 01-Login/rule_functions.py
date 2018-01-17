import urllib3
import json


def getRulesMatching(variable, pattern, domain, manage_jwt) :
    # Setup request with content type and auth headers
    http = urllib3.PoolManager()
    req = http.request("GET", "https://{0}/api/v2/rules".format(domain),
                       headers={
                           "content-type": "application/json",
                           "Authorization" : "Bearer {0}".format(manage_jwt)
                       })

    print("Got server response : {0}".format(req.status))

    if req.status != 200:
        print("Error in server response code")
        return None

    json_data = json.loads(req.data.decode('utf-8'))

    print(len(json_data))

    rules_matching_str = []

    for json_entity in json_data:
        # Print rule name
        print("Rule : {0}".format(json_entity['name']))

        # Check if this rule has the "clientName" comparison in its script
        if variable in json_entity['script']:
            # Split the script on newlines
            lines = json_entity['script'].split("\n")

            # Loop and check if this line contains the comment
            for line in lines:
                if variable in line :
                    # If the comment is found split the line at '===' & '\''

                    delim = None

                    if pattern in line:
                        delim = pattern

                    if delim is not None:
                        apps = line.split(delim)[1]
                        apps = apps.split('\'')[1]

                        rule = {}
                        rule['title'] = apps
                        rule['script'] = json_entity['script']
                        print("Adding rule {0} : pattern {1}".format(apps, pattern))
                        rules_matching_str.append(rule)

        else :
            print("No app definitions found in this rule")

    if len(rules_matching_str) > 0:
        return rules_matching_str
    else:
        return None
