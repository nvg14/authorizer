import http.server
import socketserver
import json
import sys
from urllib.parse import urlparse

sys.path.append("/opt/homebrew/lib/python3.10/site-packages")
import jwt
import re
import jsonpath_ng as jp

authorization_rules = {}
with open('scope_to_rules_v2.json') as json_file:
    data = json.load(json_file)
    for item in data:
        authorization_rules[item["id"]] = item
        operations = list(item["operations"].keys())
        for operation in operations:
            api_path_patterns = list(item["operations"][operation].keys())
            for path_pattern in api_path_patterns:
                scope_data = item["operations"][operation][path_pattern]
                temp = "/" + operation + path_pattern
                temp = temp.replace("/", "\/")
                if "resources" in item["operations"][operation][path_pattern]:
                    resources = list(item["operations"][operation][path_pattern]["resources"].keys())
                    for resource in resources:
                        temp = temp.replace(":" + resource, str(item["operations"][operation][path_pattern]["resources"][resource]))
                authorization_rules[item["id"]]["operations"][operation][temp] = scope_data
                authorization_rules[item["id"]]["operations"][operation].pop(path_pattern)


PORT = 8080
Handler = http.server.SimpleHTTPRequestHandler
PREFIX = 'Bearer '

def get_token(header):
    if not header.startswith(PREFIX):
        raise ValueError('Invalid token')

    return header[len(PREFIX):]

from http.server import BaseHTTPRequestHandler, HTTPServer
import logging

class S(BaseHTTPRequestHandler):
    def _set_allowed_response(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
    
    def _set_denied_response(self):
        self.send_response(403)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def check_scope(self, permission, rules, url):
        
        # rules = authorization_rules[permission]
        # operation_prefix = self.headers.get("x-forwarded-prefix")
        # path = operation_prefix + self.headers.get("x-forwarded-uri")
        # logging.info(path)
        # url = urlparse(path)
        # logging.info(url)
        # # operation = url.path.split("/")[1]
        
        # logging.info(operation_prefix)
        # if operation_prefix == None:
        #     return False

        # operation = operation_prefix.strip("/")
        # logging.info(operation)
        # if operation not in rules["operations"]:
        #     logging.info(9)
        #     return False
        # logging.info(10)
        operation_scope = rules["operations"][operation]
        logging.info(operation_scope)
        for pattern, scope in operation_scope.items():
            logging.info(pattern)
            temp = re.compile(pattern)
            logging.info("---")
            logging.info(temp)
            logging.info(url.path)
            if temp.match(url.path) != None:
                logging.info(11)
                if self.headers.get("x-forwarded-method") not in scope["actions"]:
                    return False
                logging.info(12)
                if "conditions" not in scope:
                    return True
                logging.info(13)
                logging.info("Checking Headers")
                if "headers" in scope["conditions"]:
                    for header, value in scope["conditions"]["headers"].items():
                        match_count = 0
                        request_header_values = self.headers.get(header)
                        if request_header_values == None:
                            return False
                        
                        # request_header_values = request_header_values.split(",")
                        for item in value:
                            if item == request_header_values:
                                match_count += 1
                        
                        if match_count == 0:
                            return False
                        # if len(set(request_header_values) - set(value)) != 0:
                        #     return False
                
                logging.info("Checking Query")
                if "query" in scope["conditions"]:
                    for query, values in scope["conditions"]["query"].items():
                        match_count = 0
                        query_params = []
                        for value in values:
                            query_params.append(query + "=" + value)
                        
                        request_queries = url.query.split("&")
                        for q in query_params:
                            if q in request_queries:
                                match_count += 1
                        
                        if match_count == 0:
                            return False
                
                logging.info("Checking Body")
                if "body" in scope["conditions"]:
                    for key, values in scope["conditions"]["body"].items():
                        content_length = int(self.headers.get("Content-Length"))
                        body = self.rfile.read(content_length)
                        body = self.convert_bytes_to_json(body)
                        query = jp.parse(key)
                        query_result = query.find(body)
                        
                        if len(query_result) == 0:
                            return False
                        
                        query_value = query_result[0].value

                        if query_value not in values:
                            return False
                        
                return True

            else:
                return False
        # if self.command not in 

    def convert_bytes_to_json(self, body):
        my_json = body.decode('utf8').replace("'", '"')
        # Load the JSON to a Python list & dump it back out as formatted JSON
        return json.loads(my_json)
        # return json.dumps(data, indent=4, sort_keys=True)

    def authorizer(self):
        logging.info("GET request,\nPath: %s\nHeaders:\n%s\n", str(self.path), str(self.headers))
        authz = self.headers.get("Authorization")
        logging.info(1)
        if authz == None:
            logging.info(2)
            self._set_denied_response()
            return
        logging.info(3)
        decoded_data = jwt.decode(get_token(authz), "RS256", algorithms=["HS256"], options={"verify_signature": False})
        if "permissions" not in decoded_data:
            logging.info(4)
            self._set_denied_response()
            return
        logging.info(5)
        permissions = decoded_data["permissions"]
        logging.info(permissions)
        for permission in permissions:
            logging.info(6)
            logging.info(permission)
            if permission not in authorization_rules:
                logging.info(7)
                continue

            rules = authorization_rules[permission]
            operation_prefix = self.headers.get("x-forwarded-prefix")
            path = operation_prefix + self.headers.get("x-forwarded-uri")
            logging.info(path)
            url = urlparse(path)
            logging.info(url)
            # operation = url.path.split("/")[1]
            
            logging.info(operation_prefix)
            if operation_prefix == None:
                return False

            operation = operation_prefix.strip("/")
            logging.info(operation)
            if operation not in rules["operations"]:
                continue
            
            if not self.check_scope(permission, rules, url):
                
                self._set_denied_response()
                return
            else:
                
                self._set_allowed_response()
                return
        
        self._set_denied_response()
        return
    
    def do_GET(self):
        self.authorizer()

    def do_POST(self):
        self.authorizer()
    
    def do_PUT(self):
        self.authorizer()
    
    def do_DELETE(self):
        self.authorizer()
    
    def do_HEAD(self):
        self.authorizer()
    
    def do_PATCH(self):
        self.authorizer()

def run(server_class=HTTPServer, handler_class=S, port=8080):
    logging.basicConfig(level=logging.INFO)
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    logging.info('Starting httpd...\n')
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
    logging.info('Stopping httpd...\n')

if __name__ == '__main__':
    from sys import argv

    if len(argv) == 2:
        run(port=int(argv[1]))
    else:
        run()
