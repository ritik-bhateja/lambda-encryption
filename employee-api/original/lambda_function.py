import requests
import os
import time
import datetime
import logging
import uuid
from pytz import timezone
from lambda_cache import secrets_manager
import ast
import json
from jwt import decode
import boto3
import asyncio
from src import employee_by_employeecode, get_auth_role_by_token, restructure_employee_response

logger = logging.getLogger()
logger.setLevel(logging.INFO)

lam = boto3.client('lambda')

@secrets_manager.cache(name='empower-care-prod-secret-api-engine-config-v1', max_age_in_seconds=300)
def get_secret(event, context):
    keys = getattr(context, 'empower-care-prod-secret-api-engine-config-v1')
    return keys

def get_hasura_config(event, context):
    global secret_key
    global hasura_endpoint
    try:
        response = get_secret(event, context)
        secret = ast.literal_eval(response)
        secret_key = secret["API_ENGINE_SECRET_KEY"]
        hasura_endpoint = secret["API_ENGINE_ENDPOINT"]
        return secret_key, hasura_endpoint
    except:
        return None

def validate_request(event):
    response_code = 200
    response_msg = "Request Successfully processed"
    mandatoryfields = ["employee_code"]
    try:
        receviedtag = list(event['body-json'].keys())
    except Exception as error:
        logger.error("An error occurred while getting request key information %s", str(error))
        response_code = 500
        response_msg = "Something went wrong"
        return response_code, response_msg

    check = all(item in receviedtag for item in mandatoryfields)
    if not check:
        response_code = 400
        response_msg = "Functional error happened, like missing mandatory field(s) in the request"
    else:
        if event['body-json']["employee_code"] in [None, ""]:
            response_code = 400
            response_msg = "Functional error happened, like missing mandatory field(s) in the request"

    return response_code, response_msg


def lambda_handler(event, context):
    global response_data
    logger.info("Starting execution for employee api lambda")
    start_time_for_log = str(datetime.datetime.now(timezone('Asia/Kolkata')).isoformat())
    request_id = event['context']['request-id']
    start_time = time.process_time()
    response_code = 200
    response_msg = ""
    status_code = ""
    status_message = ""

    secret_keys = get_hasura_config(event, context)
    if not secret_keys is None:
        response_code, response_msg = validate_request(event)
        if response_code == 200:
            logger.info("Input Request is valid")
            response_code, response_msg, status_code, status_message, response_data = get_hasura_response(event)

            if response_code == 200:
                response_code = 200
                response_msg = "Request Successfully processed"
            elif response_code == 401:
                response_code = 401
                response_msg = "Authentication Failed"
            else:
                response_code = 500
                response_msg = "Something went wrong"
    else:
        response_code = 500
        response_msg = "Something went wrong"
        response_data = {}

    elapsed_time = (time.process_time() - start_time) * 1000
    if not response_code == 200:
        response_data = {}

    if response_data is None:
        response_data = {}
    output = {
        "request_id": request_id,
        'response_code': response_code,
        'response_error_code': status_code,
        'response_error_message': status_message,
        'time_taken': elapsed_time,
        'timestamp': str(datetime.datetime.now(timezone('Asia/Kolkata')).isoformat()),
        'response_message': response_msg,
        'response_data': response_data
    }
    try:
        if "Authorization" in event['params']['header'].keys():
            auth_token = event['params']['header']['Authorization']
            client_id_cognito = get_client_id_by_token(auth_token)
            if client_id_cognito is None:
                client_id_cognito = ""
            group1 = asyncio.gather(log_data(event, event['body-json'], output, "employee-api", start_time_for_log, client_id_cognito))
            loop = asyncio.get_event_loop()
            loop.run_until_complete(group1)
    except Exception as err:
        print("An error occurred while loging", err)
    return output


def prepare_header(event):
    clien_token = event['params']['header']['Authorization']
    is_x_hasura_user_id_found = True
    try:
        role_id, allowed_ids = get_auth_role_by_token(event)
        if allowed_ids in ["", None, []]:
            header = {'x-hasura-admin-secret': '{}'.format(secret_key),
                      'Content-Type': 'application/json', 'X-Hasura-Role': '{}'.format(role_id)}
        else:
            header = {'x-hasura-admin-secret': '{}'.format(secret_key),
                      'Content-Type': 'application/json', 'X-Hasura-Role': '{}'.format(role_id),
                      'X-Hasura-User-Id': allowed_ids}

        return header
    except Exception as err:
        logger.error("An error occurred while decoding client token {}".format(str(err)))
        return None


def get_hasura_response(event):
    json_resp = None
    resp_code = 200
    resp = ""
    status_code = ""
    status_message = ""
    resp_msg = ""
    try:
        header = prepare_header(event)
        if not header is None:
            try:
                employee_code = event['body-json']["employee_code"].strip().upper()

                if employee_code != "":
                    query = employee_by_employeecode(employee_code)
                    resp = requests.post(hasura_endpoint, headers=header, json=query)
                    logger.info("Hasura response received with HTTP status: %s", resp.status_code)

                if not resp == "":
                    response = resp.json()
                    if "errors" in response:
                        logger.info("Hasura returned errors in response")
                    elif "data" in response:
                        record_count = len(response.get("data", {}).get("employee_information_master", []))
                        logger.info("Hasura returned data with %s record(s)", record_count)
                    resp_code, resp_msg, status_code, status_message, json_resp = restructure_employee_response(response)
                    logger.info(
                        "Hasura response processed - code: %s, msg: %s, status_code: %s, status_message: %s",
                        resp_code, resp_msg, status_code, status_message
                    )
            except Exception as er:
                resp_code = 500
                json_resp = None
                logger.error("An error occurred while sending post request: %s", str(er))
        else:
            resp_code = 401
            json_resp = "Authentication Failed at role level"
            logger.info("Authentication Failed at role level, Either client is not defined or Token is not passed")
    except Exception as err:
        logger.error("Something went wrong at hasura endpoint: %s", str(err))
        resp_code = 500

    return resp_code, resp_msg, status_code, status_message, json_resp


async def log_data(event, request_body, response_body, api_name, start_time, cognito_client_id):
    try:
        payload = {
            "request_id": event['context']['request-id'],
            "api_endpoint": event['context']['resource-path'],
            "stage": event['context']['stage'],
            "http_method": event['context']['http-method'],
            "api_name": api_name,
            "client_id": cognito_client_id,
            "request_body": request_body,
            "response_body": response_body,
            "request_time": start_time,
            "response_time": str(datetime.datetime.now(timezone('Asia/Kolkata')).isoformat())
        }
        response = lam.invoke(FunctionName='empower_care_prod_lambda_apilogging',
                              InvocationType='Event',
                              Payload=json.dumps(payload))
    except Exception as err:
        print("An error occurred while invoking log lambda", err)


def get_client_id_by_token(token):
    try:
        clien_token = str(token)
        if "Bearer" in clien_token:
            clien_token = clien_token.replace("Bearer", "")
            clien_token = clien_token.replace(" ", "")
        clien_token_decoded = decode(clien_token, algorithms=["RS256"], options={"verify_signature": False})
        if "client_id" in clien_token_decoded.keys():
            client_id = clien_token_decoded["client_id"]
            return client_id
        else:
            return None
    except Exception as err:
        logger.error('Error while decoding token, Error message: %s', err)
        return None
