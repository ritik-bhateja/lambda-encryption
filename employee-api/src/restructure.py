import json
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

json_response = {}

def restructure_employee_response(resp):
    response_code = 200
    response_msg = "Request processed successfully"
    status_code = ""
    status_message = ""
    check_error_data = resp.keys()
    json_response = {}
    try:
        if "data" in check_error_data:
            response_data = resp["data"]
            if "employee_information_master" in response_data.keys():
                if not resp["data"]["employee_information_master"] in [[], {}]:
                    employee_information_master = response_data["employee_information_master"][0]
                    json_response["employee_information_master"] = employee_information_master

                else:
                    logger.info("No matching records found with requested details")
                    status_code = "EMP404"
                    status_message = "Employee is not available"
                    response_code = 200
                    response_msg = "Request Processed successfully, No matching record found"

        else:
            if "errors" in check_error_data:
                error = resp["errors"]
                response_code = 500
                response_msg = "Something went wrong"
                logger.info("Error received from hasura response")
            elif "error" in check_error_data:
                error = resp["error"]
                response_code = 500
                response_msg = "Something went wrong"
                logger.info("Error received from hasura response")
            elif "data" in resp.keys():
                if "employee_information_master" in resp["data"].keys():
                    if resp["data"]["employee_information_master"] in [[], {}]:
                        logger.info("No matching records found with requested details")
                        status_code = "EMP404"
                        status_message = "Employee is not available"
                        response_code = 200
                        response_msg = "Request Processed successfully, No matching record found"
                    else:
                        response_code = 500
                        response_msg = "Something went wrong"
                else:
                    response_code = 500
                    response_msg = "Something went wrong"
            else:
                response_code = 500
                response_msg = "Something went wrong"

    except Exception as err:
        logger.error("An error occurred while restructuring the response", str(err))
        response_code = 500
        response_msg = "Something went wrong"

    return response_code, response_msg, status_code, status_message, json_response
