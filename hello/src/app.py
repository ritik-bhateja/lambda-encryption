"""Hello API. Plain business logic: payload_crypto handles encryption at the edges."""

import json

from payload_crypto import secure_api


@secure_api()
def handler(event, context):
    print("hello")
    payload = json.loads(event["body"]) if event.get("body") else {}
    if not isinstance(payload, dict):
        return {"statusCode": 400, "body": json.dumps({"error": "body must be a JSON object"})}

    name = payload.get("name", "world")
    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({"response_data": {"message": f"hello {name}", "received": payload}}),
    }
