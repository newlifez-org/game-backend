'use strict';
global.fetch = require('node-fetch')
const AWS = require("aws-sdk");
const jwt_decode = require("jwt-decode");
const db = new AWS.DynamoDB.DocumentClient();

// Create a response
function response(statusCode, message) {
    return {
        statusCode: statusCode,
        headers: {
            "Access-Control-Allow-Origin": "*", // Required for CORS support to work
            "Access-Control-Allow-Credentials": true, // Required for cookies, authorization headers with HTTPS
        },
        body: JSON.stringify(message),
        isBase64Encoded: true | false,
    };
}

// Check empty
function isEmpty(value) {
    return (
        (typeof value == "string" && !value.trim()) ||
        typeof value == "undefined" ||
        value === null
    );
}

// Get customer id
function getCustomerID(bearerToken) {
    const decoded = jwt_decode(bearerToken.split(" ")[1]);
    const decodeString = JSON.stringify(decoded);
    const decodeStringReplicate = decodeString.replace("cognito:username", "username");
    return JSON.parse(decodeStringReplicate).username;
}

// Get customer email
function getCustomerEmail(bearerToken) {
    const decoded = jwt_decode(bearerToken);
    return decoded.email;
}

const resultSuccess = {
    message: "OK"
};
const resultError = {
    message: "Error",
};
exports.getToken = async (event, context, callback) => {
    const username = getCustomerID(event.headers.Authorization);
    const params = {
        TableName: process.env.USER_TABLE,
        Key: {
            username: username,
        },
        KeyConditionExpression: "username = :username",
        ExpressionAttributeValues: {
            ":username": username
        },
    };
    const item = await db.get(params).promise();
    if (isEmpty(item.Item)) {
        resultError.message = "User not exists";
        return callback(null, response(422, resultError));
    } else {
        const wallet_address = item.Item.wallet_address;
        // wallet address
        const responseCallBack = {
            wallet_address: wallet_address,
            list_tokens: [
                {
                    token_id: "9233f8a9-8356-4d10-90b9-e760098dbf62",
                    token_uri: "https://dev.cdn.newlifez.io/metadata/1.json"
                },
                {
                    token_id: "ef8120f4-a25f-4f4a-9e69-38a030ccf47a",
                    token_uri: "https://dev.cdn.newlifez.io/metadata/1.json"
                }
            ]
        }
        return callback(null, response(200, responseCallBack));
    }
}