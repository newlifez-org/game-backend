'use strict';
global.fetch = require('node-fetch')
const AWS = require("aws-sdk");
const jwt_decode = require("jwt-decode");
const db = new AWS.DynamoDB.DocumentClient();
const { CosmWasmClient } = require('@cosmjs/cosmwasm-stargate');

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

let client;

const getAuraWasmClient = async () => {
    const client = await CosmWasmClient.connect(process.env.RPC_ENDPOINT);
    return client;
}

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
        if (!client) {
            client = await getAuraWasmClient();
        }
        const tokens = {
            tokens: {
                owner: wallet_address
            }
        }
        const result = await client.queryContractSmart(process.env.CONRTACT_ADDRESS, tokens);
        let data = [];
        for(let element of result.tokens) {
            const nftInfo = {
                nft_info: {
                    token_id: element
                }
            }
            const nft = await client.queryContractSmart(process.env.CONRTACT_ADDRESS, nftInfo);
            data.push({token_id: element, token_uri: nft.token_uri});
        }
        const responseCallBack = {
            wallet_address: wallet_address,
            list_tokens: data
        }
        return callback(null, response(200, responseCallBack));
    }
}