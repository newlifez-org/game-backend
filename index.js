'use strict';
global.fetch = require('node-fetch')
const AWS = require("aws-sdk");
const Cognito = require('./cognito/index');
const jwt_decode = require("jwt-decode");
const db = new AWS.DynamoDB.DocumentClient();
const md5 = require('md5');

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

exports.signUp = async (event, context, callback) => {
    const reqBody = JSON.parse(event.body);
    if (
        isEmpty(reqBody.walletAddress) ||
        isEmpty(reqBody.username) ||
        isEmpty(reqBody.email) ||
        isEmpty(reqBody.password)
    ) {
        resultError.message = "The required parameters are not enough";
        return callback(null, response(400, resultError));
    }
    const paramsCheckExistUser = {
        TableName: process.env.USER_TABLE,
        Key: {
            username: reqBody.username,
        },
        KeyConditionExpression: "username = :username AND wallet_address = :walletAddress",
        ExpressionAttributeValues: {
            ":username": reqBody.username,
            ":walletAddress": reqBody.walletAddress
        },
    };
    const itemCheckExistUser = await db.get(paramsCheckExistUser).promise();
    if (isEmpty(itemCheckExistUser.Item)) {
        const signUpCognitoResponse = await Cognito.signUp(String(reqBody.username), reqBody.email, reqBody.password);
        if (signUpCognitoResponse.statusCode === 201) {
            const newUser = {
                wallet_address: reqBody.walletAddress,
                username: reqBody.username,
                email: reqBody.email,
                password: md5(reqBody.password),
                user_confirm: signUpCognitoResponse.response.userConfirmed,
                created_at: new Date().toISOString().replace(/\..+/, "") + "Z",
                updated_at: new Date().toISOString().replace(/\..+/, "") + "Z"
            };
            return db
                .put({
                    TableName: process.env.USER_TABLE,
                    Item: newUser,
                })
                .promise()
                .then(() => {
                    return callback(null, response(200, resultSuccess));
                })
                .catch((err) => {
                    resultError.message = err.message;
                    return callback(null, response(err.statusCode, resultError));
                });
        } else {
            resultError.message = signUpCognitoResponse.response.message;
            return callback(null, response(signUpCognitoResponse.statusCode, resultError));
        }
    } else {
        resultError.message = "User already exists";
        return callback(null, response(422, resultError));
    }
}

exports.verifyOTP = async (event, context, callback) => {
    const reqBody = JSON.parse(event.body);
    if (
        isEmpty(reqBody.username) ||
        isEmpty(reqBody.otp)
    ) {
        resultError.message = "The required parameters are not enough";
        return callback(null, response(400, resultError));
    }
    const paramsCheckExist = {
        TableName: process.env.USER_TABLE,
        Key: {
            username: reqBody.username,
        },
        KeyConditionExpression: "username = :username",
        ExpressionAttributeValues: {
            ":username": reqBody.username,
        },
    };
    const itemCheckExist = await db.get(paramsCheckExist).promise();
    if (isEmpty(itemCheckExist.Item)) {
        resultError.message = "User not exists";
        return callback(null, response(422, resultError))
    } else {
        const verifyOTPResponse = await Cognito.verify(reqBody.username, reqBody.otp);
        console.log(verifyOTPResponse);
        if (verifyOTPResponse.response === 'SUCCESS') {
            const userUpdate = {
                TableName: process.env.USER_TABLE,
                Key: {
                    username: reqBody.username,
                },
                UpdateExpression: "SET user_confirm = :user_confirm, updated_at = :updated_at",
                ExpressionAttributeValues: {
                    ":user_confirm": true,
                    ":updated_at": new Date().toISOString().replace(/\..+/, "") + "Z"
                },
                ReturnValues: "UPDATED_NEW",
            };
            console.log(userUpdate);
            return db.update(userUpdate)
                .promise()
                .then((res) => {
                    return callback(null, response(200, resultSuccess));
                })
                .catch((err) => {
                    resultError.message = err.message;
                    return callback(null, response(err.statusCode, resultError));
                });
        } else {
            resultError.message = verifyOTPResponse.response;
            return callback(null, response(verifyOTPResponse.statusCode, resultError));
        }
    }
}

exports.signIn = async (event, context, callback) => {
    const reqBody = JSON.parse(event.body);
    if (
        isEmpty(reqBody.username) ||
        isEmpty(reqBody.password)
    ) {
        resultError.message = "The required parameters are not enough";
        return callback(null, response(400, resultError));
    }
    const paramsCheckExist = {
        TableName: process.env.USER_TABLE,
        Key: {
            username: reqBody.username,
        },
        KeyConditionExpression: "username = :username",
        ExpressionAttributeValues: {
            ":username": reqBody.username,
        },
    };
    const itemCheckExist = await db.get(paramsCheckExist).promise();
    if (isEmpty(itemCheckExist.Item)) {
        resultError.message = "User not exists";
        return callback(null, response(422, resultError))
    } else {
        const cognitoSignIn = await Cognito.signIn(reqBody.username, reqBody.password);
        return callback(null, response(cognitoSignIn.statusCode, cognitoSignIn.response));
    }
}
exports.getInfoUser = async (event, context, callback) => {
    const username = getCustomerID(event.headers.Authorization);
    const params = {
        TableName: process.env.USER_TABLE,
        Key: {
            username: username,
        },
        KeyConditionExpression: "username = :username",
        ExpressionAttributeValues: {
            ":username": username,
        },
    };
    const item = await db.get(params).promise();
    if (isEmpty(item.Item)) {
        resultError.message = "Username not exists";
        return callback(null, response(422, resultError))
    } else {
        const result = {
            wallet_address: "",
            username: "",
            email: "",
            created_at: "",
            verify_otp: false
        }
        result.wallet_address = item.Item.wallet_address
        result.username = item.Item.username
        result.email = item.Item.email
        result.created_at = item.Item.created_at
        result.verify_otp = item.Item.user_confirm
        return callback(null, response(200, result));
    }
}
exports.refreshToken = async (event, context, callback) => {
    const reqBody = JSON.parse(event.body);
    if (
        isEmpty(reqBody.access_token) ||
        isEmpty(reqBody.refresh_token)
    ) {
        resultError.message = "The required parameters are not enough";
        return callback(null, response(400, resultError));
    }
    const cognitoRefreshToken = await Cognito.refreshToken(getCustomerEmail(reqBody.access_token), reqBody.refresh_token);
    return callback(null, response(200, cognitoRefreshToken));
}

exports.autoConfirmUser = async (event, context, callback) => {
    event.response.autoConfirmUser = true;
    event.response.autoVerifyEmail = true;
    context.done(null, event);
}