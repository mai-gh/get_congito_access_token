#!/usr/bin/env node

const { UserPool } = require("cognito-srp");
const axios = require("axios");
const moment = require("moment-timezone");

const main = async () => {
  const username = process.env.USERNAME;
  const password = process.env.PASSWORD;
  const clientId = process.env.CLIENTID;
  const userPoolId = process.env.USERPOOLID;

  if (!( process.env.USERNAME && process.env.PASSWORD && process.env.CLIENTID && process.env.USERPOOLID)) {
    console.log( "\n ERROR: **** must provide USERNAME PASSWORD CLIENTID USERPOOLID as environment variables ****\n");
    console.log( " EXAMPLE: $ USERNAME=aaa PASSWORD=bbb CLIENTID=ccc USERPOOLID=ddd node get_congito_access_token.js\n");
    process.exit();
  }

  const [poolSrv, poolName] = userPoolId.split("_");
  const userAgent = "Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0";
  const userPool = new UserPool(poolName);
  const challenge = await userPool.getClientChallenge({ username, password });
  const srpA = challenge.calculateA();

  const firstResponse = await axios({
    method: "POST",
    url: `https://cognito-idp.${poolSrv}.amazonaws.com/`,
    headers: {
      "Content-Type": "application/x-amz-json-1.1",
      "X-Amz-Target": "AWSCognitoIdentityProviderService.InitiateAuth",
      "User-Agent": userAgent,
    },
    data: {
      AuthFlow: "USER_SRP_AUTH",
      ClientId: clientId,
      AuthParameters: {
        USERNAME: username,
        SRP_A: srpA.toString("hex"),
      },
      ClientMetadata: {},
    },
  });

  const timestamp = firstResponse.headers.date;
  const fixedTimestamp = moment(timestamp).tz("UTC").format("ddd MMM DD HH:mm:ss zz YYYY");
  const srpB = firstResponse.data.ChallengeParameters.SRP_B;
  const salt = firstResponse.data.ChallengeParameters.SALT;
  const secretBlock = firstResponse.data.ChallengeParameters.SECRET_BLOCK;
  const session = challenge.getSession(srpB, salt);
  const signature = session.calculateSignature(secretBlock, fixedTimestamp);

  const secondResponse = await axios({
    method: "POST",
    url: `https://cognito-idp.${poolSrv}.amazonaws.com/`,
    headers: {
      "Content-Type": "application/x-amz-json-1.1",
      "X-Amz-Target": "AWSCognitoIdentityProviderService.RespondToAuthChallenge",
      "User-Agent": userAgent,
    },
    data: {
      ChallengeName: "PASSWORD_VERIFIER",
      ClientId: clientId,
      ChallengeResponses: {
        USERNAME: username,
        PASSWORD_CLAIM_SECRET_BLOCK: secretBlock,
        TIMESTAMP: fixedTimestamp,
        PASSWORD_CLAIM_SIGNATURE: signature,
      },
      ClientMetadata: {},
    },
  });

  process.stdout.write(secondResponse.data.AuthenticationResult.AccessToken);
};

main();
