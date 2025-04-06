import express from "express";
import cookieParser from "cookie-parser";
import { engine } from "express-handlebars";
import crypto from "crypto";
import dotenv from "dotenv";
import fetch from "node-fetch";
import jwksClient from "jwks-rsa";
import jwt from "jsonwebtoken";
import { URLSearchParams } from "url";

// NOTE TO SELF WHEN USING NODE EXPRESS: INDEX.JS DOES NOT UPDATE AUTOMATICALLY
// DO -- npx tsc -- TO UPDATE
// RUN WITH: node dist/index.js

// Loading environment variables
dotenv.config();

const app = express();
console.log("Express Loaded");

//#region Handlebars setup
app.engine("handlebars", engine());
app.set("view engine", "handlebars");
app.set("views", "./views");
//#endregion Handlebars setup

// Using cookies
app.use(cookieParser("SuchSecretMuchWow"));

// Caching. In memory state storage
const cache = new Map<string, string>();
console.log("Cache loaded with: ", cache);

//#region Necessary environment constants
const {
  CLIENT_ID,
  CLIENT_SECRET,
  REDIRECT_URI,
  KEYCLOAK_BASE_URL,
  REALM
} = process.env;
//#endregion Necessary environment constants

//#region Reusing config from Keycloak
let config: any;

async function fetchConfig() {
  if (!config) {
    const res = await fetch(`${KEYCLOAK_BASE_URL}/realms/${REALM}/.well-known/openid-configuration`);
    config = await res.json();
  }
  return config;
}
//#endregion Reusing config from Keycloak

//#region Helpers for PKCE
function generateRandomString(size = 32): string {
  return crypto.randomBytes(size).toString("hex");
}

function base64URLEncode(str: Buffer): string {
  return str.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function sha256(buffer: string): Buffer {
  return crypto.createHash("sha256").update(buffer).digest();
}
//#endregion Helpers for PKCE

//#region Home Route
app.get("/", (req, res) => {
  // Reads user cookie to see if someone is logged in
  const user = req.cookies["user"];
  console.log("User from cookie: ", user);
  // If user is found, user name for the page
  const name = user?.name || "world";
  // Render home.handlebars
  res.render("home", { placeholder: name });
});
//#endregion Home Route

//#region Login Route
// Generates state and code verifier, stores them in cache, 
// builds login URL and redirects to Keycloak where OAuth 2.0 is kicked off
app.get("/login", async (req, res) => {
  const config = await fetchConfig();
  // Secure state and codeVerifier
  const state = generateRandomString();
  const codeVerifier = generateRandomString();
  // Proof Key for Code Exchange(PKCE) code challenge
  const codeChallenge = base64URLEncode(sha256(codeVerifier));

  cache.set(state, codeVerifier);

  // Auth Request
  const params = new URLSearchParams({
    client_id: CLIENT_ID!,
    scope: "openid email phone address profile",
    response_type: "code",
    redirect_uri: REDIRECT_URI!,
    prompt: "login",
    state: state,
    code_challenge_method: "S256",
    code_challenge: codeChallenge
  });
  res.redirect(`${config.authorization_endpoint}?${params.toString()}`); //Redirect to Keycloak
});
//#endregion Login Route

//#region Callback - Auth Response
// Called by Keycloak after user logs in
// Reads auth code and state from URL
// Verifies that the state is valid and retrieves the matching codeVerifier from cache
// Sends request to Keycloak to exchange the code for tokens
// Verifies the id_token using Keycloaks public key
// Fetches user info from Keycloak using the access_token
// Stores user info in a secure cooke(user) for later.
// Redirects the user to /finish to prove that login worked with Auth
app.get("/callback", async (req, res) => {
  console.log("Callback query parameters:", req.query);
  const { state, code } = req.query as { state: string; code: string };
  const codeVerifier = cache.get(state)!;
  cache.delete(state); // Cleaning

  const config = await fetchConfig();

  // Exchange auth code for tokens
  const parameters = {
    grant_type: "authorization_code",
    code: code,
    redirect_uri: REDIRECT_URI!,
    code_verifier: codeVerifier,
    client_id: CLIENT_ID!,
    client_secret: CLIENT_SECRET!,
  };

  const response = await fetch(config.token_endpoint, {
    method: "POST",
    body: new URLSearchParams(parameters),
  });

  const tokenData = await response.json() as TokenResponse;
  const { id_token, access_token } = tokenData;

  console.log("ID Token before decode: ", id_token);
  const decoded = jwt.decode(id_token, { complete: true });
  console.log("ID Token after decode: ", decoded);

  //Verify ID Token
  const client = jwksClient({ jwksUri: config.jwks_uri });
  const key = await new Promise<string>((resolve, reject) => {
    client.getSigningKey(decoded?.header.kid, (err, key) => {
      if (err) return reject(err);
      resolve((key as any).getPublicKey());
    });
  });

  try {
    const verifiedToken = jwt.verify(id_token, key, {
      algorithms: ["RS256"],
      audience: CLIENT_ID,
      issuer: `${KEYCLOAK_BASE_URL}/realms/${REALM}`
    }) as jwt.JwtPayload;

   // User info as a cookie
   res.cookie("user", verifiedToken, {httpOnly: true, secure: false, sameSite: "lax", maxAge: 3600*1000});

    //Fetch user info and set it in the cookie
    const userInfoRes = await fetch(config.userinfo_endpoint, {
      headers: { Authorization: `Bearer ${access_token}` },
    });

    const user = await userInfoRes.json();
    res.cookie("user", user, {httpOnly: true, maxAge: 3600*1000});

    res.redirect("/finish");
  } catch (err) {
    console.error(err);
    res.status(401).send("Token verification failed");
  }
  res.send();
});
//#endregion Callback - Auth Response

//#region Finish route to confirm it actually redirects after successful callback
app.get("/finish", (req, res) => {
  const user = req.cookies["user"];
  const name = user?.name || "Woop";
  res.render("finish", {placeholderTwo: name});
});
//#endregion Finish route to confirm it actually redirects after successful callback

const port = 3000;
app.listen(port, () =>
  console.log(`App listening to port http://localhost:${port}`),);
