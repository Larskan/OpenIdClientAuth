# Intro
Contains a web application that allows users to authenticate using their credentials in Keycloak

# Getting Started

Need to have the following installed:

Node.js installed, can be found here:
[Link to installing Node.js](https://nodejs.org/en/download)

Docker installed, can be found here:
[Link to installing Docker](https://www.docker.com/products/docker-desktop/)

Install express handlebars:
```bash
npm install express express-handlebars node-fetch
```
Install typescript:
```bash
npm install --save-dev typescript concurrently nodemon @types/express @types/node @types/express-handlebars @types/node-fetch
```
Install jwks-rsa:
```bash
npm install --save jwks-rsa
```

Need to have Keycloaks set up with a Client and Docker running

# Enter the index.ts and run it
```bash
npm run dev
```

# Interaction
## Login Route
Generates state and code verifier, stores them in cache then builds login URL and redirects to Keycloak where OAuth 2.0 is kicked off

## Callback Route
Called by Keycloak after user logs in

Reads auth code and state from URL and verifies that the state is valid and retrieves the matching codeVerifier from cache

Sends request to Keycloak to exchange the code for tokens and verifies the id_token using Keycloaks public key - Here the Token is decoded and verified, if successful, it stores user info as a cookie. 

Fetches user info from Keycloak using the access_token and stores user info in a secure cooke(user) for later.

Redirects the user to /finish to prove that login worked with Auth

## Finish Route
There as a proof of concept that redirection happens, for an actual project the redirection would be toward your actual website.

## Decoding process shown through console logs
- ![Decoding](https://i.gyazo.com/b082e1140c2ab3ee6369c88cadce5171.png)



