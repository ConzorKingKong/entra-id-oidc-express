require('dotenv').config()

const express = require('express');
const session = require('express-session');
const axios = require('axios');
const qs = require('querystring');
const crypto = require('crypto');
const cookieParser = require('cookie-parser');


const app = express();

// Configuration settings for Microsoft Entra ID
const config = {
  clientId: process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET_VALUE,
  redirectUri: "http://localhost:3000/auth/callback",
  scope: ["openid", "email", "profile"]
};

// Add session middleware
app.use(session({
  secret: process.env.SECRET,
  resave: false,
  saveUninitialized: true
}));

app.use(cookieParser(process.env.COOKIE_SECRET));

// The root path links us to the /auth endpoint, which generates
// the url to start oauth flow
app.get('/', (req, res) => {
  res.send('<a href="/auth">Login with Microsoft Entra ID</a>');
});

// The auth endpoint generates our oauth url for Microsoft Entra ID
app.get('/auth', (req, res) => {

  require('crypto').randomBytes(24, function(err, buffer) {
    let stateParam = buffer.toString('hex');
    res.cookie("stateParam", stateParam, { maxAge: 1000 * 60 * 5, signed: true });

    const authUrl = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?" + qs.stringify({
      client_id: config.clientId,
      response_type: 'code',
      redirect_uri: config.redirectUri,
      response_mode: 'query',
      scope: config.scope.join(" "),
      state: stateParam
    });

    res.redirect(authUrl);
  });

  
});

// This is our Redirect URI
// After the flow has started, Microsoft sends us back
// an authorization code, authorizing us to get access and refresh tokens
// on behalf of the user
app.get('/auth/callback', async (req, res) => {
  const { code, state } = req.query;
  const { stateParam } = req.signedCookies;

  if (stateParam !== state) {
    res.status(422).send("Invalid State");
    return;
  }

  const tokenUrl = "https://login.microsoftonline.com/common/oauth2/v2.0/token?";

  const tokenParams = {
    client_id: config.clientId,
    scope: config.scope.join(" "),
    code,
    redirect_uri: config.redirectUri,
    grant_type: 'authorization_code',
    client_secret: config.clientSecret
  };

  try {
    const response = await axios.post(tokenUrl, qs.stringify(tokenParams), {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      }
    });

    // save the token data in the user session in express
    req.session.tokenSet = response.data;
    res.redirect('/profile');
  } catch (error) {
    console.error('Token exchange error:', error);
    res.redirect('/');
  }
});

// grab token data from express session
// and get user info from microsoft
app.get('/profile', async (req, res) => {
  if (!req.session.tokenSet) {
    return res.redirect('/');
  }

  const { id_token } = req.session.tokenSet;

  // the main profile information is in the body
  // of the JWT
  const body = id_token.split(".")[1];

  // convert it from base64 to utf8
  let bufferObj = Buffer.from(body, "base64");
  let string = bufferObj.toString("utf8");

  res.send(`<h1>Profile</h1><span>${string}</span><br><br><a href="/logout">logout</a>`);
});

app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error(err);
    }
    res.redirect('/');
  });
});


const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});