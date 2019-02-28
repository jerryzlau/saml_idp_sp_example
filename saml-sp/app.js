
// saml2-js
const saml2 = require('saml2-js');

const fs = require('fs');
const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');

const app = express();
app.set('view engine', 'ejs');

app.use(session({
  secret: 'jTje8019P4ZKhm9q3bkmxsFhCxvnKcug',
  resave: true,
  saveUninitialized: true
}));
app.use(bodyParser.json()); // to support JSON-encoded bodies
app.use(bodyParser.urlencoded({ // to support URL-encoded bodies
  extended: false
}));

// Create service provider
const spOptions = {
  entity_id: 'http://localhost:3000/login',
  private_key: fs.readFileSync('./key-test.pem').toString(),
  certificate: fs.readFileSync('./cert-test.pem').toString(),
  assert_endpoint: 'http://localhost:3000/assert',
  allow_unencrypted_assertion: true /* FOR TESTING ONLY */
};
const sp = new saml2.ServiceProvider(spOptions);

// Create identity provider
const idpOptions = {
  sso_login_url: 'http://localhost:7000/saml/sso',
  sso_logout_url: 'http://localhost:7000/saml/slo',
  certificates: [fs.readFileSync('./idp-public-cert.pem').toString()]
};
const idp = new saml2.IdentityProvider(idpOptions);

app.get('/', (req, res) => {
  const nameId = (req.session.user) ? req.session.user.name_id : null;
  res.render('index', { nameId });
});

app.get('/metadata.xml', (req, res) => {
  res.type('application/xml');
  res.send(sp.create_metadata());
});

app.all('/login', (req, res) => {
  sp.create_login_request_url(idp, {}, (err, loginUrl, requestId) => {
    if (err != null) return res.send(500);
    return res.redirect(loginUrl);
  });
});

// Assert endpoint for when login completes
app.post('/assert', (req, res) => {
  const options = { request_body: req.body };
  sp.post_assert(idp, options, (err, samlResponse) => {
    if (err != null) return res.send(500);

    if (samlResponse) {
      req.session.user = samlResponse.user;
      console.log(samlResponse.user);
    }

    return res.redirect('/');
  });
});

app.get('/logout', (req, res) => {
  const options = {
    name_id: req.session.user.name_id,
    session_index: req.session.user.session_index
  };
  sp.create_logout_request_url(idp, options, (err, logoutUrl) => {
    if (err != null) return res.send(500);
    return res.redirect(logoutUrl);
  });
});

app.post('/logout', (req, res) => {
  delete req.session.user;
  return res.redirect('/');
});

app.listen(3000, () => {
  console.log('Running on 3000');
});

