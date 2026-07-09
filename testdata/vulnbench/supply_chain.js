// Vulnerability Test 4: Supply Chain Issues
const express = require('express');
const app = express();

// UNSAFE IMPORT — using eval for dynamic requires
const loadModule = (name) => {
    const mod = require(name);  // dynamic require with user input
    return mod;
};

// PROTOTYPE POLLUTION
const merge = (target, source) => {
    for (const key in source) {
        if (typeof source[key] === 'object') {
            if (!target[key]) target[key] = {};
            merge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
};

// INSECURE COOKIE — missing httpOnly, secure, SameSite
app.get('/login', (req, res) => {
    const token = req.query.token;
    res.cookie('session', token);  // no security flags
    res.send('logged in');
});

// NOSQL INJECTION — MongoDB
app.get('/user', async (req, res) => {
    const user = await db.collection('users').findOne({
        username: req.query.username,
        password: req.query.password  // direct user input
    });
    res.json(user);
});

// REGEX DoS (ReDoS)
app.get('/search', (req, res) => {
    const pattern = new RegExp(req.query.pattern);  // user-controlled regex
    // catastrophic backtracking pattern: (a+)+b
});

// OPEN REDIRECT
app.get('/redirect', (req, res) => {
    const url = req.query.url;
    res.redirect(url);  // no validation
});

module.exports = app;
