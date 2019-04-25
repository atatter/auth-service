const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const sessions = require('client-sessions');
const bcrypt = require('bcryptjs');
const app = express();

// Setup session
app.use(sessions({
    cookieName: 'session',
    secret: 'itisnotreallyagoodsecret',
    httpOnly: true,
    duration: 30 * 60 * 1000, // 30 mins
}));

// Setup mongodb connection
mongoose.connect('mongodb://localhost/auth-service', { useNewUrlParser: true })
let User = mongoose.model('User', new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
}));

// Setup application/json reader
app.use(bodyParser.json());

app.post('/login', (req, res) => {
    User.findOne({ email: req.body.email }, (err, user) => {
        if (err || !user || !bcrypt.compareSync(req.body.password, user.password)) {
            return res.send({ error: 'Incorrect email / password' });
        }
        req.session.userId = user._id;
        res.send({ message: 'Successfully logged in' });
    });
});

// User session middleware
app.use((req, _, next) => {
    if (!(req.session && req.session.userId)) return next();
    User.findById(req.session.userId, (err, user) => {
        if (err) return next(err);
        if (!user) return next();
        user.password = undefined;
        req.user = user;
        next();
    });
});

// User login required helper
function loginRequired(req, res, next) {
    if (!req.user) return res.status(403).send({ error: 'Authentication required' });
    next();
}

app.post('/logout', (req, res) => {
    req.session.reset();
    res.send({ message: 'Successfully logged out!' });
});

app.post('/register', (req, res) => {
    let hash = bcrypt.hashSync(req.body.password, 14);
    req.body.password = hash;
    const user = new User(req.body);
    user.save(err => {
        if (err) {
            let error = 'Something went wrong!';
            if (err.code === 11000) error = 'This email is already taken.';
            return res.send({ error });
        }
        res.send({ message: 'User created.' });
    });
});

app.get('/', loginRequired, (_, res) => {
    res.send({ message: 'Hello!' });
});

app.listen(8080);