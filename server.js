var express = require('express');
var bodyParser = require('body-parser');
var fs = require('fs');
var bcrypt = require('bcryptjs');
var jwt = require('jsonwebtoken');
var nodemailer = require('nodemailer');
var passport = require('passport');
var GoogleStrategy = require('passport-google-oauth20').Strategy;
var axios = require('axios');
const { createCheckoutSession } = require('./stripe');
const { createPayment } = require('./paypal');
var session = require('express-session');

var app = express();
var SECRET_KEY = 's3cr3tK3yLuxeTrove2024!@#456';
const PORT = process.env.PORT || 8080;

// Hardcoded values for testing
const GOOGLE_CLIENT_ID = '444996944007-89b5f974jk3lt3ptsnmarp7doqetd4b8.apps.googleusercontent.com';
const GOOGLE_CLIENT_SECRET = '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';
const EMAIL_USER = 'backendluxetrove@gmail.com';
const EMAIL_PASS = 'passtheword@2024';
const PAYPAL_CLIENT_ID = 'AZZCWOjzXpKhgbXWJBYznw65EaqmUh0Rf5LojIDe5wF0ckx_GHRFrm5_H7FHEaTEQ15LrGG8TyACkEgy'
const PAYPAL_CLIENT_SECRET = 'ELXGpKVoTTVA58ftV_Y1FRnhv_yWv1EWMYXjN_DuiD5Wa0XaVjqmaWVpJznAv8NtgMJr15mSQUYnF-u_'
const STRIPE_SECRET_KEY= 'sk_test_51PYQYLBoBI2Kef4Lz7UF51nq6N4mATzGPCdWmC5OVhGBezUkRvL2nBUMcNThe6Hb9DjvRnJkLVbdvTEBrXoirpDS00wENzZYX1'


// Middleware to parse JSON bodies
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({ secret: 'secret', resave: false, saveUninitialized: true }));
app.use(passport.initialize());
app.use(passport.session());
app.use(express.json());

// Simple logging middleware
app.use((req, res, next) => {
    console.log(`${req.method} request for '${req.url}'`);
    next();
});

// Nodemailer setup
var transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// Passport Google OAuth2 setup
passport.use(new GoogleStrategy({
    clientID: '444996944007-89b5f974jk3lt3ptsnmarp7doqetd4b8.apps.googleusercontent.com',
    clientSecret: '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',
    callbackURL: 'http://127.0.0.1:8080/auth/google/callback'
}, function(token, tokenSecret, profile, done) {
    // Implement user search or creation logic here
    // For simplicity, let's just return the profile
    return done(null, profile);
}));

passport.serializeUser(function(user, done) {
    done(null, user);
});

passport.deserializeUser(function(obj, done) {
    done(null, obj);
});

console.log('createCheckoutSession:', createCheckoutSession);
console.log('createPayment:', createPayment);


// Stripe payment route
app.post('/create-checkout-session', (req, res) => {
    console.log('Received request for create-checkout-session');
    createCheckoutSession(req, res);
});

// PayPal payment route
app.post('/create-payment', (req, res) => {
    console.log('Received request for create-payment');
    createPayment(req, res);
});

// Endpoint to Get a list of users
app.get('/getUsers', function(req, res) {
    fs.readFile(__dirname + "/" + "users.json", 'utf8', function(err, data) {
        if (err) {
            res.status(500).send('Error reading users file');
            return;
        }
        res.send(data);
    });
});

// User registration endpoint
app.post('/register', function(req, res) {
    var firstname = req.body.firstname;
    var lastname = req.body.lastname;
    var email = req.body.email;
    var phone = req.body.phone;
    var password = req.body.password;

    fs.readFile(__dirname + "/users.json", 'utf8', function(err, data) {
        if (err) {
            return res.status(500).send('Error reading users file');
        }
        var users = JSON.parse(data);

        // Check if user already exists
        if (Object.values(users).some(function(user) { return user.email === email; })) {
            return res.status(400).send('User already exists');
        }

        bcrypt.hash(password, 10, function(err, hashedPassword) {
            if (err) {
                console.error('Error hashing password:', err);
                return res.status(500).send('Error hashing password');
            }

            var newUserId = Object.keys(users).length + 1;
            var newUser = {
                id: newUserId,
                firstname: firstname,
                lastname: lastname,
                email: email,
                phone: phone,
                password: hashedPassword
            };

            users["user" + newUserId] = newUser;

            fs.writeFile(__dirname + "/users.json", JSON.stringify(users, null, 2), function(err) {
                if (err) {
                    return res.status(500).send('Error writing users file');
                }
                res.status(201).send(newUser);
            });
        });
    });
});

// Endpoint to update a user's profile
app.put('/updateUser', function(req, res) {
    console.log('Received PUT request to /updateUser');
    console.log('Request body:', req.body);

    fs.readFile(__dirname + "/" + "users.json", 'utf8', function(err, data) {
        if (err) {
            res.status(500).send('Error reading users file');
            return;
        }

        var users = JSON.parse(data);
        var userId = req.body.id;
        var user = users["user" + userId];

        if (!user) {
            res.status(404).send('User not found');
            return;
        }

        user.firstname = req.body.firstname || user.firstname;
        user.lastname = req.body.lastname || user.lastname;
        user.email = req.body.email || user.email;
        if (req.body.password) {
            bcrypt.hash(req.body.password, 10, function(err, hashedPassword) {
                if (err) {
                    res.status(500).send('Error hashing new password');
                    return;
                }
                user.password = hashedPassword;

                users["user" + userId] = user;

                fs.writeFile(__dirname + "/" + "users.json", JSON.stringify(users, null, 2), function(err) {
                    if (err) {
                        res.status(500).send('Error writing users file');
                        return;
                    }

                    var mailOptions = {
                        from: process.env.EMAIL_USER,
                        to: user.email,
                        subject: 'Profile Update Confirmation',
                        text: 'Your profile has been updated successfully.'
                    };

                    transporter.sendMail(mailOptions, function(error, info) {
                        if (error) {
                            console.error('Error sending email:', error);
                            res.status(500).send('Error sending confirmation email');
                        } else {
                            console.log('Email sent: ' + info.response);
                            res.status(200).send(user);
                        }
                    });
                });
            });
        } else {
            users["user" + userId] = user;

            fs.writeFile(__dirname + "/" + "users.json", JSON.stringify(users, null, 2), function(err) {
                if (err) {
                    res.status(500).send('Error writing users file');
                    return;
                }

                var mailOptions = {
                    from: process.env.EMAIL_USER,
                    to: user.email,
                    subject: 'Profile Update Confirmation',
                    text: 'Your profile has been updated successfully.'
                };

                transporter.sendMail(mailOptions, function(error, info) {
                    if (error) {
                        console.error('Error sending email:', error);
                        res.status(500).send('Error sending confirmation email');
                    } else {
                        console.log('Email sent: ' + info.response);
                        res.status(200).send(user);
                    }
                });
            });
        }
    });
});


// User login endpoint
app.post('/login', function(req, res) {
    var email = req.body.email;
    var password = req.body.password;

    fs.readFile(__dirname + "/users.json", 'utf8', function(err, data) {
        console.error('Error reading users file:', err);
        if (err) {
            return res.status(500).send('Error reading users file');
        }
        var users = JSON.parse(data);

        var user = Object.values(users).find(function(user) { return user.email === email; });
        if (!user) {
            console.log('User not found with email:', email);
            return res.status(400).send('Invalid email or password');
        }

        bcrypt.compare(password, user.password, function(err, isMatch) {
            if (err) {
                console.error('Error comparing passwords:', err);
                return res.status(500).send('Error comparing passwords');
            }
            if (!isMatch) {
                console.log('Password mismatch for user:', email);
                return res.status(400).send('Invalid email or password');
            }

            var token = jwt.sign({ id: user.id, email: user.email }, SECRET_KEY, { expiresIn: '1h' });
            console.log('User logged in successfully:', email);
            res.send({ token: token });
        });
    });
});

// User logout endpoint
app.post('/logout', function(req, res) {
    req.logout(function(err) {
        if (err) {
            return res.status(500).send('Error logging out');
        }
        res.send('Logged out successfully');
    });
});

// Password recovery endpoint
app.post('/recoverPassword', function(req, res) {
    var email = req.body.email;

    fs.readFile(__dirname + "/users.json", 'utf8', function(err, data) {
        if (err) {
            return res.status(500).send('Error reading users file');
        }
        var users = JSON.parse(data);

        var user = Object.values(users).find(function(user) { return user.email === email; });
        if (!user) {
            return res.status(400).send('User not found');
        }

        var resetToken = jwt.sign({ id: user.id, email: user.email }, SECRET_KEY, { expiresIn: '15m' });
        var resetLink = 'http://127.0.0.1:8080/resetPassword?token=' + resetToken;

        var mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Password Recovery',
            text: 'Click the following link to reset your password: ' + resetLink
        };

        transporter.sendMail(mailOptions, function(error, info) {
            if (error) {
                return res.status(500).send('Error sending email');
            }
            res.send('Password recovery email sent');
        });
    });
});

// Password reset endpoint
app.post('/resetPassword', function(req, res) {
    var token = req.body.token;
    var newPassword = req.body.newPassword;

    try {
        var decoded = jwt.verify(token, SECRET_KEY);
        fs.readFile(__dirname + "/users.json", 'utf8', function(err, data) {
            if (err) {
                return res.status(500).send('Error reading users file');
            }
            var users = JSON.parse(data);

            var user = users["user" + decoded.id];
            if (!user) {
                return res.status(400).send('Invalid token');
            }

            bcrypt.hash(newPassword, 10, function(err, hashedPassword) {
                if (err) {
                    return res.status(500).send('Error hashing new password');
                }

                user.password = hashedPassword;
                fs.writeFile(__dirname + "/users.json", JSON.stringify(users, null, 2), function(err) {
                    if (err) {
                        return res.status(500).send('Error writing users file');
                    }
                    res.send('Password reset successfully');
                });
            });
        });
    } catch (err) {
        res.status(500).send('Error processing request');
    }
});

// Endpoint to verify user account
app.post('/verifyAccount', function(req, res) {
    var userId = req.body.userId; // Assuming userId is sent from client-side or stored in session
    var identification = req.body.identification; // Valid means of identification
    var residentialAddress = req.body.residentialAddress; // Residential address

    // Here you can implement verification logic
    // For simplicity, we'll just send a success response
    res.status(200).json({ message: 'Account verified successfully' });
});

const GIG_API_URL = 'https://api.giglogistics.com/';
const DHL_API_URL = 'https://api.dhl.com/';

const currencies = ['NGN', 'ZAR', 'USD'];
let currentCurrency = 'USD';

// Middleware to switch currency
app.use((req, res, next) => {
    const { currency } = req.query;
    if (currency && currencies.includes(currency)) {
      currentCurrency = currency;
    }
    next();
  });

// Endpoint to get shipping rates from GIG
app.get('/shipping/gig', async (req, res) => {
    try {
      const response = await axios.get(GIG_API_URL, { params: { currency: currentCurrency } });
      res.json(response.data);
    } catch (error) {
      res.status(500).send('Error fetching GIG shipping rates');
    }
  });
  
  // Endpoint to get shipping rates from DHL
  app.get('/shipping/dhl', async (req, res) => {
    try {
      const response = await axios.get(DHL_API_URL, { params: { currency: currentCurrency } });
      res.json(response.data);
    } catch (error) {
      res.status(500).send('Error fetching DHL shipping rates');
    }
  });
  
  // Endpoint to switch currency
  app.get('/currency', (req, res) => {
    res.json({ currentCurrency });
  });
  
  // Example endpoint to get the list of currencies
  app.get('/currencies', (req, res) => {
    res.json({ currencies });
  });

// Mock shipping rates
app.post('/shippingRates', async (req, res) => {
    try {
        const { origin, destination, weight, type } = req.body;
        const endpoint = type === 'international' ? 'internationalShippingRates' : 'localShippingRates';
        
        // Fetch the data from db.json
        const response = require('./db.json'); // Load the JSON directly
        
        // Find the matching rates based on origin, destination, and weight
        const rates = response[endpoint].find(rate => 
            rate.origin === origin && 
            rate.destination === destination && 
            rate.weight === weight
        ).rates;

        res.send(rates);
    } catch (error) {
        console.error('Error fetching shipping rates:', error);
        res.status(500).send('Error fetching shipping rates');
    }
});

// Mock create shipment
app.post('/createShipment', async (req, res) => {
    try {
        const response = await axios.post('http://localhost:3000/createShipment', req.body);
        res.send(response.data);
    } catch (error) {
        res.status(500).send('Error creating shipment');
    }
});


// Mock track shipment
app.get('/trackShipment/:trackingNumber', async (req, res) => {
    try {
        const trackingNumber = req.params.trackingNumber;
        const response = await axios.get(`http://localhost:3000/trackShipment`);
        const trackingStatus = response.data.status;
        res.send({ trackingNumber, status: trackingStatus });
    } catch (error) {
        res.status(500).send('Error tracking shipment');
    }
});

// Google OAuth2 routes
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback', passport.authenticate('google', { failureRedirect: '/' }), function(req, res) {
    res.redirect('/success.html');
});


// Create a server to listen at port 8080
app.listen(PORT, '0.0.0.0', function() {
    console.log("REST API demo app listening at http://0.0.0.0:" + PORT);
});

