var express = require('express');
var bodyParser = require('body-parser');
var fs = require('fs');
var bcrypt = require('bcryptjs');
var jwt = require('jsonwebtoken');
var nodemailer = require('nodemailer');
var passport = require('passport');
var GoogleStrategy = require('passport-google-oauth20').Strategy;
var session = require('express-session');

var app = express();
var SECRET_KEY = 's3cr3tK3yLuxeTrove2024!@#456';
var PORT = 8080;

// Middleware to parse JSON bodies
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({ secret: 'secret', resave: false, saveUninitialized: true }));
app.use(passport.initialize());
app.use(passport.session());

// Simple logging middleware
app.use((req, res, next) => {
    console.log(`${req.method} request for '${req.url}'`);
    next();
});

// Nodemailer setup
var transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: 'backendluxetrove@gmail.com',
        pass: 'passtheword@2024'
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
                        from: 'backendluxetrove@gmail.com',
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
                    from: 'backendluxetrove@gmail.com',
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
            from: 'backendluxetrove@gmail.com',
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


// Google OAuth2 routes
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback', passport.authenticate('google', { failureRedirect: '/' }), function(req, res) {
    res.redirect('/success.html');
});

const PORT = process.env.PORT || 8080;
// Create a server to listen at port 8080
app.listen(PORT, '127.0.0.1', function() {
    console.log("REST API demo app listening at http://127.0.0.1:" + PORT);
});
