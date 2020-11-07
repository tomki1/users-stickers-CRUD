const express = require('express');
const bcrypt = require('bcrypt');
const router = express.Router();
const User = require('../db/user');


// routes paths are prepended with /auth
router.get('/', (req, res) => {
    res.json({
        message: '👨‍'
    });
});

function validUser(user) {
    const validEmail = typeof user.email == 'string' && user.email.trim() != '';
    const validPassword = typeof user.password == 'string' && user.password.trim() != '' && user.password.trim().length >=6;

    return validEmail && validPassword;
}

router.post('/signup', (req, res, next) => {
    if(validUser(req.body)) {
        User
            .getOneByEmail(req.body.email)
            .then(user => {
                console.log('user', user);
                // if user not found
                if(!user) {
                // then it is a unique email
                // hash password
                bcrypt.hash(req.body.password, 10)
                    .then((hash) => {
                    const user = {
                    email: req.body.email,
                    password: hash,
                    created_at: new Date()
                    };
                    User
                        .create(user)
                        .then(id => {
                            setUserIdCookie(req, res, id);

                            res.json({
                                id,
                                message: 'unique user'
                            });
                        });
               
               
            });
            }
            else { // email in use
                next(new Error('Email in use'));
            }
                
            });
      
    } else 
    {// send an error
        next(new Error('Invalid user'));
    }
    
});

function setUserIdCookie(req, res, id) {
    const isSecure = req.app.get('env') != 'development';
    res.cookie('user_id', id, {
        httpOnly: true,
        secure: isSecure,
        signed: true

    });
}

router.post('/login', (req, res, next) => {
    // check to see if user is in database
    if(validUser(req.body)) {
        User    
            .getOneByEmail(req.body.email)
            .then(user => {


               
                if (user) {
                    // check password against hashed password
                    bcrypt
                        .compare(req.body.password, user.password)
                        .then((result) => {
                            // if the passwords matched
                            if(result) {
                                // set set-cookie header
                                setUserIdCookie(req, res, user.id);
 
                                res.json({
                                    id: user.id,
                                    message: 'logged in'
                                  });

                            }
                            else {
                                next(Error("Invalid login1"));
                            }
                           
                        
                    });
                    

                }

                else {
                    next(Error("Invalid login2"));
                }
              

    });
}
    else {
        next(new Error('Invalid login3'));
    }
});


router.get('/logout', (req, res) => {

    res.clearCookie('user_id');
    res.json({
        message: 'you are logged out'
    });
});


module.exports = router;