const bcryptjs = require('bcryptjs');
const { validationResult } = require('express-validator/check');

const User = require('../models/user');

exports.getLogin = (req, res, next) => {
  // const isAuthenticated =
  //   req.get('Cookie').split(';')[1].trim().split('=')[1] === 'true';
  let message = req.flash('error');
  if (message.length > 0) {
    message = message[0];
  } else {
    message = null;
  }
  res.render('auth/login', {
    path: '/login',
    pageTitle: 'Login Form',
    errorMessage: message,
    oldInput: {
      email: '',
      password: '',
    },
    validationError: [],
  });
};

exports.getSignup = (req, res, next) => {
  let message = req.flash('error');
  if (message.length > 0) {
    message = message[0];
  } else {
    message = null;
  }
  res.render('auth/signup', {
    path: '/signup',
    pageTitle: 'Signup',
    isAuthenticated: false,
    errorMessage: message,
    oldInput: {
      email: '',
      password: '',
      confirmPassword: '',
    },
    validationError: [],
  });
};

exports.postLogin = (req, res, next) => {
  const email = req.body.email;
  const password = req.body.password;
  const errors = validationResult(req);

  if (!errors.isEmpty()) {
    return res.status(422).render('auth/login', {
      path: '/login',
      pageTitle: 'Login Form',
      errorMessage: errors.array()[0].msg,
      oldInput: {
        email: email,
        password: password,
      },
      validationError: errors.array(),
    });
  }

  User.findOne({ email: email }).then((user) => {
    //user not found keep the old input
    if (!user) {
      return res.status(422).render('auth/login', {
        path: '/login',
        pageTitle: 'Login Form',
        errorMessage: 'Invalid email or password.',
        oldInput: {
          email: email,
          password: password,
        },
        validationError: [],
      });
    }

    bcryptjs
      .compare(password, user.password)
      .then((doMatch) => {
        if (doMatch) {
          req.session.isLoggedIn = true;
          req.session.user = user;
          return req.session.save((err) => {
            return res.redirect('/');
          });
        }
        return res.status(422).render('auth/login', {
          path: '/login',
          pageTitle: 'Login Form',
          errorMessage: 'Incorrect password',
          oldInput: {
            email: email,
            password: password,
          },
          validationError: [],
        });
      })
      .catch((e) => {
        console.log(e);
        res.redirect('/login');
      });
  });
};

exports.postSignup = async (req, res, next) => {
  try {
    const email = req.body.email;
    const password = req.body.password;
    const errors = validationResult(req);

    //error
    if (!errors.isEmpty()) {
      return res.status(422).render('auth/signup', {
        path: '/signup',

        pageTitle: 'Signup',

        errorMessage: errors.array()[0].msg,

        oldInput: {
          email,
          password,
          confirmPassword: req.body.confirmPassword,
        },

        validationError: errors.array(),
      });
    }

    const hashedPassword = await bcryptjs.hash(password, 12);
    const user = new User({
      email: email,
      password: hashedPassword,
      cart: { items: [] },
    });

    await user.save();
    console.log('USER CREATED!');
    req.flash('error', 'Sign-up successfull');
    res.redirect('/login');
  } catch (err) {
    const error = new Error(err);
    error.httpStatusCode = 500;
    return next(error);
  }
};

exports.postLogout = async (req, res, next) => {
  try {
    await req.session.destroy();
    res.redirect('/');
  } catch (err) {
    const error = new Error(err);
    error.httpStatusCode = 500;
    return next(error);
  }
};

exports.getReset = (req, res, next) => {
  let message = req.flash('error');
  if (message.length > 0) {
    message = message[0];
  } else {
    message = null;
  }
  res.render('auth/reset', {
    path: '/reset',
    pageTitle: 'Reset Password',
    errorMessage: message,
  });
};
//IMPORTANT : Once the response is sent,req data is finished.It doesn't float around the controllers and routes.

//problem here is
//1. req object has true value in isLoggedin property
//2.response is sent with 'home' view
//3.so problem with navigation is that it doesn't get the isLoggedIn property.

//req.isLoggedIn = true
// res.setHeader('Set-Cookie', 'isLoggedIn=true');
