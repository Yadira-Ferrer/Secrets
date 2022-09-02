//jshint esversion:6
const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const mongoose = require('mongoose');
const md5 = require('md5');
const bcrypt = require('bcrypt');
const saltRounds = 10;

require('dotenv').config();

const app = express();

app.use(express.static('public'));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));

mongoose.connect('mongodb://localhost:27017/user');

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
});

const User = new mongoose.model('User', userSchema);

app.get('/', (req, res) => {
  res.render('home');
});

app.get('/login', (req, res) => {
  res.render('login');
});

app.post('/login', (req, res) => {
  const username = req.body.username;
  const password = req.body.password;

  User.findOne({ email: username }, (err, user) => {
    if (err) {
      console.log(err);
    } else {
      if (user) {
        bcrypt.compare(password, user.password, (err, result) => {
          if (result) {
            res.render('secrets');
          }
        });
      }
    }
  });
});

app.get('/register', (req, res) => {
  res.render('register');
});

app.post('/register', (req, res) => {
  bcrypt.hash(req.body.password, saltRounds, (err, hash) => {
    const newUser = new User({
      email: req.body.username,
      password: hash,
    });

    newUser.save((err) => {
      if (err) {
        console.log(err);
      } else {
        res.render('secrets');
      }
    });
  });
});

app.listen(3000, () => console.log('Server is running on port 3000'));

/*
  Niveles de seguridad
  1 - Usuario y contraseña
  2 - Encriptar
    - Variables de entorno
  3 - Hashing Passwords
  4 - 'Salting' password + salt -> hash
      (*) Salt Rounds
  5 - Cookies & Sessions
      > npm i passport passport-local passport-local-mongoose express-session
 */
