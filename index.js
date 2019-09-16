const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const bcrypt = require('bcryptjs');

const db = require('./database/dbConfig.js');
const Users = require('./users/users-model.js');

const server = express();

server.use(helmet());
server.use(express.json());
server.use(cors());

function validateCredentials(req, res, next){
  let { username, password } = req.body;
  Users.findBy({ username })
    .first()
    .then(user => {
      if (user && bcrypt.compareSync(password, user.password)) {
        next();
      } else {
        res.status(401).json({ message: 'Invalid Credentials' });
      }
    })
    .catch(error => {
      res.status(500).json({message:'error validating credentials'});
    });
}

server.get('/', (req, res) => {
  res.send("It's alive!");
});

server.post('/api/register', (req, res) => {
  let {username, password} = req.body;
  const hash = bcrypt.hashSync(password, 8)
  Users.add({username, password: hash})
    .then(saved => {
      res.status(201).json(saved);
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

server.post('/api/login', validateCredentials, (req, res) => {
  let { username, password } = req.body;
  Users.findBy({ username })
    .first()
    .then(user => {
      if (user && bcrypt.compareSync(password, user.password)) {
        res.status(200).json({ message: `Welcome ${user.username}!` });
      } else {
        res.status(401).json({ message: 'Invalid Credentials' });
      }
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

server.get('/api/users', validateCredentials, (req, res) => {
  Users.find()
    .then(users => {
      res.json(users);
    })
    .catch(err => res.json({message: 'error getting users'}));
});

server.get('/hash', (req, res) => {
  const name = req.query.name;

  //hash the name

  const hash = bcrypt.hashSync(name, 8); // use bcryptjs to hash the name
  res.send(`the hash for ${name} is ${hash}`)
})


const port = process.env.PORT || 5000;
server.listen(port, () => console.log(`\n** Running on port ${port} **\n`));

/* Write a middleware that will check for the username and password
   (like with login) and let the request continue to /api/users if 
   credentials are good. Return 401 if credentials are invalid.

   Use the middleware to restrict access to GET /api/users endpoint.
*/