require('dotenv').config()

const express = require('express')
const cors = require('cors')
const mongoose = require('mongoose')
const port = process.env.PORT || 3001;
const userModel = require('./model/db')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const cookieParser = require('cookie-parser')
const ORIGIN_URL = process.env.ORIGIN_URL


const app = express()
app.use(express.json())
app.use(cookieParser())


app.use(cors({
    origin: ['http://localhost:4200'],
    methods: ["GET", "POST"],
    credentials: true
}
));


mongoose.connect('mongodb://127.0.0.1/elearning')
    .then(() => console.log('MongoDB is Connected!!'))
    .catch((error) => console.log(error))



const varifinguser = (req, res, next) => {
    const token = req.cookies.token;
    if (!token) {
        return res.json('Token is missing!')
    }
    else {
        jwt.verify(token, 'jwt-secret-key', (err, decoded) => {
            if (err) {
                return res.json('err is there')
            }
            else {
                if (decoded.role === 'admin') {
                    next()
                } else {
                    return res.json('Not admin')
                }
            }
        })
    }
}


app.get('/table', varifinguser, (req, res) => {
    res.json('Success!')
})
app.get('/', (req, res) => {
    res.send('Hello Nodejs')
    console.log('Backend is On!')
})


app.post('/signup', (req, res) => {
    const { name, email, role, password } = req.body;
    bcrypt.hash(password, 5)
        .then((hash) => {
            userModel.create({
                name,
                email,
                role,
                password: hash
            })
            .then(user => {
                const token = jwt.sign({ email: user.email, role: user.role }, "jwt-secret-key", { expiresIn: '1d' });
                res.status(200).json({ message: 'User created successfully!', token: token, role: user.role });
            })
            .catch(err => res.status(500).json({ error: "Failed to register user. Please try again later." }));
        })
        .catch(err => res.status(500).json({ error: 'Failed to hash password. Please try again later.' }));
});



app.post('/login', (req, res) => {
    const { email, role, password } = req.body;
    userModel.findOne({ email: email })
        .then(user => {
            if (user) {
                if (user.role === role) {
                    bcrypt.compare(password, user.password, (err, response) => {
                        if (response) {
                            const token = jwt.sign({ email: user.email, role: user.role }, "jwt-secret-key", { expiresIn: '1d' });
                            res.cookie("token", token, {
                                withCredentials: true,
                                httpOnly: false,
                            });
                            res.json({ message: 'Logged in successfully', role: user.role });
                            console.log('Logged in successfully!')
                            
                        } else {
                            console.log('Password is not matching!!');
                            res.status(401).json({ error: 'Password is not matching' });
                        }
                    });
                } else {
                    console.log('User role does not match!');
                    res.status(401).json({ error: 'User role does not match' });
                }
            } else {
                res.status(404).json({ error: 'User not found' });
            }
        })
        .catch(err => {
            console.error('Internal Server Error:', err);
            res.status(500).send('Internal Server Error');
        });
});


app.listen(port, () => {
    console.log(`The server is working on the ${port} `)
})