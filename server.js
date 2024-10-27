import express from "express";
import bodyParser from "body-parser";
import cors from "cors";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy } from "passport-local";
import GoogleStrategy from "passport-google-oauth2";
import session from "express-session";
import env from "dotenv";
import cookieParser from "cookie-parser";
import MongoStore from "connect-mongo";
import mongoose from "mongoose";

// Load environment variables
env.config();

const app = express();
const port = process.env.PORT || 5000;
const saltRounds = 10;
const mongoURL = process.env.MONGO_URL || "mongodb://localhost:27017";

// Connect to MongoDB
mongoose.connect(mongoURL, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log("MongoDB connected"))
    .catch(err => console.log("MongoDB connection error:", err));

// Define User and Book models
const UserSchema = new mongoose.Schema({
    username: String,
    password: String,
});

const BookSchema = new mongoose.Schema({
    userid: String,
    title: String,
    author: String,
    isbn: String,
    brief: String,
    DOC: String,
    rating: Number,
    summary: String,
    updation: Date,
});

const User = mongoose.model("User", UserSchema);
const Book = mongoose.model("Book", BookSchema);

// Set up session middleware
const store = MongoStore.create({
    mongoUrl: mongoURL,
    collectionName: 'sessions', // Specify the name of the collection
});

app.use(session({
    store: store,
    secret: process.env.SESSION_SECRET,
    resave: true,
    saveUninitialized: false,
    cookie: {
        maxAge: 1000 * 60 * 20,
        secure: true,
        httpOnly: true,
        sameSite: 'None',
    },
}));

app.use(cookieParser());
const frontend_url = process.env.ORIGIN || 'http://localhost:5173';
const backend_url = process.env.BACKEND_URL || 'http://localhost:5000';
app.use(cors({
    origin: frontend_url,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true,
}));
app.use(bodyParser.json());
app.use(passport.initialize());
app.use(passport.session());

app.get('/auth/google', passport.authenticate("google", {
    scope: ["profile"]
}));

app.get('/auth/google/callback', (req, res, next) => {
    passport.authenticate('google', (err, user) => {
        if (err) return next(err);
        req.logIn(user, (err) => {
            if (err) return next(err);
            req.session.save(() => {
                res.redirect(`${frontend_url}/dashboard?userID=${encodeURIComponent(user.userid)}&username=${encodeURIComponent(user.username)}`);
            });
        });
    })(req, res, next);
});

// Replace PostgreSQL queries with Mongoose methods
app.get('/bookDetails', async (req, res) => {
    try {
        const id = req.query.id;
        const ord = req.query.sorting;
        let books;

        switch (ord) {
            case "Recent":
                books = await Book.find({ userid: id }).sort({ bookid: -1 });
                break;
            case "Title":
                books = await Book.find({ userid: id }).sort({ title: 1 });
                break;
            case "Rating":
                books = await Book.find({ userid: id }).sort({ rating: -1 });
                break;
            default:
                books = await Book.find({ userid: id });
                break;
        }

        res.json({ val: books });
    } catch (e) {
        console.log(e);
        res.sendStatus(500);
    }
});

app.get('/check', (req, res) => {
    if (req.isAuthenticated()) {
        res.json({ valid: true, userID: req.user.userid, username: req.user.username });
    } else {
        res.json({ valid: false });
    }
});

app.get('/delete', async (req, res) => {
    const id = req.query.id;
    try {
        await Book.deleteOne({ _id: id });
        res.sendStatus(200);
    } catch (error) {
        console.log(error);
        res.sendStatus(500);
    }
});

app.post('/Edit', async (req, res) => {
    const data = req.body;
    const time = new Date();
    try {
        await Book.updateOne({ _id: data.bookID }, {
            title: data.title,
            author: data.author,
            isbn: data.isbn,
            brief: data.brief,
            DOC: data.DOC,
            rating: data.rating,
            summary: data.summary,
            updation: time,
        });
        res.redirect(`/bookDetails?id=${encodeURIComponent(data.id)}&sorting=${encodeURIComponent(data.sortingBasis)}`);
    } catch (error) {
        console.log(error);
        res.sendStatus(500);
    }
});

app.post('/Add', async (req, res) => {
    const data = req.body;
    const time = new Date();
    try {
        const newBook = new Book({
            userid: data.id,
            title: data.title,
            author: data.author,
            isbn: data.isbn,
            brief: data.brief,
            DOC: data.DOC,
            rating: data.rating,
            summary: data.summary,
            updation: time,
        });
        await newBook.save();
        res.redirect(`/bookDetails?id=${encodeURIComponent(data.id)}&sorting=${encodeURIComponent(data.sortingBasis)}`);
    } catch (error) {
        console.log(error);
        res.sendStatus(500);
    }
});

app.post('/login/data', (req, res, next) => {
    passport.authenticate('local', (err, user, info) => {
        if (err) return next(err);
        if (!user) return res.json({ message: info.message });
        req.logIn(user, (err) => {
            if (err) return next(err);
            req.session.save(() => {
                res.json({ message: "Authenticated", userID: user.userid, username: user.username });
            });
        });
    })(req, res, next);
});

app.post('/signup/data', async (req, res) => {
    const signupData = req.body;
    const username = signupData.username;
    const password = signupData.pwd;
    try {
        const userExists = await User.findOne({ username });
        if (userExists) {
            res.json({ message: "*Username already taken!!" });
        } else {
            const hashedPassword = await bcrypt.hash(password, saltRounds);
            const newUser = new User({ username, password: hashedPassword });
            await newUser.save();
            req.logIn(newUser, (err) => {
                if (err) console.log(err);
                res.json({ message: "Authenticated", userID: newUser._id, username: newUser.username });
            });
        }
    } catch (error) {
        console.log(error);
        res.sendStatus(500);
    }
});

passport.use(new Strategy({ usernameField: 'username', passwordField: 'pwd' }, async (username, pwd, cb) => {
    try {
        const user = await User.findOne({ username });
        if (user) {
            const isMatch = await bcrypt.compare(pwd, user.password);
            return cb(null, isMatch ? user : false, { message: "*Incorrect password!!" });
        } else {
            return cb(null, false, { message: "*Username not found!!" });
        }
    } catch (err) {
        return cb(err);
    }
}));

passport.use("google", new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: `${backend_url}/auth/google/callback`,
    useProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
}, async (accessToken, refreshToken, profile, cb) => {
    try {
        const user = await User.findOne({ username: profile.displayName });
        if (!user) {
            const newUser = new User({ username: profile.displayName, password: "google" });
            await newUser.save();
            cb(null, newUser);
        } else {
            cb(null, user);
        }
    } catch (error) {
        console.log(error);
    }
}));

passport.serializeUser((user, cb) => {
    cb(null, user);
});

passport.deserializeUser(async (user, done) => {
    try {
        const sessionUser = await User.findById(user._id);
        done(null, sessionUser || false);
    } catch (error) {
        console.log(error);
        done(error);
    }
});

app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
});
