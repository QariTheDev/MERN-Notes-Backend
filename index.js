const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
// require('dotenv').config();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

const User = require('./models/user.model');
const Note = require('./models/note.model');

const JWT_SECRET = '0c5a8e7c7ee4879778e29068498b28830ebe863f69dda24db0f2574c17616919';
const JWT_REFRESH_SECRET = '0c5a8e7c7ee4879778e29068498b28830ebe863f69dda24db0f2574c17616919123';
const ACCESS_TOKEN_EXPIRATION = '2d';
const REFRESH_TOKEN_EXPIRATION = '7d';

const PORT = process.env.PORT || 5000;
const app = express();

// Authorization Middleware
function authenticateToken(req, res, next) {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];

    if (!token) {
        return res.status(401).json({ error: "Unauthorized" });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: "Token verification failed" });
        }
        req.user = user;
        next();
    });
}

// Refresh Token Middleware
function authenticateRefreshToken(req, res, next) {
    const refreshToken = req.body.refreshToken;

    if (!refreshToken) {
        return res.status(401).json({ error: "Refresh token not provided" });
    }

    jwt.verify(refreshToken, JWT_REFRESH_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: "Refresh token verification failed" });
        }
        req.user = user;
        next();
    });
}

app.use(express.json());
app.use(cors({ origin: '*' }));

mongoose.connect('mongodb+srv://talhaiqbal7272:Commandoz1@notes.ohqyao7.mongodb.net/');

app.get("/", (req, res) => {
    res.json({ data: "Hello World" });
});

//Create Account
app.post("/create-account", async (req, res) => {
    const { fullName, email, password } = req.body;
    const isUser = await User.findOne({ email });

    if (isUser) return res.json({ error: "User already exists" });
    if (!fullName || !email || !password) return res.json({ error: "All fields are required" });

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({
        fullName,
        email,
        password: hashedPassword
    });

    await newUser.save();

    res.json({ message: "Account Creation Successful" });
});

//Login Account
app.post("/login", async (req, res) => {
    const { email, password } = req.body;
    const userInfo = await User.findOne({ email });

    if (!userInfo) return res.json({ error: "Invalid Credentials" });

    const isPasswordValid = await bcrypt.compare(password, userInfo.password);

    if (!isPasswordValid) return res.json({ error: "Invalid Credentials" });

    const user = { user: userInfo };

    // Generate access token
    const accessToken = jwt.sign({ user }, JWT_SECRET, {
        expiresIn: ACCESS_TOKEN_EXPIRATION,
    });

    // Generate refresh token
    const refreshToken = jwt.sign({ user }, JWT_REFRESH_SECRET, {
        expiresIn: REFRESH_TOKEN_EXPIRATION,
    });

    res.json({ message: "Login Successful", accessToken, refreshToken, user });
});

// Refresh Token Endpoint
app.post("/refresh-token", authenticateRefreshToken, (req, res) => {
    const user = req.user;

    const accessToken = jwt.sign({ user }, JWT_SECRET, {
        expiresIn: ACCESS_TOKEN_EXPIRATION,
    });

    res.json({ accessToken, user });
});

//Add Note
app.post("/add-note", authenticateToken, async (req, res) => {
    const { title, description, tags } = req.body;
    const { user } = req.user;

    if (!title || !description) {
        return res.json({ error: "All fields are required" });
    }

    try {
        const newNote = new Note({
            title,
            description,
            tags: tags || [],
            userId: user.user._id
        });

        await newNote.save();
        res.json({ message: "Note added successfully" });

    } catch (error) {
        return res.json({ error: error.message });
    }
});

//Edit Note
app.put("/edit-note/:noteId", authenticateToken, async (req, res) => {
    const { title, description, tags, isPinned } = req.body;
    const noteId = req.params.noteId;
    const { user } = req.user;

    if (!title && !description && !tags) return res.json({ error: "No changes to save" });

    try {
        const note = await Note.findOne({ _id: noteId, userId: user.user._id });

        if (!note) return res.json({ error: "Note not found" });

        if (title) note.title = title;
        if (description) note.description = description;
        if (tags) note.tags = tags || [];
        if (isPinned) note.isPinned = isPinned || false;


        await note.save();
        res.json({ message: "Note updated successfully" });
    }
    catch {
        return res.json({ error: error.message });
    }
});

//Delete Note
app.delete("/delete-note/:noteId", authenticateToken, async (req, res) => {
    const noteId = req.params.noteId;
    const { user } = req.user;

    console.log(user.user._id);

    try {
        const note = await Note.findOne({ _id: noteId, userId: user.user._id });

        if (!note) return res.json({ error: "Note not found" });

        await note.deleteOne({ _id: noteId, userId: user.user._id })
        res.json({ message: "Note deleted successfully" });
    }
    catch {
        return res.json({ error: error.message });
    }
});

//Get Notes
app.get("/get-notes", authenticateToken, async (req, res) => {
    const { user } = req.user;
    const notes = await Note.find({ userId: user.user._id });

    if (!notes) return res.json({ error: "No notes found" });

    res.json({ notes });
});

// Update isPin
app.put("/update-note-pinned/:noteId", authenticateToken, async (req, res) => {
    const noteId = req.params.noteId;
    const { isPinned } = req.body;
    const { user } = req.user;

    try {
        const note = await Note.findOne({ _id: noteId, userId: user.user._id });

        if (!note) return res.status(404).json({ error: "Note not found" });

        note.isPinned = isPinned;

        await note.save();

        res.json({ message: "Note pinned status updated successfully", note });
    } catch (error) {
        console.error('Error updating note pinned status:', error);
        res.status(500).json({ error: "Internal server error" });
    }
});

//Get User
app.get("/get-user", authenticateToken, async (req, res) => {
    const { user } = req.user;

    const isUser = await User.find({ _id: user._id });

    if (!isUser) return res.json({ error: "User not found" });

    res.json({ user });
});

//Search Notes
app.get("/search-notes", authenticateToken, async (req, res) => {
    const { query } = req.query;
    const { user } = req.user;

    try {
        const notes = await Note.find({
            userId: user.user._id,
            $or: [
                { title: { $regex: query, $options: 'i' } },
                { description: { $regex: query, $options: 'i' } },
                { tags: { $regex: query, $options: 'i' } }
            ]
        })

        if (!notes) return res.json({ error: "No notes found" });

        res.json({ notes });
    }
    catch (error) {
        return res.json({ error: error.message });
    }
});

app.listen(PORT, () => {
    console.log(`Server is running on PORT ${PORT}`);
});

module.exports = app;