


const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const cors = require('cors');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(bodyParser.json());
app.use(cors());

// Connect to MongoDB (Make sure MongoDB is running on your machine)
mongoose.connect('mongodb://localhost:27017/supermall', {
    useNewUrlParser: true,
    useUnifiedTopology: true
});
const db = mongoose.connection;

db.on('error', console.error.bind(console, 'MongoDB connection error:'));
db.once('open', () => {
    console.log('Connected to MongoDB');
});

// Define User Schema and Model
const userSchema = new mongoose.Schema({
    username: { type: String, unique: true, required: true },
    password: { type: String, required: true }
});
const User = mongoose.model('User', userSchema);

// Define Admin Schema and Model
const adminSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true }
});
const Admin = mongoose.model('Admin', adminSchema);

// Ensure only one fixed admin account exists
Admin.findOne({ username: 'admin' }).then(admin => {
    if (!admin) {
        // Hash the password before saving
        bcrypt.genSalt(10, (err, salt) => {
            bcrypt.hash('adminpassword', salt, (err, hash) => {
                const newAdmin = new Admin({
                    username: 'admin',
                    password: hash
                });

                newAdmin.save().then(() => console.log('Default admin created')).catch(err => console.error(err));
            });
        });
    }
}).catch(err => console.error(err));


// User Signup Route
app.post('/api/signup', async (req, res) => {
    const { username, password } = req.body;
    if (password.length < 8) {
        return res.status(400).json({ success: false, message: 'Password must be at least 8 characters long.' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    try {
        const newUser = new User({ username, password: hashedPassword });
        await newUser.save();
        res.status(201).json({ success: true });
    } catch (error) {
        res.status(400).json({ success: false, message: 'Username already exists.' });
    }
});

// User Login Route
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user) {
        return res.status(400).json({ success: false, message: 'Invalid credentials.' });
    }
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
        return res.status(400).json({ success: false, message: 'Invalid credentials.' });
    }
    res.json({ success: true });
});

// Admin Login Route
app.post('/admin/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        // Check if admin exists in the database
        const admin = await Admin.findOne({ username });
        if (!admin) {
            return res.status(404).json({ success: false, message: 'Admin not found' });
        }

        // Validate password
        const isMatch = await bcrypt.compare(password, admin.password);
        if (!isMatch) {
            return res.status(400).json({ success: false, message: 'Invalid credentials' });
        }

        // Create and send JWT token (example)
        const payload = {
            admin: {
                id: admin.id
            }
        };

        jwt.sign(payload, 'secretToken', { expiresIn: '1h' }, (err, token) => {
            if (err) throw err;
            res.json({ success: true, token });
        });

    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

// Middleware to verify admin token
function verifyAdminToken(req, res, next) {
    const token = req.headers['authorization'];
    if (!token) {
        return res.status(403).json({ success: false, message: 'No token provided' });
    }

    jwt.verify(token.split(' ')[1], 'secretToken', (err, decoded) => {
        if (err) {
            return res.status(401).json({ success: false, message: 'Unauthorized access' });
        }
        req.adminId = decoded.admin.id;
        next();
    });
}

// Backend code for listing offers
const offerSchema = new mongoose.Schema({
    title: { type: String, required: true },
    description: { type: String, required: true },
    price: { type: Number, required: true }
});
const Offer = mongoose.model('Offer', offerSchema);

// Create an offer
app.post('/api/offers', verifyAdminToken, async (req, res) => {
    const { title, description, price } = req.body;
    try {
        const newOffer = new Offer({ title, description, price });
        await newOffer.save();
        res.status(201).json({ success: true });
    } catch (error) {
        res.status(400).json({ success: false, message: 'Could not create offer' });
    }
});

// Get all offers
app.get('/api/offers', async (req, res) => {
    try {
        const offers = await Offer.find();
        res.json(offers);
    } catch (error) {
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Start server
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});

