require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const mysql = require('mysql2');
const crypto = require('crypto');
const path = require('path');
const session = require('express-session');
const bcrypt = require('bcrypt');
const csrf = require('csurf');

const app = express();

// ---------- MIDDLEWARE ----------
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.set('view engine', 'ejs');

// ---------- ENVIRONMENT VARIABLES ----------
const PORT = process.env.PORT || 3000;

const ENCRYPTION_KEY_HEX = process.env.ENCRYPTION_KEY;
if (!ENCRYPTION_KEY_HEX || ENCRYPTION_KEY_HEX.length !== 64) {
    console.error("❌ ENCRYPTION_KEY must be a 64-character hex string (32 bytes). Check your .env file.");
    process.exit(1);
}
const ENCRYPTION_KEY = Buffer.from(ENCRYPTION_KEY_HEX, 'hex');
const IV_LENGTH = 16;

// ---------- MYSQL CONNECTION ----------
const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME
});

db.connect(err => {
    if (err) {
        console.error('❌ MySQL connection failed:', err.code);
        console.error(`Attempted connection to: ${process.env.DB_USER}@${process.env.DB_HOST}/${process.env.DB_NAME}`);
        process.exit(1);
    }
    console.log('✅ Connected to MySQL database');
});

// ---------- SESSION CONFIG ----------
app.use(session({
    secret: process.env.SESSION_SECRET || 'supersecretkey',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: false,       // set to true only if HTTPS
        httpOnly: true,      // protect cookie
        maxAge: 5 * 60 * 1000 // 5 minutes session timeout
    },
    rolling: true  // resets session expiry on each request
}));


// ---------- CSRF PROTECTION ----------
const csrfProtection = csrf();

// Apply CSRF to all POST routes
app.use(csrfProtection);

// Automatically add CSRF token to every EJS view
app.use((req, res, next) => {
    res.locals.csrfToken = req.csrfToken();
    next();
});

// ---------- HELPER FUNCTIONS (ENCRYPTION) ----------
function encrypt(text) {
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return { iv: iv.toString('hex'), encryptedData: encrypted };
}

function decrypt(encryptedHex, ivHex) {
    const iv = Buffer.from(ivHex, 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
    let decrypted = decipher.update(encryptedHex, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

// ---------- AUTH ROUTES ----------

// Register
app.get('/register', (req, res) => res.render('register'));

app.post('/register', async (req, res) => {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
        return res.status(400).send('Missing registration fields.');
    }

    try {
        const hash = await bcrypt.hash(password, 10);
        db.query(
            'INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)',
            [username, email, hash],
            err => {
                if (err) {
                    console.error(err);
                    if (err.code === 'ER_DUP_ENTRY') {
                        return res.status(409).send('Error: Email address is already registered.');
                    }
                    return res.status(500).send('Error registering user.');
                }
                res.redirect('/login');
            }
        );
    } catch (e) {
        console.error(e);
        res.status(500).send('Server error during registration.');
    }
});

// Login
app.get('/login', (req, res) => res.render('login'));

app.post('/login', (req, res) => {
    const { email, password } = req.body;
    db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).send('Server error during login.');
        }

        if (results.length === 0) return res.status(401).send('Invalid email or password');

        const user = results[0];
        const match = await bcrypt.compare(password, user.password_hash);
        if (!match) return res.status(401).send('Invalid email or password');

        req.session.userId = user.id;
        res.redirect('/notes');
    });
});

// Logout
app.get('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) console.error("Error destroying session:", err);
        res.redirect('/login');
    });
});

// ---------- NOTES ROUTES ----------

// Redirect root
app.get('/', (req, res) => {
    if (!req.session.userId) return res.redirect('/login');
    res.redirect('/notes');
});

// Notes page (protected)
app.get('/notes', (req, res) => {
    if (!req.session.userId) return res.redirect('/login');

    const userId = req.session.userId;

    db.query('SELECT * FROM notes WHERE user_id = ? ORDER BY created_at DESC', [userId], (err, rows) => {
        if (err) {
            console.error(err);
            return res.status(500).send('Database error');
        }

        const decryptedNotes = rows.map(note => {
            try {
                const decryptedContent = decrypt(note.encrypted_content, note.iv);
                return { ...note, content: decryptedContent };
            } catch (e) {
                console.error('Decryption failed for note ID:', note.id, e);
                return {
                    ...note,
                    title: `[ERROR] ${note.title}`,
                    content: 'Decryption failed. Key or data may be corrupted.'
                };
            }
        });

        res.render('index', { notes: decryptedNotes });
    });
});

// Add note (protected)
app.post('/notes/add', (req, res) => {
    if (!req.session.userId) return res.redirect('/login');

    const { title, content } = req.body;
    if (!title || !content) {
        return res.status(400).send('Title and content are required.');
    }

    const userId = req.session.userId;
    const { iv, encryptedData } = encrypt(content);

    db.query(
        'INSERT INTO notes (user_id, title, encrypted_content, iv) VALUES (?, ?, ?, ?)',
        [userId, title, encryptedData, iv],
        err => {
            if (err) {
                console.error(err);
                return res.status(500).send('Error adding note.');
            }
            res.redirect('/notes');
        }
    );
});

// ---------- CSRF ERROR HANDLER ----------
app.use((err, req, res, next) => {
    if (err.code === 'EBADCSRFTOKEN') {
        return res.status(403).send('Form tampered with or session expired. Please reload the page and try again.');
    }
    next(err);
});

// ---------- START SERVER ----------
app.listen(PORT, () => console.log(`🚀 Server running at http://localhost:${PORT}`));
