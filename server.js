const express = require('express');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const path = require('path');
const fs = require('fs');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const SQLiteStore = require('connect-sqlite3')(session);

const { google } = require('googleapis');
const nodemailer = require('nodemailer');
const { fetchNewsDataIo, fetchNewsApiOrg } = require('./newsFetcher');
const cron = require('node-cron');

const app = express();
const PORT = 3000;
const DB_PATH = path.join(__dirname, 'database.db');

// --- Database Setup ---
const db = new sqlite3.Database(DB_PATH, (err) => {
    if (err) {
        console.error(err.message);
    }
    console.log('Connected to the SQLite database.');
});

db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users ( 
        id TEXT PRIMARY KEY,
        email TEXT NOT NULL UNIQUE,
        password TEXT,
        accessToken TEXT,
        refreshToken TEXT
    )`)
    db.run(`CREATE TABLE IF NOT EXISTS settings (
        user_id TEXT PRIMARY KEY,
        receiveEmails BOOLEAN,
        useGmail BOOLEAN,
        sendWelcomeEmail BOOLEAN,
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS news_sources (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL UNIQUE,
        api_name TEXT NOT NULL, -- e.g., 'NewsData', 'NewsAPI'
        api_key TEXT NOT NULL,
        base_url TEXT NOT NULL,
        endpoint TEXT, -- specific endpoint for this source if applicable
        category TEXT -- e.g., 'tech', 'general'
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS user_news_preferences (
        user_id TEXT NOT NULL,
        source_id INTEGER NOT NULL,
        keywords TEXT, -- comma-separated keywords for filtering
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
        FOREIGN KEY (source_id) REFERENCES news_sources (id) ON DELETE CASCADE,
        PRIMARY KEY (user_id, source_id)
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS study_plans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT NOT NULL,
        course_name TEXT NOT NULL,
        total_days INTEGER NOT NULL,
        start_date TEXT NOT NULL,
        current_day INTEGER DEFAULT 1,
        status TEXT DEFAULT 'active',
        last_email_sent TEXT,
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS daily_tasks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        plan_id INTEGER NOT NULL,
        day_number INTEGER NOT NULL,
        topic TEXT NOT NULL,
        is_completed BOOLEAN DEFAULT 0,
        completed_at TEXT,
        performance_score INTEGER DEFAULT 100,
        FOREIGN KEY (plan_id) REFERENCES study_plans (id) ON DELETE CASCADE,
        UNIQUE (plan_id, day_number)
    )`);

    // Insert initial news sources (run only once)
    db.run(`INSERT OR IGNORE INTO news_sources (name, api_name, api_key, base_url, category) VALUES (?, ?, ?, ?, ?)`, ['NewsData.io', 'NewsData', 'pub_88472ed957654879aff435bb6c6870d3', 'https://newsdata.io/api/1/news', 'general']);
    db.run(`INSERT OR IGNORE INTO news_sources (name, api_name, api_key, base_url, category) VALUES (?, ?, ?, ?, ?)`, ['NewsAPI.org', 'NewsAPI', '8af0429573d14acdbe8f36105a88dd5e', 'https://newsapi.org/v2/', 'general']);
    db.run(`INSERT OR IGNORE INTO news_sources (name, api_name, api_key, base_url, endpoint, category) VALUES (?, ?, ?, ?, ?, ?)`, ['TechCrunch', 'NewsAPI', '8af0429573d14acdbe8f36105a88dd5e', 'https://newsapi.org/v2/', 'top-headlines?sources=techcrunch', 'tech']);
    db.run(`INSERT OR IGNORE INTO news_sources (name, api_name, api_key, base_url, endpoint, category) VALUES (?, ?, ?, ?, ?, ?)`, ['Wired', 'NewsAPI', '8af0429573d14acdbe8f36105a88dd5e', 'https://newsapi.org/v2/', 'everything?domains=wired.com', 'tech']);
    db.run(`INSERT OR IGNORE INTO news_sources (name, api_name, api_key, base_url, endpoint, category) VALUES (?, ?, ?, ?, ?, ?)`, ['The Verge', 'NewsAPI', '8af0429573d14acdbe8f36105a88dd5e', 'https://newsapi.org/v2/', 'everything?domains=theverge.com', 'tech']);
    db.run(`INSERT OR IGNORE INTO news_sources (name, api_name, api_key, base_url, endpoint, category) VALUES (?, ?, ?, ?, ?, ?)`, ['CNET', 'NewsAPI', '8af0429573d14acdbe8f36105a88dd5e', 'https://newsapi.org/v2/', 'everything?domains=cnet.com', 'tech']);
});

// --- Scheduled News Delivery (Placeholder) ---
cron.schedule('0 8 * * * ', async () => { // Runs every day at 8:00 AM
    console.log('Running daily news fetch and email task...');
    sendDailyNewsDigest();
});

// --- Scheduled Study Task Delivery ---
cron.schedule('0 9 * * * ', async () => { // Runs every day at 9:00 AM (adjust time as needed)
    console.log('Running daily study task email process...');
    sendDailyStudyTaskEmail();
});


// --- Email Sending Functions ---
// Fallback email function using Nodemailer when Gmail API is not available
async function sendLocalWelcomeEmail(userEmail) {
    // Create a test account if needed
    console.log('Attempting to send welcome email via Nodemailer to:', userEmail);
    
    // Create reusable transporter
    const transporter = nodemailer.createTransport({
        host: process.env.SMTP_HOST || 'smtp.ethereal.email', // Default to ethereal for testing
        port: process.env.SMTP_PORT || 587,
        secure: process.env.SMTP_SECURE === 'true' || false,
        auth: {
            user: process.env.SMTP_USER || 'techflow.ai.noreply@gmail.com',
            pass: process.env.SMTP_PASS || 'app_password_here'
        }
    });

    // Email content
    const mailOptions = {
        from: '"TechFlow AI" <techflow.ai.noreply@gmail.com>',
        to: userEmail,
        subject: 'Welcome to TechFlow AI - Your Personalized Learning Journey Begins!',
        html: `
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                <h2 style="color: #4a6ee0;">Welcome to TechFlow AI!</h2>
                <p>Hi there,</p>
                <p>We're thrilled to have you on board.</p>
                <p>You've just activated your personalized AI-powered learning and news assistant. Get ready to supercharge your growth in the tech world.</p>
                <h3>What's next?</h3>
                <ul>
                    <li><b>Personalized News:</b> You will start receiving curated tech news based on your interests.</li>
                    <li><b>Smart Scheduling:</b> Your study schedule will be optimized for your learning goals.</li>
                    <li><b>Discover Tools:</b> Get recommendations for the latest AI tools to enhance your workflow.</li>
                </ul>
                <p>You can customize your experience at any time by visiting the settings page in your dashboard.</p>
                <p>Happy learning!</p>
                <p>Best,<br>The TechFlow AI Team</p>
            </div>
        `
    };

    // Send mail
    const info = await transporter.sendMail(mailOptions);
    console.log('Nodemailer welcome email sent:', info.messageId);
    return info;
}

// Primary email function using Gmail API with fallback
async function sendWelcomeEmail(auth, userEmail) {
    try {
        console.log('Attempting to send welcome email with Gmail API to:', userEmail);
        
        if (!auth || !auth.credentials || !auth.credentials.access_token) {
            console.error('Invalid auth object for Gmail API:', auth);
            throw new Error('Invalid authentication for Gmail API');
        }
        
        const gmail = google.gmail({ version: 'v1', auth });
        const emailLines = [
            'From: "TechFlow AI" <me>',
            `To: ${userEmail}`,
            'Content-type: text/html;charset=iso-8859-1',
            'MIME-Version: 1.0',
            'Subject: Welcome to TechFlow AI - Your Personalized Learning Journey Begins!',
            '',
            'Hi there,',
            '<br><br>',
            "Welcome to <b>TechFlow AI</b>! We're thrilled to have you on board.",
            '<br><br>',
            "You've just activated your personalized AI-powered learning and news assistant. Get ready to supercharge your growth in the tech world.",
            '<br><br>',
            "<b>What's next?</b>",
            '<ul>',
            '<li><b>Personalized News:</b> You will start receiving curated tech news based on your interests.</li>',
            '<li><b>Smart Scheduling:</b> Your study schedule will be optimized for your learning goals.</li>',
            '<li><b>Discover Tools:</b> Get recommendations for the latest AI tools to enhance your workflow.</li>',
            '</ul>',
            'You can customize your experience at any time by visiting the settings page in your dashboard.',
            '<br><br>',
            'Happy learning!',
            '<br><br>',
            'Best,',
            '<br>',
            'The TechFlow AI Team'
        ].join('\r\n');

        const raw = Buffer.from(emailLines).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
        
        const result = await gmail.users.messages.send({
            userId: 'me',
            requestBody: {
                raw: raw
            }
        });
        
        console.log('Gmail API welcome email sent successfully:', result.data);
        return result;
    } catch (error) {
        console.error('Error sending welcome email with Gmail API:', error);
        // Fall back to nodemailer if Gmail API fails
        try {
            await sendLocalWelcomeEmail(userEmail);
            console.log('Fallback to nodemailer successful');
        } catch (fallbackError) {
            console.error('Fallback email also failed:', fallbackError);
        }
        throw error;
    }
}

// Function to send daily news digest
async function sendDailyNewsDigest() {
    console.log('Starting daily news digest process...');
    db.all('SELECT id, email FROM users', async (err, users) => {
        if (err) {
            console.error('Error fetching users for news digest:', err);
            return;
        }

        for (const user of users) {
            // Check user's email notification settings
            db.get('SELECT receiveEmails FROM settings WHERE user_id = ?', [user.id], async (err, userSettings) => {
                if (err) {
                    console.error(`Error fetching settings for user ${user.email}:`, err);
                    return;
                }
                if (!userSettings || !userSettings.receiveEmails) {
                    console.log(`Skipping news digest for ${user.email}: email notifications are off.`);
                    return; // Skip if notifications are off
                }

                db.all('SELECT ns.name, ns.api_name, ns.api_key, ns.base_url, ns.endpoint, unp.keywords FROM user_news_preferences unp JOIN news_sources ns ON unp.source_id = ns.id WHERE unp.user_id = ?', [user.id], async (err, preferences) => {
                    if (err) {
                        console.error(`Error fetching news preferences for user ${user.email}:`, err);
                        return;
                    }

                    let allArticles = [];
                    for (const pref of preferences) {
                        let articles = [];
                        if (pref.api_name === 'NewsData') {
                            articles = await fetchNewsDataIo(pref.api_key, pref.keywords);
                        } else if (pref.api_name === 'NewsAPI') {
                            // For NewsAPI, we use the endpoint if available, otherwise query with keywords
                            if (pref.endpoint) {
                                // Extract source from endpoint if it's a source-specific endpoint
                                const sourceMatch = pref.endpoint.match(/sources=([^&]+)/);
                                const source = sourceMatch ? sourceMatch[1] : '';
                                articles = await fetchNewsApiOrg(pref.api_key, source, pref.keywords);
                            } else {
                                articles = await fetchNewsApiOrg(pref.api_key, '', pref.keywords);
                            }
                        }
                        allArticles = allArticles.concat(articles);
                    }

                    // Filter articles by keywords if present in preferences (case-insensitive)
                    if (preferences.some(p => p.keywords)) {
                        const allKeywords = preferences.map(p => p.keywords).filter(Boolean).join(',').split(',').map(k => k.trim().toLowerCase());
                        allArticles = allArticles.filter(article => {
                            const titleAndDesc = `${article.title || ''} ${article.description || ''}`.toLowerCase();
                            return allKeywords.some(keyword => titleAndDesc.includes(keyword));
                        });
                    }

                    // Remove duplicates based on link
                    const uniqueArticles = Array.from(new Map(allArticles.map(item => [item.link, item])).values());

                    if (uniqueArticles.length > 0) {
                        let emailContent = `
                            <p>Hi ${user.email.split('@')[0]},</p>
                            <p>Here's your daily dose of tech news:</p>
                            <br>
                        `;
                        uniqueArticles.forEach(article => {
                            emailContent += `
                                <h3><a href="${article.link}">${article.title}</a></h3>
                                <p>${article.description || ''}</p>
                                <p><em>Source: ${article.source || ''} - ${new Date(article.pubDate).toLocaleDateString()}</em></p>
                                <hr>
                            `;
                        });
                        emailContent += `<p>Enjoy your reading!</p><p>The TechFlow AI Team</p>`;

                        const mailOptions = {
                            from: '"TechFlow AI" <rouaz654@gmail.com>', // Your sending email
                            to: user.email,
                            subject: 'Your Daily Tech News Digest from TechFlow AI',
                            html: emailContent
                        };

                        try {
                            await transporter.sendMail(mailOptions);
                            console.log(`Daily news digest sent to ${user.email}`);
                        } catch (error) {
                            console.error(`Error sending daily news digest to ${user.email}:`, error);
                        }
                    } else {
                        console.log(`No news articles found for ${user.email} based on preferences.`);
                    }
                });
            });
        }
    });
}

async function sendDailyStudyTaskEmail() {
    console.log('Starting daily study task email process...');
    db.all("SELECT sp.id AS plan_id, sp.user_id, sp.course_name, sp.total_days, sp.current_day, u.email FROM study_plans sp JOIN users u ON sp.user_id = u.id WHERE sp.status = 'active'", async (err, activePlans) => {
        if (err) {
            console.error('Error fetching active study plans:', err);
            return;
        }

        for (const plan of activePlans) {
            if (plan.current_day > plan.total_days) {
                // Mark plan as completed if all days are done
                db.run("UPDATE study_plans SET status = 'completed' WHERE id = ?", [plan.plan_id], (err) => {
                    if (err) console.error('Error marking study plan as completed:', err);
                    else console.log(`Study plan ${plan.plan_id} for ${plan.course_name} marked as completed.`);
                });
                continue; // Move to next plan
            }

            // Check previous day's task for performance tracking
            const previousDay = plan.current_day - 1;
            if (previousDay >= 1) {
                db.get('SELECT is_completed, performance_score FROM daily_tasks WHERE plan_id = ? AND day_number = ?', [plan.plan_id, previousDay], (err, prevTask) => {
                    if (err) {
                        console.error(`Error fetching previous task for performance check (Plan ${plan.plan_id}, Day ${previousDay}):`, err);
                    } else if (prevTask && !prevTask.is_completed) {
                        // If previous task was not completed, decrease performance score
                        const newScore = Math.max(0, prevTask.performance_score - 10); // Decrease by 10, min 0
                        db.run('UPDATE daily_tasks SET performance_score = ? WHERE plan_id = ? AND day_number = ?', [newScore, plan.plan_id, previousDay], (err) => {
                            if (err) console.error('Error updating performance score:', err);
                            else console.log(`Performance score for Plan ${plan.plan_id}, Day ${previousDay} decreased to ${newScore}.`);
                        });
                    }
                });
            }

            db.get('SELECT topic FROM daily_tasks WHERE plan_id = ? AND day_number = ?', [plan.plan_id, plan.current_day], async (err, task) => {
                if (err) {
                    console.error(`Error fetching task for plan ${plan.plan_id} (Day ${plan.current_day}):`, err);
                    return;
                }
                if (!task) {
                    console.warn(`No task found for plan ${plan.plan_id} (Day ${plan.current_day}). Skipping email.`);
                    return;
                }

                const userEmailName = plan.email.split('@')[0];
                const markCompleteLink = `http://localhost:3000/api/study-plan/complete/${plan.plan_id}/${plan.current_day}`; // Placeholder link

                const emailContent = `
                    <p>Hi ${userEmailName},</p>
                    <p>Your study task for today (Day ${plan.current_day} of ${plan.total_days}) for <b>${plan.course_name}</b> is:</p>
                    <h3>${task.topic}</h3>
                    <p>To mark this task as complete, please click the link below:</p>
                    <p><a href="${markCompleteLink}">Mark as Complete</a></p>
                    <p>Keep up the great work!</p>
                    <p>The TechFlow AI Team</p>
                `;

                const mailOptions = {
                    from: '"TechFlow AI" <rouaz654@gmail.com>', // Use the configured sender email
                    to: plan.email,
                    subject: `Your Daily Study Task: ${plan.course_name} - Day ${plan.current_day}`,
                    html: emailContent
                };

                try {
                    await transporter.sendMail(mailOptions);
                    console.log(`Daily study task email sent to ${plan.email} for ${plan.course_name} (Day ${plan.current_day}).`);

                    // Update last_email_sent and increment current_day
                    db.run('UPDATE study_plans SET last_email_sent = ?, current_day = current_day + 1 WHERE id = ?', [new Date().toISOString(), plan.plan_id], (err) => {
                        if (err) console.error('Error updating study plan after email send:', err);
                    });
                } catch (error) {
                    console.error(`Error sending daily study task email to ${plan.email}:`, error);
                }
            });
        }
    });
}

// Nodemailer transporter for local email sending
const transporter = nodemailer.createTransport({
    service: 'gmail', // You can use other services like 'Outlook', 'Yahoo', etc., or configure SMTP directly
    auth: {
        user: 'rouaz654@gmail.com', // Replace with your email address
        pass: 'ypos jzpx pxdt gtus'   // Replace with your email password or app-specific password
    }
});

async function sendLocalWelcomeEmail(userEmail) {
    const mailOptions = {
        from: '"TechFlow AI" <rouaz654@gmail.com>', // Replace with your email address
        to: userEmail,
        subject: 'Welcome to TechFlow AI - Your Personalized Learning Journey Begins!',
        html: `
            <p>Hi there,</p>
            <br><br>
            <p>Welcome to <b>TechFlow AI</b>! We're thrilled to have you on board.</p>
            <br><br>
            <p>You've just activated your personalized AI-powered learning and news assistant. Get ready to supercharge your growth in the tech world.</p>
            <br><br>
            <p><b>What's next?</b></p>
            <ul>
                <li><b>Personalized News:</b> You will start receiving curated tech news based on your interests.</li>
                <li><b>Smart Scheduling:</b> Your study schedule will be optimized for your learning goals.</li>
                <li><b>Discover Tools:</b> Get recommendations for the latest AI tools to enhance your workflow.</li>
            </ul>
            <p>You can customize your experience at any time by visiting the settings page in your dashboard.</p>
            <br><br>
            <p>Happy learning!</p>
            <br><br>
            <p>Best,</p>
            <br>
            <p>The TechFlow AI Team</p>
        `
    };

    try {
        await transporter.sendMail(mailOptions);
        console.log('Local welcome email sent successfully to:', userEmail);
    } catch (error) {
        console.error('Error sending local welcome email:', error);
    }
}

async function sendStudyPlanSetupConfirmationEmail(userEmail, courseName, totalDays) {
    const mailOptions = {
        from: '"TechFlow AI" <rouaz654@gmail.com>', // Use the configured sender email
        to: userEmail,
        subject: `Your ${courseName} Study Plan is Ready!`,
        html: `
            <p>Hi there,</p>
            <br>
            <p>Great news! Your personalized study plan for <b>${courseName}</b> has been successfully set up.</p>
            <p>You've committed to completing this course in <b>${totalDays} days</b>.</p>
            <br>
            <p>Here's what you can expect:</p>
            <ul>
                <li>Starting tomorrow, you'll receive daily emails with your study task for the day.</li>
                <li>Each email will include a link to mark your task as complete.</li>
                <li>Stay consistent to track your progress and performance!</li>
            </ul>
            <br>
            <p>Get ready to supercharge your learning journey!</p>
            <br>
            <p>Best,</p>
            <p>The TechFlow AI Team</p>
        `
    };

    try {
        await transporter.sendMail(mailOptions);
        console.log(`Study plan setup confirmation email sent to: ${userEmail}`);
    } catch (error) {
        console.error('Error sending study plan setup confirmation email:', error);
    }
}


// --- PASSPORT & SESSION SETUP ---
googleClientId = '619251603027-gv82131g6nvebciteqj7e98dcv6tasgi.apps.googleusercontent.com'
googleClientSecret = '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'

app.use(session({
    store: new SQLiteStore({
        db: 'database.db',
        dir: __dirname
    }),
    secret: 'your_secret_session_key', // Replace with a real secret key
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        sameSite: 'lax',  // Helps with CSRF protection while allowing redirects
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
    }
}));

app.use(passport.initialize());
app.use(passport.session());

passport.use(new GoogleStrategy({
    clientID: googleClientId,
    clientSecret: googleClientSecret,
    callbackURL: "http://localhost:3000/auth/google/callback",
    scope: ['profile', 'email', 'https://www.googleapis.com/auth/gmail.send'],
    accessType: 'offline',
    prompt: 'consent'
},
(accessToken, refreshToken, profile, cb) => {
    console.log('Google auth callback received:', { 
        profileId: profile.id,
        email: profile.emails?.[0]?.value,
        hasAccessToken: !!accessToken,
        hasRefreshToken: !!refreshToken
    });
    
    if (!profile.emails || !profile.emails[0] || !profile.emails[0].value) {
        console.error('No email found in Google profile');
        return cb(new Error('No email found in Google profile'));
    }
    
    // First check if user exists by email (more reliable than ID)
    db.get('SELECT * FROM users WHERE email = ?', [profile.emails[0].value], (err, existingUserByEmail) => {
        if (err) { 
            console.error('Database error during Google auth:', err);
            return cb(err); 
        }
        
        // If user exists by email but has different ID, use that record
        if (existingUserByEmail && existingUserByEmail.id !== profile.id) {
            console.log('User exists with different ID, updating record');
            db.run('UPDATE users SET id = ?, accessToken = ?, refreshToken = ? WHERE email = ?', 
                [profile.id, accessToken, refreshToken || existingUserByEmail.refreshToken, profile.emails[0].value], (err) => {
                if (err) { 
                    console.error('Error updating user ID and tokens:', err);
                    return cb(err); 
                }
                return cb(null, { 
                    id: profile.id, 
                    email: profile.emails[0].value,
                    accessToken: accessToken,
                    refreshToken: refreshToken || existingUserByEmail.refreshToken
                });
            });
            return;
        }
        
        // Otherwise proceed with normal ID-based lookup
        db.get('SELECT * FROM users WHERE id = ?', [profile.id], (err, row) => {
            if (err) { 
                console.error('Database error during Google auth:', err);
                return cb(err); 
            }
            if (row) {
                // User exists, update tokens - keep existing refresh token if new one not provided
                db.run('UPDATE users SET accessToken = ?, refreshToken = ? WHERE id = ?', 
                    [accessToken, refreshToken || row.refreshToken, profile.id], (err) => {
                    if (err) { 
                        console.error('Error updating tokens:', err);
                        return cb(err); 
                    }
                    return cb(null, { 
                        id: profile.id, 
                        email: profile.emails[0].value,
                        accessToken: accessToken,
                        refreshToken: refreshToken || row.refreshToken
                    });
                });
            } else {
                // New user, insert into database with transaction
                db.serialize(() => {
                    db.run('BEGIN TRANSACTION');
                    db.run('INSERT INTO users (id, email, accessToken, refreshToken) VALUES (?, ?, ?, ?)', 
                        [profile.id, profile.emails[0].value, accessToken, refreshToken], (err) => {
                        if (err) { 
                            console.error('Error inserting new user:', err);
                            db.run('ROLLBACK');
                            return cb(err); 
                        }
                        
                        db.run('INSERT INTO settings (user_id, receiveEmails, useGmail, sendWelcomeEmail) VALUES (?, ?, ?, ?)', 
                            [profile.id, true, true, true], (err) => {
                            if (err) { 
                                console.error('Error inserting settings for new user:', err);
                                db.run('ROLLBACK');
                                return cb(err); 
                            }
                            
                            db.run('COMMIT');
                            return cb(null, { 
                                id: profile.id, 
                                email: profile.emails[0].value,
                                accessToken: accessToken,
                                refreshToken: refreshToken
                            });
                        });
                    });
                });
            }
        });
    });
}
));

passport.serializeUser((user, cb) => {
    cb(null, user.id);
});

passport.deserializeUser((id, cb) => {
    db.get('SELECT * FROM users WHERE id = ?', [id], (err, row) => {
        if (err) { return cb(err); }
        if (row) {
            // Ensure accessToken and refreshToken are null if not present (for local users)
            const user = {
                id: row.id,
                email: row.email,
                accessToken: row.accessToken || null,
                refreshToken: row.refreshToken || null
            };
            cb(null, user);
        } else {
            cb(null, false);
        }
    });
});

// --- END PASSPORT SETUP ---

app.use(express.static(path.join(__dirname, 'public')));
app.use(bodyParser.json());

// --- LOCAL AUTHENTICATION ROUTES ---
app.post('/api/register', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ message: 'Email and password are required.' });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const id = Date.now().toString(); // Simple unique ID for now
        db.run('INSERT INTO users (id, email, password) VALUES (?, ?, ?)', [id, email, hashedPassword], function(err) {
            if (err) {
                if (err.message.includes('UNIQUE constraint failed')) {
                    console.error('Registration error: Email already exists.', err.message);
                    return res.status(409).json({ message: 'User with that email already exists.' });
                }
                console.error('Database error during registration:', err); // Log the full error object
                return res.status(500).json({ message: 'Error registering user. Please try again later.' });
            }
            // Insert default settings for the new user
            db.run('INSERT INTO settings (user_id, receiveEmails, useGmail, sendWelcomeEmail) VALUES (?, ?, ?, ?)', [id, true, true, true], function(err) {
                if (err) {
                    console.error('Database error during settings creation:', err);
                    return res.status(500).json({ message: 'Error creating user settings. Please try again later.' });
                }
                // Automatically log in the user after successful registration
                // The user object passed to req.login should be compatible with passport.serializeUser
                const newUser = { id: id, email: email };
                req.login(newUser, (err) => {
                    if (err) {
                        console.error('Error during req.login after registration:', err);
                        return res.status(500).json({ message: 'Error logging in after registration.' });
                    }
                    // Send welcome email for local registration
                    sendLocalWelcomeEmail(email);
                    res.status(201).json({ message: 'User registered and logged in successfully!', email: email });
                });
            });
        });
    } catch (error) {
        console.error('Error hashing password:', error);
        res.status(500).json({ message: 'Server error during registration.' });
    }
});

app.post('/api/login', (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ message: 'Email and password are required.' });
    }

    db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
        if (err) {
            console.error('Database error during login:', err.message);
            return res.status(500).json({ message: 'Error logging in.' });
        }
        if (!user) {
            return res.status(401).json({ message: 'Invalid email or password.' });
        }

        try {
            const match = await bcrypt.compare(password, user.password);
            if (match) {
                req.login(user, (err) => {
                    if (err) { return res.status(500).json({ message: 'Error logging in.' }); }
                    res.json({ message: 'Logged in successfully!', email: user.email });
                });
            } else {
                res.status(401).json({ message: 'Invalid email or password.' });
            }
        } catch (error) {
            console.error('Error comparing passwords:', error);
            res.status(500).json({ message: 'Server error during login.' });
        }
    });
});

// --- AUTHENTICATION ROUTES ---
app.get('/auth/google', (req, res, next) => {
    // Store the redirect path from query parameter or referrer
    const redirectPath = req.query.redirect || req.headers.referer || '/';
    req.session.redirectAfterAuth = redirectPath;
    next();
}, passport.authenticate('google'));

app.get('/auth/google/callback', 
  passport.authenticate('google', { failureRedirect: '/?auth_failed=true' }),
  (req, res) => {
    console.log('Google OAuth callback successful, user authenticated');
    
    // Successful authentication, now send welcome email if needed
    db.get('SELECT * FROM settings WHERE user_id = ?', [req.user.id], (err, row) => {
        console.log("User object in callback:", req.user);
        console.log("Settings row:", row);
        
        if (err) { 
            console.error("Error getting settings:", err);
            // Continue with redirect despite settings error
        }
        
        // Try to send welcome email if settings indicate it should be sent
        if (row && row.sendWelcomeEmail && req.user.accessToken) {
            console.log("Attempting to send welcome email.");
            try {
                const oauth2Client = new google.auth.OAuth2();
                oauth2Client.setCredentials({ 
                    access_token: req.user.accessToken,
                    refresh_token: req.user.refreshToken
                });
                
                // Send welcome email asynchronously (don't wait for it)
                sendWelcomeEmail(oauth2Client, req.user.email)
                    .then(() => {
                        console.log('Welcome email sent successfully');
                        // Update setting asynchronously
                        db.run('UPDATE settings SET sendWelcomeEmail = ? WHERE user_id = ?', 
                            [false, req.user.id], 
                            (err) => {
                                if (err) console.error('Error updating sendWelcomeEmail setting:', err);
                            });
                    })
                    .catch(err => console.error("sendWelcomeEmail error:", err));
            } catch (error) {
                console.error('Error setting up welcome email:', error);
                // Continue with redirect despite email error
            }
        } else {
            console.log("Welcome email not sent. Either settings row not found or sendWelcomeEmail is false.");
        }
        
        // Check if there's a redirect path stored in the session
        const redirectPath = req.session.redirectAfterAuth || '/';
        console.log('Redirecting to:', redirectPath);
        
        // Clear the redirect path from session
        delete req.session.redirectAfterAuth;
        
        // Redirect with success parameter
        res.redirect(redirectPath + (redirectPath.includes('?') ? '&' : '?') + 'loggedin=true');
    });
  });

// --- API ROUTES ---
app.get('/api/user-status', (req, res) => {
    if (req.isAuthenticated()) {
        // The user is logged in. Send back their email and whether they have a Google token.
        res.json({
            email: req.user.email,
            isGmailConnected: !!req.user.accessToken // This will be true if the accessToken exists, false otherwise
        });
    } else {
        // Not authenticated
        res.status(401).json({ message: 'Not authenticated' });
    }
});

app.get('/api/settings', (req, res) => {
    if (!req.isAuthenticated()) {
        return res.status(401).json({ message: 'Not authenticated' });
    }
    db.get('SELECT * FROM settings WHERE user_id = ?', [req.user.id], (err, row) => {
        if (err) {
            return res.status(500).json({ message: 'Error reading database.' });
        }
        res.json({ settings: row });
    });
});

app.post('/api/settings', (req, res) => {
    if (!req.isAuthenticated()) {
        return res.status(401).json({ message: 'Not authenticated' });
    }
    const newSettings = req.body.settings;
    db.run('UPDATE settings SET receiveEmails = ?, useGmail = ? WHERE user_id = ?', 
        [newSettings.receiveEmails, newSettings.useGmail, req.user.id], 
        (err) => {
            if (err) {
                return res.status(500).json({ message: 'Error writing to database.' });
            }
            res.json({ message: 'Settings saved successfully!' });
        }
    );
});

app.post('/api/disconnect', (req, res) => {
    if (!req.isAuthenticated()) {
        return res.status(401).json({ message: 'Not authenticated' });
    }
    
    // Clear Google tokens from the user record
    db.run('UPDATE users SET accessToken = NULL, refreshToken = NULL WHERE id = ?', [req.user.id], (err) => {
        if (err) {
            console.error('Error clearing tokens:', err);
            return res.status(500).json({ message: 'Error disconnecting from Gmail' });
        }
        
        req.logout((err) => {
            if (err) {
                console.error('Error during logout:', err);
                return res.status(500).json({ message: 'Error during logout' });
            }
            res.json({ message: 'Disconnected successfully!' });
        });
    });
});

// --- NEWS API ROUTES ---
app.get('/api/news/sources', (req, res) => {
    db.all('SELECT id, name FROM news_sources', [], (err, rows) => {
        if (err) {
            return res.status(500).json({ message: 'Error fetching news sources.' });
        }
        res.json({ sources: rows });
    });
});

app.get('/api/news/preferences', (req, res) => {
    if (!req.isAuthenticated()) {
        return res.status(401).json({ message: 'Not authenticated' });
    }
    db.all('SELECT source_id, keywords FROM user_news_preferences WHERE user_id = ?', [req.user.id], (err, rows) => {
        if (err) {
            return res.status(500).json({ message: 'Error fetching news preferences.' });
        }
        res.json({ preferences: rows });
    });
});

app.post('/api/news/preferences', (req, res) => {
    if (!req.isAuthenticated()) {
        return res.status(401).json({ message: 'Not authenticated' });
    }
    const { preferences } = req.body; // preferences is an array of { source_id, keywords }
    const user_id = req.user.id;

    db.serialize(() => {
        db.run('DELETE FROM user_news_preferences WHERE user_id = ?', [user_id], (err) => {
            if (err) {
                console.error('Error deleting old news preferences:', err);
                return res.status(500).json({ message: 'Error saving preferences.' });
            }

            if (preferences && preferences.length > 0) {
                const stmt = db.prepare('INSERT INTO user_news_preferences (user_id, source_id, keywords) VALUES (?, ?, ?)');
                preferences.forEach(pref => {
                    stmt.run(user_id, pref.source_id, pref.keywords || '');
                });
                stmt.finalize((err) => {
                    if (err) {
                        console.error('Error inserting new news preferences:', err);
                        return res.status(500).json({ message: 'Error saving preferences.' });
                    }
                    res.json({ message: 'News preferences saved successfully!' });
                });
            } else {
                res.json({ message: 'News preferences saved successfully (no sources selected).' });
            }
        });
    });
});

app.post('/api/study-plan/create', (req, res) => {
    if (!req.isAuthenticated()) {
        return res.status(401).json({ message: 'Authentication required.' });
    }

    const { courseName, totalDays } = req.body;
    const user_id = req.user.id;
    const startDate = new Date().toISOString().split('T')[0]; // YYYY-MM-DD

    if (!courseName || !totalDays || totalDays <= 0) {
        return res.status(400).json({ message: 'Course name and valid number of days are required.' });
    }

    db.serialize(() => {
        // Insert into study_plans table
        db.run('INSERT INTO study_plans (user_id, course_name, total_days, start_date) VALUES (?, ?, ?, ?)',
            [user_id, courseName, totalDays, startDate],
            function(err) {
                if (err) {
                    console.error('Error inserting study plan:', err);
                    return res.status(500).json({ message: 'Error creating study plan.' });
                }

                const plan_id = this.lastID; // Get the ID of the newly inserted study plan

                // Generate and insert daily tasks
                const stmt = db.prepare('INSERT INTO daily_tasks (plan_id, day_number, topic) VALUES (?, ?, ?)');
                for (let i = 1; i <= totalDays; i++) {
                    let topic;
                    if (i === 1) {
                        topic = `Introduction to ${courseName}`;
                    } else if (i === totalDays) {
                        topic = `Final Review and Next Steps in ${courseName}`;
                    } else if (i === totalDays - 1 && totalDays > 1) {
                        topic = `Project Setup and Initial Implementation for ${courseName}`;
                    }
                    else {
                        topic = `Day ${i}: Core Concepts of ${courseName} - Part ${i}`;
                    }
                    stmt.run(plan_id, i, topic);
                }
                stmt.finalize((err) => {
                    if (err) {
                        console.error('Error inserting daily tasks:', err);
                        return res.status(500).json({ message: 'Error creating daily tasks.' });
                    }
                    // Send confirmation email
                    const userEmail = req.user.email; // Assuming user email is available in req.user
                    sendStudyPlanSetupConfirmationEmail(userEmail, courseName, totalDays);

                    res.status(201).json({ message: 'Study plan created successfully!', planId: plan_id });
                });
            }
        );
    });
});

app.get('/api/study-plan/complete/:planId/:dayNumber', (req, res) => {
    if (!req.isAuthenticated()) {
        // Redirect to login if not authenticated
        return res.redirect('/login.html?redirect=/api/study-plan/complete/' + req.params.planId + '/' + req.params.dayNumber);
    }

    const { planId, dayNumber } = req.params;
    const user_id = req.user.id;
    const completedAt = new Date().toISOString();

    db.get('SELECT user_id FROM study_plans WHERE id = ?', [planId], (err, plan) => {
        if (err) {
            console.error('Error fetching study plan for completion:', err);
            return res.status(500).send('Error marking task complete.');
        }
        if (!plan || plan.user_id !== user_id) {
            return res.status(403).send('Unauthorized or plan not found.');
        }

        db.run('UPDATE daily_tasks SET is_completed = 1, completed_at = ? WHERE plan_id = ? AND day_number = ?',
            [completedAt, planId, dayNumber],
            function(err) {
                if (err) {
                    console.error('Error updating daily task completion status:', err);
                    return res.status(500).send('Error marking task complete.');
                }
                if (this.changes === 0) {
                    return res.status(404).send('Task not found or already completed.');
                }
                res.send('Task marked as complete! You can close this window.'); // Simple confirmation
            }
        );
    });
});

// --- HTML SERVING ---
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/settings', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'settings.html'));
});

app.get('/auth-test', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'auth-test.html'));
});

app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});

// Add logout route
app.post('/api/logout', (req, res) => {
    console.log('Logout request received');
    if (req.isAuthenticated()) {
        console.log('User authenticated, logging out:', req.user.email);
        req.logout((err) => {
            if (err) {
                console.error('Error during logout:', err);
                return res.status(500).json({ message: 'Error during logout' });
            }
            console.log('User logged out successfully');
            res.json({ message: 'Logged out successfully' });
        });
    } else {
        console.log('Logout requested but user not authenticated');
        res.status(401).json({ message: 'Not authenticated' });
    }
});
