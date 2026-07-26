const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const compression = require('compression');
require('dotenv').config();

const app = express();
app.set('trust proxy',1);
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || '0fa16d9e26cbedfc10a9f40c61d124bfc77d847306eedae081f6067ca2d15fafb123b55d63dbc4bd1722b5d9ea82ed05cf24f13dfb5552d399033025a94c5ff3';

// ========== MIDDLEWARE ==========
app.use(helmet({
    contentSecurityPolicy: false
}));
app.use(compression());
app.use(cors({
    origin: '*',
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

// Increase payload size limit
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    validate: {
        xForwardedForHeader: false,
        trustProxy: false
    }
});
app.use('/api', limiter);

// ========== SERVE STATIC FILES ==========
// ✅ Serve index.html at root path
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Serve static files (CSS, JS, etc.)
app.use(express.static(__dirname));

// ========== MYSQL CONNECTION ==========
const db = mysql.createPool({
    host: 'localhost',
    user: 'root',
    password: 'ChinBaroda@1109', // CHANGE THIS
    database: 'eventgo_db',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// Test MySQL connection
db.getConnection((err, connection) => {
    if (err) {
        console.error('❌ MySQL Connection Failed:', err.message);
        process.exit(1);
    } else {
        console.log('✅ Connected to MySQL database');
        connection.release();
    }
});

// Promisify db queries
const query = (sql, params) => {
    return new Promise((resolve, reject) => {
        db.query(sql, params, (err, results) => {
            if (err) reject(err);
            else resolve(results);
        });
    });
};

// ========== TEST ENDPOINT ==========
app.get('/api/test', (req, res) => {
    res.json({
        status: 'success',
        message: '🚀 EventGo Server is running!',
        timestamp: new Date().toISOString()
    });
});

// ========== FILE UPLOAD SETUP ==========
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const uploadDir = './uploads';
        if (!fs.existsSync(uploadDir)) {
            fs.mkdirSync(uploadDir);
        }
        const userId = req.user ? req.user.id : 'temp';
        const userDir = path.join(uploadDir, String(userId));
        if (!fs.existsSync(userDir)) {
            fs.mkdirSync(userDir);
        }
        cb(null, userDir);
    },
    filename: (req, file, cb) => {
        const uniqueName = Date.now() + '-' + file.originalname;
        cb(null, uniqueName);
    }
});

const upload = multer({
    storage: storage,
    limits: { fileSize: 20 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        const allowedTypes = ['image/jpeg', 'image/png', 'image/jpg', 'application/pdf', 'image/heic', 'image/heif'];
        if (allowedTypes.includes(file.mimetype)) {
            cb(null, true);
        } else {
            cb(new Error('Invalid file type. Only JPG, PNG, PDF, HEIC allowed.'));
        }
    }
});

app.use('/uploads', express.static('uploads'));

// ========== AUTH MIDDLEWARE ==========
const authenticate = async (req, res, next) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) {
            return res.status(401).json({ error: 'Authentication required' });
        }

        const decoded = jwt.verify(token, JWT_SECRET);
        const users = await query('SELECT id, username, full_name, role FROM user WHERE id = ?', [decoded.id]);

        if (users.length === 0) {
            return res.status(401).json({ error: 'User not found' });
        }

        req.user = users[0];
        next();
    } catch (error) {
        return res.status(401).json({ error: 'Invalid or expired token' });
    }
};

// ========== AUTH ROUTES ==========
// Login - PLAIN TEXT PASSWORD COMPARISON
app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password required' });
        }

        console.log(`🔐 Login attempt: ${username}`);

        const users = await query(
            'SELECT id, username, password, full_name, role FROM user WHERE username = ?',
            [username]
        );

        if (users.length === 0) {
            console.log(`❌ User not found: ${username}`);
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const user = users[0];
        
        // ✅ PLAIN TEXT PASSWORD CHECK
        const validPassword = (password === user.password);

        if (!validPassword) {
            console.log(`❌ Invalid password for: ${username}`);
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        console.log(`✅ Login successful: ${username}`);

        const token = jwt.sign(
            { id: user.id, username: user.username, role: user.role },
            JWT_SECRET,
            { expiresIn: '7d' }
        );

        res.json({
            token,
            user: {
                id: user.id,
                username: user.username,
                full_name: user.full_name,
                role: user.role
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Get current user
app.get('/api/auth/me', authenticate, async (req, res) => {
    res.json(req.user);
});

// ========== REGISTER NEW USER - PUBLIC ==========
app.post('/api/auth/register', async (req, res) => {
    try {
        const { username, password, full_name, role } = req.body;
        
        console.log(`📝 Registration attempt: ${username}`);
        
        if (!username || !password || !full_name) {
            return res.status(400).json({ error: 'All fields required' });
        }
        
        // Check if user exists
        const existing = await query('SELECT id FROM user WHERE username = ?', [username]);
        if (existing.length > 0) {
            console.log(`❌ Username already exists: ${username}`);
            return res.status(400).json({ error: 'Username already exists' });
        }
        
        // Store password as plain text
        await query(
            'INSERT INTO user (username, password, full_name, role) VALUES (?, ?, ?, ?)',
            [username, password, full_name, role || 'employee']
        );
        
        console.log(`✅ User registered successfully: ${username}`);
        res.json({ message: 'User created successfully' });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// ========== PROJECT ROUTES ==========
app.get('/api/projects', authenticate, async (req, res) => {
    try {
        const projects = await query('SELECT * FROM projects ORDER BY name');
        res.json(projects);
    } catch (error) {
        console.error('Error fetching projects:', error);
        res.json([]);
    }
});

app.post('/api/projects', authenticate, async (req, res) => {
    try {
        const { name } = req.body;
        if (!name) {
            return res.status(400).json({ error: 'Project name required' });
        }

        const result = await query('INSERT INTO projects (name, created_by) VALUES (?, ?)', [name, req.user.id]);
        res.json({ id: result.insertId, name, message: 'Project added successfully' });
    } catch (error) {
        console.error('Error adding project:', error);
        if (error.code === 'ER_DUP_ENTRY') {
            return res.status(400).json({ error: 'Project already exists' });
        }
        res.status(500).json({ error: 'Server error' });
    }
});

// ========== EXPENSE ROUTES ==========
app.get('/api/expenses', authenticate, async (req, res) => {
    try {
        const { project, employee } = req.query;
        let sql = `
            SELECT 
                e.*,
                p.name as project_name,
                u.full_name as employee_name
            FROM expense e
            JOIN projects p ON e.project_id = p.id
            JOIN user u ON e.user_id = u.id
            WHERE 1=1
        `;
        const params = [];

        if (req.user.role === 'employee') {
            sql += ' AND e.user_id = ?';
            params.push(req.user.id);
        }

        if (project) {
            sql += ' AND p.name = ?';
            params.push(project);
        }

        if (employee && req.user.role === 'senior') {
            sql += ' AND u.full_name = ?';
            params.push(employee);
        }

        sql += ' ORDER BY e.expense_date DESC';

        const expenses = await query(sql, params);
        res.json(expenses);
    } catch (error) {
        console.error('Error fetching expenses:', error);
        res.json([]);
    }
});

app.post('/api/expenses', authenticate, upload.single('receipt'), async (req, res) => {
    try {
        console.log('📝 Received expense submission');
        console.log('Body:', req.body);
        console.log('File:', req.file);

        const { projectId, expenseDate, amount, expenseWhere, receipt } = req.body;
        const receiptFile = req.file ? `${req.user.id}/${req.file.filename}` : null;

        if (!projectId || !expenseDate || !amount || !expenseWhere) {
            return res.status(400).json({ error: 'All fields required' });
        }

        const receiptBool = receipt === 'yes' ? 1 : 0;

        const result = await query(
            `INSERT INTO expense 
             (project_id, user_id, expense_date, amount, expense_where, reciept, reciept_file) 
             VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [projectId, req.user.id, expenseDate, amount, expenseWhere, receiptBool, receiptFile]
        );

        console.log('✅ Expense added successfully, ID:', result.insertId);

        res.json({
            id: result.insertId,
            message: 'Expense added successfully',
            file: receiptFile
        });
    } catch (error) {
        console.error('❌ Error adding expense:', error);
        res.status(500).json({ error: 'Server error: ' + error.message });
    }
});

app.delete('/api/expenses/:id', authenticate, async (req, res) => {
    try {
        const { id } = req.params;

        const expense = await query('SELECT user_id, reciept_file FROM expense WHERE id = ?', [id]);

        if (expense.length === 0) {
            return res.status(404).json({ error: 'Expense not found' });
        }

        if (req.user.role !== 'senior' && expense[0].user_id !== req.user.id) {
            return res.status(403).json({ error: 'Not authorized to delete this expense' });
        }

        if (expense[0].reciept_file) {
            const filePath = path.join('./uploads', expense[0].reciept_file);
            if (fs.existsSync(filePath)) {
                fs.unlinkSync(filePath);
            }
        }

        await query('DELETE FROM expense WHERE id = ?', [id]);
        res.json({ message: 'Expense deleted successfully' });
    } catch (error) {
        console.error('Error deleting expense:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// ========== EXPORT ROUTES ==========
app.get('/api/export/csv', authenticate, async (req, res) => {
    try {
        const { project, employee } = req.query;
        let sql = `
            SELECT 
                p.name as Project,
                u.full_name as Name,
                e.expense_date as Date,
                e.amount as Amount,
                e.expense_where as \`Where\`,
                CASE WHEN e.reciept = 1 THEN 'Yes' ELSE 'No' END as Receipt,
                e.reciept_file as 'Receipt File'
            FROM expense e
            JOIN projects p ON e.project_id = p.id
            JOIN user u ON e.user_id = u.id
            WHERE 1=1
        `;
        const params = [];

        if (req.user.role === 'employee') {
            sql += ' AND e.user_id = ?';
            params.push(req.user.id);
        }

        if (project) {
            sql += ' AND p.name = ?';
            params.push(project);
        }

        if (employee && req.user.role === 'senior') {
            sql += ' AND u.full_name = ?';
            params.push(employee);
        }

        sql += ' ORDER BY e.expense_date DESC';

        const data = await query(sql, params);

        if (data.length === 0) {
            return res.status(404).json({ error: 'No data to export' });
        }

        const csvRows = [];
        const headers = Object.keys(data[0]);
        csvRows.push(headers.join(','));

        for (const row of data) {
            const values = headers.map(header => {
                const val = row[header] || '';
                return `"${String(val).replace(/"/g, '""')}"`;
            });
            csvRows.push(values.join(','));
        }

        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', `attachment; filename=eventgo_${Date.now()}.csv`);
        res.send(csvRows.join('\n'));
    } catch (error) {
        console.error('Error exporting CSV:', error);
        res.status(500).json({ error: 'Server error: ' + error.message });
    }
});

// ========== START SERVER ==========
app.listen(PORT, () => {
    console.log(`\n🚀 EventGo Server running on http://localhost:${PORT}`);
    console.log(`📝 API Endpoints:`);
    console.log(`  GET  / - EventGo App (index.html)`);
    console.log(`  GET  /api/test - Test server`);
    console.log(`  POST /api/auth/login - Login`);
    console.log(`  POST /api/auth/register - Register user (public)`);
    console.log(`  GET  /api/auth/me - Get current user`);
    console.log(`  GET  /api/projects - Get projects`);
    console.log(`  POST /api/projects - Add project`);
    console.log(`  GET  /api/expenses - Get expenses`);
    console.log(`  POST /api/expenses - Add expense (Max 10MB)`);
    console.log(`  DELETE /api/expenses/:id - Delete expense`);
    console.log(`  GET  /api/export/csv - Export to CSV`);
    console.log(`\n💡 Default login: admin / admin123`);
    console.log(`🔗 Test URL: http://localhost:${PORT}/api/test`);
    console.log(`🌐 Open app: http://localhost:${PORT}/\n`);
});
