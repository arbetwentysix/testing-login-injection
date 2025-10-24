const express = require('express');
const path = require('path');
const session = require('express-session');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const db = require('./src/db');

const app = express();
const port = 3000;

app.use(bodyParser.urlencoded({ extended: true }));

app.use(express.static('src'));

app.use(session({
    secret: 'passwordnya-adalah-password',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 60 * 60 * 1000 }
}));

const validateUsername = (u) => {
  if (!u || typeof u !== 'string') return null;
  const t = u.trim();
  if (t.length < 3 || t.length > 50) return null;
  if (!/^[a-zA-Z0-9_.-]+$/.test(t)) return null;
  return t;
}

app.get('/', (req, res) => {
    if (req.session.isLoggedIn) {
        res.sendFile(path.join(__dirname, 'src/dashboard.html'));
    } else {
        res.redirect('/login');
    }
});

app.get('/dashboard', (req, res) => {
    if (req.session.isLoggedIn) {
        res.sendFile(path.join(__dirname, 'src/dashboard.html'));
    } else {
        res.redirect('/login');
    }
});

app.get('/login', (req, res) => {
    if (req.session.isLoggedIn) {
        return res.redirect('/dashboard');
    }

    res.sendFile(path.join(__dirname, 'src/login.html'));
});

app.post('/login', async (req, res) => {
  const rawUsername = req.body.username;
  const password = req.body.password;

  const username = validateUsername(rawUsername);
  if (!username || !password) {
    // Pesan generik — jangan bocorkan detail
    return res.status(401).send('Username atau Password salah.');
  }

  try {
    // === PARAMETERIZED QUERY (prepared statement) ===
    // Gunakan db.execute dengan placeholder (?) untuk mencegah injection
    const result = await db.query(
      'SELECT id, username, password FROM users WHERE username = $1 LIMIT 1',
      [username]
    );
    const user = result.rows[0];


    if (!user) {
      return res.status(401).send('Username atau Password salah.');
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).send('Username atau Password salah.');
    }

    // Regenerate session untuk mencegah session fixation
    req.session.regenerate((err) => {
      if (err) {
        console.error('Session regenerate error:', err);
        return res.status(500).send('Terjadi kesalahan server.');
      }

      // Simpan hanya data penting
      req.session.isLoggedIn = true;
      req.session.userId = user.id;
      req.session.username = user.username;

      res.redirect('/dashboard');
    });
  } catch (err) {
    console.error('Safe login error:', err);
    res.status(500).send('Terjadi kesalahan server.');
  }
});

app.get('/login-unsafe-sql', (req, res) => {
    if (req.session.isLoggedIn) {
      return res.redirect('/dashboard');
    }

    res.sendFile(path.join(__dirname, 'src/login-unsafe.html'));
});

app.post('/login-unsafe-sql', async (req, res) => {
  const { username, password } = req.body;

  try {
    // <<< TIDAK AMAN: input user disambung langsung ke string SQL >>>
    // Contoh berbahaya: username = "admin' OR '1'='1"
    // const sql = `SELECT id, username, password FROM users WHERE username = '${username}' LIMIT 1`;
    const sql = `SELECT id, username, password FROM users WHERE username = '${username}' AND password = '${password}' LIMIT 1`;
    const result = await db.query(sql);
    const user = result.rows[0];


    if (!user) {
      return res.status(401).send('Username atau Password salah.');
    }

    // Simpel: set session tanpa regenerate (jangan lakukan ini di production)
    req.session.isLoggedIn = true;
    req.session.username = user.username;

    res.redirect('/dashboard');
  } catch (err) {
    console.error('Unsafe login error:', err);
    res.status(500).send('Terjadi kesalahan server.');
  }
});

app.get('/register', (req, res) => {
  res.sendFile(path.join(__dirname, 'src/register.html'));
});

app.post('/register', async (req, res) => {
  const { username, password } = req.body;

  try {
    const result = await db.query(
      'SELECT username FROM users WHERE username = $1',
      [username]
    );

    if (result.rows.length > 0) {
      req.session.errorMessage = 'Username sudah terdaftar.';
      return res.redirect('/register');
    }
  
    const hashedPassword = await bcrypt.hash(password, 10);

    await db.query(
      'INSERT INTO users (username, password, role) VALUES ($1, $2, $3)',
      [username, hashedPassword, 'user']
    );

    res.redirect('/login');
    
  } catch (error) {
    console.error('Database/Bcrypt Error during registration:', error);
    res.status(500).send('Terjadi kesalahan server saat registrasi.');
  }
});

app.get('/register-unsafe', (req, res) => {
  res.sendFile(path.join(__dirname, 'src/register-unsafe.html'));
});

app.post('/register-unsafe', async (req, res) => {
  const { username, password } = req.body;

  try {
    // 1. Cek apakah username sudah digunakan
    const result = await db.query(
      'SELECT username FROM users WHERE username = $1',
      [username]
    );

    if (result.rows.length > 0) {
      req.session.errorMessage = 'Username sudah terdaftar.';
      return res.redirect('/register');
    }

    await db.query(
      'INSERT INTO users (username, password, role) VALUES ($1, $2, $3)',
      [username, password, 'user']
    );


    res.redirect('/login-unsafe-sql');
    
  } catch (error) {
    console.error('Database/Bcrypt Error during registration:', error);
    res.status(500).send('Terjadi kesalahan server saat registrasi.');
  }
});

app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error('Error saat logout:', err);
      return res.status(500).send('Terjadi kesalahan saat logout.');
    }
    res.redirect('/login');
  });
});

app.listen(port, () => {
  console.log(`app running in http://localhost:${port}`);
});