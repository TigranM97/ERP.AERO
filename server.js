const express = require("express");
const cors = require("cors");
const app = express();
const pool = require("./config/database");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const Joi = require('joi');
const multer = require('multer');
const path = require('path');
const fs = require("fs");

const PORT = process.env.APP_PORT || 3001;

app.use(cors());
app.use(express.json());

const upload = multer({ dest: 'uploads/' });

const registrationSchema = Joi.object({
  firstName: Joi.string().required(),
  lastName: Joi.string().required(),
  email: Joi.string().email().required(),
  phoneNumber: Joi.string().length(12).required(),
  password: Joi.string().min(5).required(),
});

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, path.join(__dirname, "uploads"));
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
    const fileExtension = path.extname(file.originalname);
    cb(null, uniqueSuffix + fileExtension);
  },
});

const update = multer({ storage });


app.post('/users/signup', async (req, res) => {
  const { firstName, lastName, email, password } = req.body;
  const { error } = registrationSchema.validate({ firstName, lastName, email, password });
  if (error) {
    res.status(400).json({ error: error.details[0].message });
    return;
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    const query = `INSERT INTO users (first_name, last_name, email, password) VALUES (?, ?, ?, ?)`;
    const values = [firstName, lastName, email, hashedPassword];
    pool.query(query, values);

    res.status(200).json({ message: 'User registered successfully' });
  } catch (error) {
    console.error('Error during user registration:', error);
    res.status(500).json({ error: 'Error during user registration' });
  }
});


let refreshTokens = []; // in production keeping in DB

app.post("/signin/new_token", (req, res) => {
  const refreshToken = req.body.token;
  if (refreshToken == null) return res.sendStatus(401);
  if (!refreshTokens.includes(refreshToken)) return res.sendStatus(403);
  jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    const accessToken = generateAccessToken({ name: user.name });
    res.json({ accessToken: accessToken });
  });
});

app.post('/users/signin', (req, res) => {
  const { identifier, password } = req.body;

  const query = `
    SELECT * FROM users
    WHERE email = ? OR phone_number = ?
  `;

  pool.query(query, [identifier, identifier], async (err, rows) => {
    if (err) {
      console.error('Error retrieving user from database:', err);
      res.status(500).json({ error: 'Internal server error' });
      return;
    }

    if (rows.length === 0) {
      res.status(401).json({ error: 'Invalid credentials' });
      return;
    }

    const user = rows[0];

    try {
      const isPasswordValid = await bcrypt.compare(password, user.password);

      if (!isPasswordValid) {
        res.status(401).json({ error: 'Invalid credentials' });
        return;
      }

      // Generate JWT access and refresh tokens
      const accessToken = jwt.sign({ userId: user.id }, process.env.ACCESS_SECRET_TOKEN, { expiresIn: '10m' });
      const refreshToken = jwt.sign({ userId: user.id },  process.env.REFRESH_TOKEN_SECRET, { expiresIn: '7d' });
      refreshTokens.push(refreshToken) // in production insert to DB

      res.status(200).json({ accessToken, refreshToken });
    } catch (error) {
      console.error('Error during password comparison:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  });
});

app.post('/file/upload', upload.single('file'), (req, res) => {
  console.log("req.file", req.file);
  const { originalname, mimetype, size } = req.file;
  const extension = path.extname(originalname);
  const name = path.basename(originalname, extension);

  const query = 'INSERT INTO files (name, extension, mime_type, size) VALUES (?, ?, ?, ?)';
  const values = [name, extension, mimetype, size];

  pool.query(query, values, (err, result) => {
    if (err) {
      console.error('Error inserting file data into database:', err);
      res.status(500).json({ error: 'Error inserting data into database' });
      return;
    }

    res.status(200).json({ message: 'File uploaded and data recorded successfully' });
  });
});

app.get("/file/list", async (req, res) => {
  const pageSize = parseInt(req.query.list_size) || 10; 
  const page = parseInt(req.query.page) || 1;
  const offset = (page - 1) * pageSize; 

  try {
    const countQuery = "SELECT COUNT(*) AS total FROM files";
    const totalCountResult = await pool.query(countQuery);
    const totalCount = totalCountResult[0].total;

    const query = "SELECT * FROM files LIMIT ? OFFSET ?";
    const values = [pageSize, offset];
    const files = await pool.query(query, values);

    const totalPages = Math.ceil(totalCount / pageSize); 

    res.status(200).json({
      files,
      pagination: {
        totalFiles: totalCount,
        totalPages,
        currentPage: page,
        pageSize,
      },
    });
  } catch (error) {
    console.error("Error retrieving files from database:", error);
    res.status(500).json({ error: "Error retrieving files from database" });
  }
});



app.delete("/file/delete/:id", async (req, res) => {
  const fileId = req.params.id; 

  try {
    const query = "SELECT * FROM files WHERE id = ?";
    const result = await pool.query(query, [fileId]);
    const file = result[0];

    if (!file) {
      return res.status(404).json({ error: "File not found" });
    }

    const deleteQuery = "DELETE FROM files WHERE id = ?";
    await pool.query(deleteQuery, [fileId]);

    const filePath = path.join(__dirname, "uploads", file.filename);
    fs.unlink(filePath, (err) => {
      if (err) {
        console.error("Error deleting file from local storage:", err);
      }
    });

    res.status(200).json({ message: "File deleted successfully" });
  } catch (error) {
    console.error("Error deleting file:", error);
    res.status(500).json({ error: "Error deleting file" });
  }
});

app.get("/file/:id", async (req, res) => {
  const fileId = req.params.id; 

  try {
    const query = "SELECT * FROM files WHERE id = ?";
    const result = await pool.query(query, [fileId]);
    const file = result[0];

    if (!file) {
      return res.status(404).json({ error: "File not found" });
    }

    res.status(200).json({ file });
  } catch (error) {
    console.error("Error retrieving file:", error);
    res.status(500).json({ error: "Error retrieving file" });
  }
});

app.get("/file/download/:id", async (req, res) => {
  const fileId = req.params.id;

  try {
    const query = "SELECT * FROM files WHERE id = ?";
    const result = await pool.query(query, [fileId]);
    const file = result[0];

    if (!file) {
      return res.status(404).json({ error: "File not found" });
    }

    const filePath = path.join(__dirname, "uploads", file.filename);

    res.setHeader("Content-Disposition", `attachment; filename=${file.filename}`);
    res.setHeader("Content-Type", file.mimeType);

    res.sendFile(filePath);
  } catch (error) {
    console.error("Error downloading file:", error);
    res.status(500).json({ error: "Error downloading file" });
  }
});


app.put("/file/update/:id", update.single("file"), async (req, res) => {
  const fileId = req.params.id; 
  try {
    const query = "SELECT * FROM files WHERE id = ?";
    const result = await pool.query(query, [fileId]);
    const file = result[0];

    if (!file) {
      return res.status(404).json({ error: "File not found" });
    }

    const filePath = path.join(__dirname, "uploads", file.filename);
    fs.unlink(filePath, (err) => {
      if (err) {
        console.error("Error deleting old file from local storage:", err);
      }
    });

    const newFilename = req.file.filename;
    const updateQuery = "UPDATE files SET filename = ? WHERE id = ?";
    await pool.query(updateQuery, [newFilename, fileId]);

    res.status(200).json({ message: "File updated successfully" });
  } catch (error) {
    console.error("Error updating file:", error);
    res.status(500).json({ error: "Error updating file" });
  }
});

app.delete('/logout', (req, res) => {
  refreshTokens = refreshTokens.filter(token => token !== req.body.token)
  res.sendStatus(204)
})


function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) {
    return res.sendStatus(401);
  }
  jwt.verify(token, process.env.ACCESS_SECRET_TOKEN, (err, user) => {
    if (err) {
      return res.sendStatus(403);
    }
    req.user = user;
    next();
  });
}

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
