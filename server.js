const express = require("express");
const multer = require("multer");
const path = require("path");
const cors = require("cors");
const helmet = require("helmet");
const dotenv = require("dotenv");
const oracledb = require("oracledb");
const bcrypt = require("bcryptjs"); // Add bcrypt for password hashing

dotenv.config();

const app = express();

// Set up middleware for security (Helmet)
app.use(helmet());

// Enable CORS for all requests
app.use(cors());

// To parse JSON bodies
app.use(express.json());

// Serve login page at the root
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "login.html"));
});

// Serve static HTML/CSS/JS files from 'public' folder after the login route
app.use(express.static(path.join(__dirname, "public")));

// Serve the main page after successful login
app.get("/index", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// Set up storage engine for multer (only video files)
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, "uploads/"); // Store the video file in the 'uploads' folder
  },
  filename: function (req, file, cb) {
    // Save the video file with a unique name using the current timestamp
    cb(null, Date.now() + path.extname(file.originalname));
  },
});

const upload = multer({
  storage: storage,
  limits: { fileSize: 200 * 1024 * 1024 }, // Set file size limit to 200MB (adjust as needed)
  fileFilter: function (req, file, cb) {
    const fileTypes = /mp4|mov|avi|mkv/;
    const extname = fileTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = fileTypes.test(file.mimetype);

    if (extname && mimetype) {
      return cb(null, true);
    } else {
      cb(new Error("Only video files are allowed!"));
    }
  },
});

// Database connection configuration
const dbConfig = {
  user: process.env.DB_USER || "system",
  password: process.env.DB_PASSWORD || "4493",
  connectionString: process.env.DB_CONNECTION_STRING || "localhost/XE",
};

// Function to load data on server start
let loadedData = [];
async function loadData() {
  let connection;
  try {
    connection = await oracledb.getConnection(dbConfig);
    const result = await connection.execute(`SELECT * FROM videos`);

    loadedData = result.rows.map((row) => ({
      id: Number(row[0]),
      title: String(row[1]),
      description: String(row[2]),
      tags: String(row[3]),
      videoPath: String(row[4]),
    }));

    console.log("Loaded data from database:", loadedData);
  } catch (err) {
    console.error("Error loading data on server start:", err);
  } finally {
    if (connection) {
      try {
        await connection.close();
      } catch (err) {
        console.error("Error closing database connection:", err);
      }
    }
  }
}

// Route to get loaded data
app.get("/api/videos", (req, res) => {
  try {
    res.json(loadedData);
  } catch (error) {
    console.error("Error serializing data:", error);
    res.status(500).send({ message: "Error serializing data." });
  }
});

app.use("/uploads", express.static(path.join(__dirname, "uploads")));

// Route to upload video
app.post("/upload-video", upload.single("videoFile"), async (req, res) => {
  const { title, description, tags } = req.body;
  const videoPath = req.file ? `/uploads/${req.file.filename}` : null;

  if (!title || !description || !tags || !videoPath) {
    return res.status(400).json({ message: "Please provide all fields and a video file." });
  }

  try {
    const connection = await oracledb.getConnection(dbConfig);
    await connection.execute(
      `INSERT INTO videos (title, description, tags, video_path) 
       VALUES (:title, :description, :tags, :videoPath)`,
      { title, description, tags, videoPath }
    );
    await connection.commit();
    await connection.close();

    loadedData.push({ title, description, tags, videoPath });
    res.json({ message: "Video uploaded successfully!", videoPath });
  } catch (err) {
    console.error("Database error:", err);
    res.status(500).json({ message: "Database error", error: err.message });
  }
});

// Route for user signup
app.post("/signup", async (req, res) => {
  const { username, password } = req.body;

  // Validate password
  if (!username || !password) {
    return res.status(400).json({ message: "Please provide both username and password." });
  }

  try {
    const connection = await oracledb.getConnection(dbConfig);

    // Check if the username already exists
    const checkUserResult = await connection.execute(
      `SELECT * FROM users WHERE username = :username`,
      { username }
    );

    if (checkUserResult.rows.length > 0) {
      return res.status(400).json({ message: "Username already exists." });
    }

    // Hash the password before storing it
    const hashedPassword = await bcrypt.hash(password, 10);

    await connection.execute(
      `INSERT INTO users (username, password) VALUES (:username, :password)`,
      { username, password: hashedPassword }
    );
    await connection.commit();
    await connection.close();

    res.json({ message: "User registered successfully!" });
  } catch (error) {
    console.error("Error during signup:", error);
    res.status(500).json({ message: "Error registering user." });
  }
});

// Route for user login
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: "Please provide both username and password." });
  }

  try {
    const connection = await oracledb.getConnection(dbConfig);
    const result = await connection.execute(
      `SELECT id, username, password FROM users WHERE username = :username AND ROWNUM = 1`,
      { username }
    );

    console.log("Database query result:", result); // Log the query result

    if (result.rows.length === 0) {
      return res.status(401).json({ message: "Invalid username or password." });
    }

    const user = result.rows[0]; // Assuming result.rows is an array of rows
    const storedPassword = user[2]; // Password is in the third column (index 2)

    console.log("Stored password (hashed):", storedPassword); // Log the stored password

    // Compare the provided password with the stored hashed password
    const isPasswordMatch = await bcrypt.compare(password, storedPassword);
    console.log("Password match:", isPasswordMatch); // Log if passwords match

    if (!isPasswordMatch) {
      return res.status(401).json({ message: "Invalid username or password." });
    }

    res.json({ message: "Login successful!" });
  } catch (error) {
    console.error("Error during login:", error);
    res.status(500).json({ message: "Error logging in." });
  }
});

// Centralized error-handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ message: "An internal server error occurred.", error: err.message });
});

// Start the server using environment variable PORT
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
