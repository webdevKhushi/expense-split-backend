import dotenv from "dotenv";
dotenv.config();
import express from "express";
import cors from "cors";
import pkg from "pg";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

const { Pool } = pkg;
const app = express();
const PORT = 3000;
const JWT_SECRET = process.env.JWT_SECRET;

// ✅ CORS Fix (Add your frontend origin)
app.use(cors());
app.use(express.json()); // replaced bodyParser


// PostgreSQL Connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL || "postgresql://postgres:1234@localhost:5433/expensesplit",
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false,
});

// Auth Middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader?.split(" ")[1];

  if (!token) {
    return res.status(401).json({ message: "Token missing" });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ message: "Token invalid" });
    }
    req.user = user;
    next();
  });
}

// Signup
app.post("/api/signup", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ success: false, message: "Username and password required" });

  try {
    const hash = await bcrypt.hash(password, 10);
    await pool.query("INSERT INTO users (username, password) VALUES ($1, $2)", [username, hash]);
    const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: "1h" });
    res.json({ success: true, username, token });
  } catch (err) {
    console.error("Signup Error:", err.message);
    res.status(500).json({ success: false, message: "Signup failed" });
  }
});

// Login
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;
  try {
    const result = await pool.query("SELECT * FROM users WHERE username = $1", [username]);
    const user = result.rows[0];
    if (!user || !(await bcrypt.compare(password, user.password)))
      return res.status(401).json({ success: false, message: "Invalid credentials" });

    const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: "1h" });
    res.json({ success: true, username, token });
  } catch (err) {
    console.error("Login Error:", err.message);
    res.status(500).json({ success: false, message: "Login failed" });
  }
});

// Create Room
app.post("/api/rooms", authenticateToken, async (req, res) => {
  const { room_name } = req.body;
  const created_by = req.user.username;

  if (!room_name)
    return res.status(400).json({ message: "Room name is required" });

  try {
    const result = await pool.query(
      "INSERT INTO rooms (name, created_by) VALUES ($1, $2) RETURNING id",
      [room_name, created_by]
    );
    res.json({ success: true, roomId: result.rows[0].id, room_name });
  } catch (err) {
    console.error("Create Room Error:", err.message);
    res.status(500).json({ message: "Failed to create room" });
  }
});

app.post("/api/join-room", authenticateToken, async (req, res) => {
  const { room_id } = req.body;
  const username = req.user.username;

  try {
    const exists = await pool.query("SELECT * FROM rooms WHERE id = $1", [room_id]);
    if (exists.rowCount === 0)
      return res.status(404).json({ success: false, message: "Room not found" });

    // ✅ Check if already a participant
    const alreadyJoined = await pool.query(
      "SELECT 1 FROM participants WHERE room_id = $1 AND username = $2",
      [room_id, username]
    );

    if (alreadyJoined.rowCount === 0) {
      // Only insert if not already joined
      await pool.query(
        "INSERT INTO participants (room_id, username) VALUES ($1, $2)",
        [room_id, username]
      );

      await pool.query(
        `INSERT INTO room_expenses (room_id, username, description, amount, people, created_at)
         VALUES ($1, $2, $3, $4, $5, NOW())`,
        [room_id, username, 'joined the room', 0, 1]
      );
    }

    res.json({ success: true, message: "Joined room successfully" });
  } catch (err) {
    console.error("Join Room Error:", err.message);
    res.status(500).json({ success: false, message: "Failed to join room" });
  }
});


// Add Room Expense
app.post("/api/room/:roomId/expense", authenticateToken, async (req, res) => {
  const { roomId } = req.params;
  const { desc, amount } = req.body;
  const username = req.user.username;

  if (!desc || !amount)
    return res.status(400).json({ message: "All fields are required" });

  try {
    const roomResult = await pool.query("SELECT created_by FROM rooms WHERE id = $1", [roomId]);
    if (roomResult.rowCount === 0)
      return res.status(404).json({ message: "Room not found" });

    const roomCreator = roomResult.rows[0].created_by;
    if (username.trim().toLowerCase() !== roomCreator.trim().toLowerCase())
      return res.status(403).json({ message: "Only room creator can add expenses" });

    const countRes = await pool.query("SELECT COUNT(*) FROM participants WHERE room_id = $1", [roomId]);
    const people = parseInt(countRes.rows[0].count);

    await pool.query(
      "INSERT INTO room_expenses (room_id, username, description, amount, people, created_at) VALUES ($1, $2, $3, $4, $5, NOW())",
      [roomId, username, desc, amount, people]
    );

    res.json({ success: true, message: "Room expense added" });
  } catch (err) {
    console.error("Add Room Expense Error:", err.message);
    res.status(500).json({ success: false, message: "Failed to add room expense" });
  }
});

// Personal Expense
app.post("/api/expense", authenticateToken, async (req, res) => {
  const { desc, amount, people } = req.body;
  const username = req.user.username;

  if (!desc || !amount || !people)
    return res.status(400).json({ success: false, message: "All fields are required" });

  try {
    await pool.query(
      "INSERT INTO expenses (username, description, amount, people, created_at) VALUES ($1, $2, $3, $4, NOW())",
      [username, desc, amount, people]
    );
    res.json({ success: true });
  } catch (err) {
    console.error("Add Personal Expense Error:", err.message);
    res.status(500).json({ success: false });
  }
});

// Get Room Participants
app.get("/api/room/:roomId/participants", authenticateToken, async (req, res) => {
  const { roomId } = req.params;

  try {
    const result = await pool.query(
      "SELECT username FROM participants WHERE room_id = $1",
      [roomId]
    );

    res.json({ success: true, users: result.rows.map(r => r.username) });
  } catch (err) {
    console.error("Fetch Participants Error:", err.message);
    res.status(500).json({ success: false });
  }
});

// ✅ Get Room Details (with creator)
app.get("/api/room/:roomId/details", authenticateToken, async (req, res) => {
  const { roomId } = req.params;

  try {
    const participantsRes = await pool.query(
      "SELECT DISTINCT username FROM participants WHERE room_id = $1",
      [roomId]
    );

    const creatorRes = await pool.query(
      "SELECT created_by FROM rooms WHERE id = $1",
      [roomId]
    );

    const participants = participantsRes.rows.map((row) => ({
      name: row.username,
    }));

    const created_by = creatorRes.rows[0]?.created_by || "";

    res.json({ success: true, participants, created_by });
  } catch (err) {
    console.error("Fetch Room Details Error:", err.message);
    res.status(500).json({ success: false, message: "Failed to fetch room details" });
  }
});

// Shared Room History: Viewable by all participants
app.get("/api/room/:roomId/history", authenticateToken, async (req, res) => {
  const { roomId } = req.params;
  const username = req.user.username;

  // ✅ Validate roomId early
  if (!roomId || isNaN(roomId)) {
    return res.status(400).json({ success: false, message: "Invalid room ID" });
  }

  try {
    // ✅ Verify the user is part of the room
    const isParticipant = await pool.query(
      "SELECT 1 FROM participants WHERE room_id = $1 AND username = $2",
      [roomId, username]
    );

    if (isParticipant.rowCount === 0) {
      return res.status(403).json({ message: "You are not a member of this room" });
    }

    // ✅ Fetch all expenses for the room
    const result = await pool.query(
      `SELECT 
        username, description, amount, people, created_at 
       FROM room_expenses 
       WHERE room_id = $1
       ORDER BY created_at DESC`,
      [roomId]
    );

    res.json({ success: true, expenses: result.rows });
  } catch (err) {
    console.error("Room Expense History Error:", err.message);
    res.status(500).json({ success: false, message: "Failed to fetch room history" });
  }
});

// 🔧 Personal expense fetch
app.get("/api/expense/personal", authenticateToken, async (req, res) => {
  const username = req.user.username;

  try {
    const result = await pool.query(
      `SELECT e.description, e.amount, e.people, e.created_at, r.name AS room_name
       FROM expenses e
       LEFT JOIN rooms r ON e.room_id = r.id
       WHERE e.username = $1
       ORDER BY e.created_at DESC`,
      [username]
    );

    res.json(result.rows);
  } catch (err) {
    console.error("Fetch Personal Expense Error:", err.message);
    res.status(500).json({ success: false, message: "Failed to fetch personal expenses" });
  }
});


// Root
app.get("/", (req, res) => res.send("Server is running"));

app.listen(PORT, () => {
  console.log(`Backend running at http://localhost:${PORT}`);
});