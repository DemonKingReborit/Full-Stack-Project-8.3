const express = require("express");
const jwt = require("jsonwebtoken");

const app = express();
app.use(express.json());

// Secret key for signing JWT
const SECRET_KEY = "secretKey123"; // In production, use environment variables

// Sample users with roles
const users = [
  { username: "adminUser", password: "admin123", role: "Admin" },
  { username: "modUser", password: "mod123", role: "Moderator" },
  { username: "normalUser", password: "user123", role: "User" },
];

// ---------------------- LOGIN ROUTE ----------------------
app.post("/login", (req, res) => {
  const { username, password } = req.body;
  const foundUser = users.find(
    (u) => u.username === username && u.password === password
  );

  if (!foundUser) {
    return res.status(401).json({ message: "Invalid username or password" });
  }

  // Create JWT with role inside payload
  const token = jwt.sign(
    { username: foundUser.username, role: foundUser.role },
    SECRET_KEY,
    { expiresIn: "1h" }
  );

  res.json({
    message: `Login successful as ${foundUser.role}`,
    token,
  });
});

// ---------------------- VERIFY TOKEN MIDDLEWARE ----------------------
function verifyToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) return res.status(403).json({ message: "Token required" });

  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) return res.status(403).json({ message: "Invalid or expired token" });
    req.user = decoded;
    next();
  });
}

// ---------------------- ROLE CHECK MIDDLEWARE ----------------------
function authorizeRoles(...allowedRoles) {
  return (req, res, next) => {
    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({
        message: `Access denied: ${req.user.role} role is not authorized for this route`,
      });
    }
    next();
  };
}

// ---------------------- PROTECTED ROUTES ----------------------

// Admin-only route
app.get("/admin-dashboard", verifyToken, authorizeRoles("Admin"), (req, res) => {
  res.json({ message: `Welcome Admin ${req.user.username}!` });
});

// Moderator route
app.get("/moderator-tools", verifyToken, authorizeRoles("Admin", "Moderator"), (req, res) => {
  res.json({ message: `Moderator access granted to ${req.user.username}` });
});

// General user route
app.get("/user-profile", verifyToken, authorizeRoles("Admin", "Moderator", "User"), (req, res) => {
  res.json({ message: `Welcome to your profile, ${req.user.username}` });
});

// ---------------------- START SERVER ----------------------
const PORT = 5000;
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
