// server.js
import express from "express";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";

dotenv.config();
const app = express();
app.use(express.json());

// Secret key
const SECRET_KEY = process.env.JWT_SECRET || "myverysecuresecret";

// Dummy users with roles
const users = [
  { id: 1, username: "admin", password: "admin123", role: "Admin" },
  { id: 2, username: "mod", password: "mod123", role: "Moderator" },
  { id: 3, username: "user", password: "user123", role: "User" },
];
 
app.post("/login", (req, res) => {
  const { username, password } = req.body;
  const foundUser = users.find(
    (u) => u.username === username && u.password === password
  );

  if (!foundUser) {
    return res.status(401).json({ message: "Invalid username or password" });
  }

  // Create JWT including role in payload
  const token = jwt.sign(
    { id: foundUser.id, username: foundUser.username, role: foundUser.role },
    SECRET_KEY,
    { expiresIn: "1h" }
  );

  res.json({
    message: "Login successful",
    role: foundUser.role,
    token,
  });
});
function verifyToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1]; // Bearer <token>

  if (!token) {
    return res.status(403).json({ message: "Access denied. No token provided." });
  }

  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ message: "Invalid or expired token" });
  }
}
function authorizeRoles(...allowedRoles) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ message: "User not authenticated" });
    }

    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({
        message: `Access denied. Role '${req.user.role}' is not allowed.`,
      });
    }

    next();
  };
}
 
app.get("/admin/dashboard", verifyToken, authorizeRoles("Admin"), (req, res) => {
  res.json({
    message: "Welcome to the Admin Dashboard",
    user: req.user,
  });
});

// Accessible only by Moderator
app.get(
  "/moderator/manage",
  verifyToken,
  authorizeRoles("Moderator"),
  (req, res) => {
    res.json({
      message: "Moderator Management Panel Accessed",
      user: req.user,
    });
  }
);

// Accessible only by User
app.get("/user/profile", verifyToken, authorizeRoles("User"), (req, res) => {
  res.json({
    message: "Welcome to your User Profile",
    user: req.user,
  });
});

// Accessible by Admin or Moderator
app.get(
  "/shared/data",
  verifyToken,
  authorizeRoles("Admin", "Moderator"),
  (req, res) => {
    res.json({
      message: "Shared data for Admin and Moderator",
      user: req.user,
    });
  }
);

const PORT = process.env.PORT || 5000;
app.listen(PORT, () =>
  console.log(`✅ Server running on http://localhost:${PORT}`)
);
