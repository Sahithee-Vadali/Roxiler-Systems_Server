const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { PrismaClient } = require("@prisma/client");

const app = express();
const prisma = new PrismaClient();

app.use(cors());
app.use(express.json());

// Secret for JWT
const JWT_SECRET = process.env.JWT_SECRET || "super-secret-key";

// Validation functions
const validateName = (name) => {
  return name && name.length >= 20 && name.length <= 60;
};

const validateAddress = (address) => {
  return address && address.length <= 400;
};

const validatePassword = (password) => {
  const hasUpperCase = /[A-Z]/.test(password);
  const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);
  return password && password.length >= 8 && password.length <= 16 && hasUpperCase && hasSpecialChar;
};

const validateEmail = (email) => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return email && emailRegex.test(email);
};

// Middleware to protect routes
function authMiddleware(req, res, next) {
  const token = req.headers["authorization"];
  if (!token) return res.status(401).json({ error: "No token provided" });

  jwt.verify(token.split(" ")[1], JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ error: "Invalid token" });
    req.user = decoded;
    next();
  });
}

// Middleware to check if user is admin
function adminMiddleware(req, res, next) {
  if (req.user.role !== "ADMIN") {
    return res.status(403).json({ error: "Admin access required" });
  }
  next();
}

// Middleware to check if user is store owner
function ownerMiddleware(req, res, next) {
  if (req.user.role !== "OWNER") {
    return res.status(403).json({ error: "Store owner access required" });
  }
  next();
}

// 👤 Signup (Admin only)
app.post("/signup", authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { name, email, password, role } = req.body;

    // Validations
    if (!validateName(name)) {
      return res.status(400).json({ error: "Name must be 20-60 characters" });
    }
    if (!validateEmail(email)) {
      return res.status(400).json({ error: "Invalid email format" });
    }
    if (!validatePassword(password)) {
      return res.status(400).json({ error: "Password must be 8-16 characters with uppercase and special character" });
    }
    if (!["USER", "OWNER", "ADMIN"].includes(role)) {
      return res.status(400).json({ error: "Invalid role" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = await prisma.user.create({
      data: { name, email, password: hashedPassword, role },
    });

    res.json({ message: "User created", user: { id: user.id, name: user.name, email: user.email, role: user.role } });
  } catch (err) {
    if (err.code === 'P2002') {
      return res.status(400).json({ error: "Email already exists" });
    }
    res.status(500).json({ error: err.message });
  }
});

// 🔑 Login
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!validateEmail(email)) {
      return res.status(400).json({ error: "Invalid email format" });
    }

    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) return res.status(400).json({ error: "User not found" });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(400).json({ error: "Invalid password" });

    const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, {
      expiresIn: "24h",
    });

    res.json({ 
      token,
      user: { id: user.id, name: user.name, email: user.email, role: user.role }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 🔄 Update Password
app.put("/users/password", authMiddleware, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;

    if (!validatePassword(newPassword)) {
      return res.status(400).json({ error: "Password must be 8-16 characters with uppercase and special character" });
    }

    const user = await prisma.user.findUnique({ where: { id: req.user.id } });
    const valid = await bcrypt.compare(currentPassword, user.password);
    if (!valid) return res.status(400).json({ error: "Current password is incorrect" });

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await prisma.user.update({
      where: { id: req.user.id },
      data: { password: hashedPassword }
    });

    res.json({ message: "Password updated successfully" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 👥 CRUD Operations for Users (Admin only)
app.get("/admin/users", authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { search, role } = req.query;
    
    let whereClause = {};
    if (search) {
      whereClause.name = { contains: search, mode: 'insensitive' };
    }
    if (role && ["USER", "OWNER", "ADMIN"].includes(role)) {
      whereClause.role = role;
    }

    const users = await prisma.user.findMany({
      where: whereClause,
      select: {
        id: true,
        name: true,
        email: true,
        role: true,
        createdAt: true,
        _count: {
          select: {
            ratings: true,
            stores: true
          }
        }
      },
      orderBy: { name: 'asc' }
    });

    res.json(users);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put("/admin/users/:id", authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { name, email, role } = req.body;
    const userId = parseInt(req.params.id);

    if (!validateName(name)) {
      return res.status(400).json({ error: "Name must be 20-60 characters" });
    }
    if (!validateEmail(email)) {
      return res.status(400).json({ error: "Invalid email format" });
    }
    if (!["USER", "OWNER", "ADMIN"].includes(role)) {
      return res.status(400).json({ error: "Invalid role" });
    }

    const user = await prisma.user.update({
      where: { id: userId },
      data: { name, email, role },
      select: {
        id: true,
        name: true,
        email: true,
        role: true,
        createdAt: true
      }
    });

    res.json({ message: "User updated", user });
  } catch (err) {
    if (err.code === 'P2002') {
      return res.status(400).json({ error: "Email already exists" });
    }
    res.status(500).json({ error: err.message });
  }
});

app.delete("/admin/users/:id", authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const userId = parseInt(req.params.id);
    
    // Check if user has stores or ratings
    const user = await prisma.user.findUnique({
      where: { id: userId },
      include: {
        _count: {
          select: { stores: true, ratings: true }
        }
      }
    });

    if (user._count.stores > 0 || user._count.ratings > 0) {
      return res.status(400).json({ error: "Cannot delete user with stores or ratings" });
    }

    await prisma.user.delete({ where: { id: userId } });
    res.json({ message: "User deleted successfully" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 🏪 CRUD Operations for Stores (Admin only)
app.post("/stores", authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { name, address, ownerId } = req.body;

    if (!validateName(name)) {
      return res.status(400).json({ error: "Name must be 20-60 characters" });
    }
    if (!validateAddress(address)) {
      return res.status(400).json({ error: "Address must be up to 400 characters" });
    }

    // Check if owner exists and is an OWNER
    const owner = await prisma.user.findUnique({ where: { id: ownerId } });
    if (!owner || owner.role !== "OWNER") {
      return res.status(400).json({ error: "Invalid owner ID or user is not a store owner" });
    }

    const store = await prisma.store.create({
      data: { name, address, ownerId },
      include: { owner: { select: { id: true, name: true, email: true } } }
    });

    res.json(store);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/admin/stores", authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { search } = req.query;
    
    let whereClause = {};
    if (search) {
      whereClause = {
        OR: [
          { name: { contains: search, mode: 'insensitive' } },
          { address: { contains: search, mode: 'insensitive' } }
        ]
      };
    }

    const stores = await prisma.store.findMany({
      where: whereClause,
      include: {
        owner: { select: { id: true, name: true, email: true } },
        ratings: {
          include: {
            user: { select: { id: true, name: true } }
          }
        }
      },
      orderBy: { name: 'asc' }
    });

    const result = stores.map((store) => {
      const avg = store.ratings.length > 0 
        ? store.ratings.reduce((a, r) => a + r.rating, 0) / store.ratings.length
        : 0;
      return { 
        ...store, 
        averageRating: parseFloat(avg.toFixed(1)),
        totalRatings: store.ratings.length
      };
    });

    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put("/admin/stores/:id", authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { name, address, ownerId } = req.body;
    const storeId = parseInt(req.params.id);

    if (!validateName(name)) {
      return res.status(400).json({ error: "Name must be 20-60 characters" });
    }
    if (!validateAddress(address)) {
      return res.status(400).json({ error: "Address must be up to 400 characters" });
    }

    // Check if owner exists and is an OWNER
    const owner = await prisma.user.findUnique({ where: { id: ownerId } });
    if (!owner || owner.role !== "OWNER") {
      return res.status(400).json({ error: "Invalid owner ID or user is not a store owner" });
    }

    const store = await prisma.store.update({
      where: { id: storeId },
      data: { name, address, ownerId },
      include: { owner: { select: { id: true, name: true, email: true } } }
    });

    res.json({ message: "Store updated", store });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete("/admin/stores/:id", authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const storeId = parseInt(req.params.id);
    
    // Delete all ratings for this store first
    await prisma.rating.deleteMany({ where: { storeId } });
    
    // Then delete the store
    await prisma.store.delete({ where: { id: storeId } });
    
    res.json({ message: "Store deleted successfully" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 🌟 Rate Store (Normal User only)
app.post("/stores/:id/rate", authMiddleware, async (req, res) => {
  if (req.user.role !== "USER") {
    return res.status(403).json({ error: "Only normal users can rate stores" });
  }

  try {
    const { rating } = req.body;

    if (!rating || rating < 1 || rating > 5) {
      return res.status(400).json({ error: "Rating must be between 1 and 5" });
    }

    const storeId = parseInt(req.params.id);
    const store = await prisma.store.findUnique({ where: { id: storeId } });
    if (!store) {
      return res.status(404).json({ error: "Store not found" });
    }

    // Check if user already rated this store
    const existingRating = await prisma.rating.findUnique({
      where: { storeId_userId: { storeId, userId: req.user.id } }
    });

    if (existingRating) {
      // Update existing rating
      const updatedRating = await prisma.rating.update({
        where: { id: existingRating.id },
        data: { rating }
      });
      res.json(updatedRating);
    } else {
      // Create new rating
      const newRating = await prisma.rating.create({
        data: { rating, storeId, userId: req.user.id }
      });
      res.json(newRating);
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 📜 Get all stores with average ratings (searchable)
app.get("/stores", async (req, res) => {
  try {
    const { search } = req.query;
    
    let whereClause = {};
    if (search) {
      whereClause = {
        OR: [
          { name: { contains: search, mode: 'insensitive' } },
          { address: { contains: search, mode: 'insensitive' } }
        ]
      };
    }

    const stores = await prisma.store.findMany({
      where: whereClause,
      include: {
        ratings: {
          include: {
            user: { select: { id: true, name: true } }
          }
        },
        owner: { select: { id: true, name: true, email: true } }
      },
      orderBy: { name: 'asc' }
    });

    const result = stores.map((store) => {
      const avg = store.ratings.length > 0 
        ? store.ratings.reduce((a, r) => a + r.rating, 0) / store.ratings.length
        : 0;
      return { 
        ...store, 
        averageRating: parseFloat(avg.toFixed(1)),
        totalRatings: store.ratings.length
      };
    });

    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 📊 Admin Dashboard
app.get("/admin/dashboard", authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const totalUsers = await prisma.user.count();
    const totalStores = await prisma.store.count();
    const totalRatings = await prisma.rating.count();

    const usersByRole = await prisma.user.groupBy({
      by: ['role'],
      _count: { role: true }
    });

    const roleCounts = {};
    usersByRole.forEach(item => {
      roleCounts[item.role] = item._count.role;
    });

    // Get top rated stores
    const topStores = await prisma.store.findMany({
      include: {
        ratings: true,
        owner: { select: { name: true } }
      },
      orderBy: {
        ratings: {
          _count: 'desc'
        }
      },
      take: 5
    });

    const topStoresWithAvg = topStores.map(store => {
      const avg = store.ratings.length > 0 
        ? store.ratings.reduce((a, r) => a + r.rating, 0) / store.ratings.length
        : 0;
      return {
        id: store.id,
        name: store.name,
        averageRating: parseFloat(avg.toFixed(1)),
        totalRatings: store.ratings.length,
        owner: store.owner.name
      };
    });

    res.json({
      totalUsers,
      totalStores,
      totalRatings,
      usersByRole: roleCounts,
      topStores: topStoresWithAvg
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 🏪 Get store owner's stores with ratings
app.get("/owner/stores", authMiddleware, ownerMiddleware, async (req, res) => {
  try {
    const stores = await prisma.store.findMany({
      where: { ownerId: req.user.id },
      include: {
        ratings: {
          include: {
            user: { select: { id: true, name: true, email: true } }
          }
        }
      }
    });

    const result = stores.map((store) => {
      const avg = store.ratings.length > 0 
        ? store.ratings.reduce((a, r) => a + r.rating, 0) / store.ratings.length
        : 0;
      return { 
        ...store, 
        averageRating: parseFloat(avg.toFixed(1)),
        totalRatings: store.ratings.length
      };
    });

    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 🚀 Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`✅ Server running on http://localhost:${PORT}`);
});
