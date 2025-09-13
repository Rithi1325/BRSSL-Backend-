// server.js - Fixed Version with Better MongoDB Connection Handling
import express from "express";
import dotenv from "dotenv";
import cors from "cors";
import mongoose from "mongoose";
import path from "path";
import fs from "fs";
import { fileURLToPath } from "url";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

// Models
import User from "./models/User.js";

// Core Routes
import authRoutes from "./routes/authRoutes.js";
import employeeRoutes from "./routes/employees.js";
import dateTimeRoutes from "./routes/dateTimeRoutes.js";
import jewelRoutes from "./routes/jewelRoutes.js";
import stockSummaryRoutes from "./routes/stockSummaryRoutes.js";
import personalLoanRoutes from "./routes/personalLoanRoutes.js";
import savedLoanDetailRoutes from "./routes/savedloandetailRoutes.js";
import collectionRoutes from "./routes/collectionRoutes.js";
import overviewRoutes from "./routes/overviewRoutes.js";
import backupRoutes from "./routes/backupRoutes.js";

// Alternative auth route (if different from authRoutes)
let authRoutesAlt = null;
try {
  const altAuth = await import("./routes/auth.js");
  authRoutesAlt = altAuth.default;
} catch (err) {
  console.log("Alternative auth routes not found, using main auth routes");
}

// Alternative employee routes
let employeeRoutesAlt = null;
try {
  const altEmployee = await import("./routes/employeeRoutes.js");
  employeeRoutesAlt = altEmployee.default;
} catch (err) {
  console.log("Alternative employee routes not found, using main employee routes");
}

// -------- Fix __dirname in ES Modules --------
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// -------- Load env variables --------
dotenv.config();
console.log('Starting server...');
console.log('MongoDB URI:', process.env.MONGO_URI ? 'Present' : 'Missing');

// -------- Initialize app --------
const app = express();

// -------- Enhanced CORS configuration --------
app.use(cors({
  origin: [
    'http://localhost:3000', 
    'http://localhost:3001', 
    'http://localhost:5173'
  ],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Accept', 'X-Requested-With'],
  exposedHeaders: ['Content-Disposition', 'Content-Length', 'Content-Type']
}));

// -------- Middleware --------
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// -------- Create necessary directories --------
const createDirectories = () => {
  const dirs = [
    path.join(__dirname, "uploads"),
    path.join(__dirname, "Uploads"),
    path.join(__dirname, "Uploads", "backups"),
    path.join(__dirname, "temp"),
    path.join(__dirname, "public")
  ];
  
  dirs.forEach(dir => {
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
      console.log(`📂 Created directory: ${dir}`);
    }
  });
};
createDirectories();

// -------- Serve static files --------
app.use("/uploads", express.static(path.join(__dirname, "uploads")));
app.use("/uploads", express.static(path.join(__dirname, "Uploads")));
app.use("/temp", express.static(path.join(__dirname, "temp")));
app.use(express.static(path.join(__dirname, "public")));

// -------- JWT & Admin Middleware --------
export const protect = (req, res, next) => {
  const token = req.header("Authorization")?.replace("Bearer ", "");
  if (!token) return res.status(401).json({ msg: "No token, authorization denied" });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded.user;
    next();
  } catch (err) {
    res.status(401).json({ msg: "Token is not valid" });
  }
};

export const authorize = (req, res, next) => {
  if (!req.user || req.user.role !== "admin") {
    return res.status(403).json({ msg: "Access denied. Admin privileges required." });
  }
  next();
};

// -------- Create Default Admin --------
const createDefaultAdmin = async () => {
  try {
    const adminExists = await User.findOne({ email: "admin@gmail.com" });
    if (!adminExists) {
      const hashedPassword = await bcrypt.hash("admin123", 10);
      await User.create({
        name: "Admin",
        email: "admin@gmail.com",
        password: hashedPassword,
        role: "admin",
      });
      console.log("✅ Default admin created");
    }
  } catch (err) {
    console.error("❌ Error creating default admin:", err);
  }
};

// -------- Database Connection --------
const connectDB = async () => {
  try {
    mongoose.set("strictQuery", false);
    
    // Updated connection options without deprecated parameters
    await mongoose.connect(process.env.MONGO_URI, {
      serverSelectionTimeoutMS: 10000,
      socketTimeoutMS: 45000,
      bufferMaxEntries: 0,
      connectTimeoutMS: 10000
    });
    
    console.log("✅ MongoDB Connected");
    
    // Test database connection by attempting to list collections
    const collections = await mongoose.connection.db.listCollections().toArray();
    console.log('Available collections:', collections.map(c => c.name));
    
    return true;
  } catch (err) {
    console.error("❌ MongoDB Connection Failed:", {
      message: err.message,
      stack: err.stack,
      timestamp: new Date().toISOString()
    });
    
    // Provide more helpful error message for IP whitelisting issue
    if (err.message.includes("Could not connect to any servers in your MongoDB Atlas cluster")) {
      console.error("🔍 This is likely an IP whitelisting issue. Please add Render's IP addresses to your MongoDB Atlas whitelist.");
      console.error("🔗 For more information: https://render.com/docs/faq#how-do-i-connect-to-databases-from-render");
    }
    
    throw err;
  }
};

// -------- Import optional dynamic routes --------
const importRoute = async (routePath, routeName) => {
  try {
    const route = await import(routePath);
    if (route.default) {
      console.log(`✅ ${routeName} loaded successfully.`);
      return route.default;
    } else {
      console.warn(`⚠️ ${routeName} loaded but no default export found.`);
      return null;
    }
  } catch (err) {
    console.warn(`⚠️ ${routeName} not found, skipping... Error: ${err.message}`);
    return null;
  }
};

// -------- Load all optional routes --------
const loadOptionalRoutes = async () => {
  const routes = {};
  
  const optionalRoutes = [
    { path: "./routes/customerRoutes.js", name: "customerRoutes" },
    { path: "./routes/loanRoutes.js", name: "loanRoutes" },
    { path: "./routes/financialYearRoutes.js", name: "financialYearRoutes" },
    { path: "./routes/jewelRateRoutes.js", name: "jewelRateRoutes" },
    { path: "./routes/interestRateRoutes.js", name: "interestRateRoutes" },
    { path: "./routes/interestRoutes.js", name: "interestRoutes" },
    { path: "./routes/voucherRoutes.js", name: "voucherRoutes" },
    { path: "./routes/trashRoutes.js", name: "trashRoutes" },
    { path: "./routes/dayBookRoutes.js", name: "dayBookRoutes" },
    { path: "./routes/ledgerRoutes.js", name: "ledgerRoutes" },
    { path: "./routes/backupRoutes.js", name: "backupRoutes" }
  ];
  
  for (const route of optionalRoutes) {
    routes[route.name] = await importRoute(route.path, route.name);
  }
  
  return routes;
};

// -------- Register all routes --------
const registerRoutes = async (optionalRoutes) => {
  console.log('Registering routes...');
  
  // Core routes - always available
  app.use("/api/auth", authRoutesAlt || authRoutes);
  app.use("/api/employees", employeeRoutesAlt || employeeRoutes);
  app.use("/api/datetime", dateTimeRoutes);
  app.use("/api/jewels", jewelRoutes);
  
  // Enhanced logging for key routes
  app.use("/api/stock-summary", (req, res, next) => {
    console.log(`Stock Summary API: ${req.method} ${req.path}`, {
      query: req.query,
      timestamp: new Date().toISOString()
    });
    next();
  }, stockSummaryRoutes);
  
  app.use("/api/personal-loans", personalLoanRoutes);
  
  app.use("/api/saved-loans", (req, res, next) => {
    console.log(`Saved Loans API: ${req.method} ${req.path}`, {
      query: req.query,
      timestamp: new Date().toISOString()
    });
    next();
  }, savedLoanDetailRoutes);
  
  app.use("/api/collections", collectionRoutes);
  
  app.use("/api/overview", (req, res, next) => {
    console.log(`Overview API: ${req.method} ${req.path}`, {
      query: req.query,
      timestamp: new Date().toISOString()
    });
    next();
  }, overviewRoutes);
  
  // Optional routes registration
  const routeMapping = [
    { route: optionalRoutes.customerRoutes, endpoint: "/api/customers" },
    { route: optionalRoutes.loanRoutes, endpoint: "/api/loans" },
    { route: optionalRoutes.financialYearRoutes, endpoint: "/api/financial-year" },
    { route: optionalRoutes.jewelRateRoutes, endpoint: "/api/jewel-rates" },
    { route: optionalRoutes.interestRateRoutes, endpoint: "/api/interest-rates" },
    { route: optionalRoutes.interestRoutes, endpoint: "/api/interest" },
    { route: optionalRoutes.voucherRoutes, endpoint: "/api/vouchers" },
    { route: optionalRoutes.trashRoutes, endpoint: "/api/trash" },
    { route: optionalRoutes.dayBookRoutes, endpoint: "/api/daybook" },
    { route: optionalRoutes.ledgerRoutes, endpoint: "/api/ledger" },
    { route: optionalRoutes.backupRoutes, endpoint: "/api/backup" }
  ];
  
  routeMapping.forEach(({ route, endpoint }) => {
    if (route) {
      app.use(endpoint, route);
      console.log(`✅ ${endpoint} route registered`);
    }
  });
};

// -------- Utility Routes --------
const setupUtilityRoutes = () => {
  // Enhanced main route
  app.get('/', (req, res) => {
    res.json({ 
      message: '🏆 Loan & Jewelry Management API is running...', 
      version: '2.0.0',
      timestamp: new Date().toISOString(),
      endpoints: {
        health: '/health',
        apiStatus: '/api-status',
        dbInfo: '/db-info',
        initStock: '/init-stock',
        testStock: '/test-stock',
        // Core APIs
        auth: '/api/auth',
        employees: '/api/employees',
        jewels: '/api/jewels',
        collections: '/api/collections',
        // Main APIs
        stockSummary: '/api/stock-summary',
        personalLoans: '/api/personal-loans',
        savedLoans: '/api/saved-loans',
        overview: '/api/overview',
        // Optional APIs
        customers: '/api/customers',
        loans: '/api/loans',
        vouchers: '/api/vouchers',
        backup: '/api/backup'
      },
      status: 'Running'
    });
  });

  // Enhanced health check endpoint
  app.get('/health', async (req, res) => {
    try {
      const dbStatus = mongoose.connection.readyState === 1 ? 'Connected' : 'Disconnected';
      
      // Test various models
      const modelTests = {};
      const modelsToTest = [
        'StockSummary', 'SavedLoanDetail', 'Voucher', 'Customer', 'Collection', 'User'
      ];
      
      for (const modelName of modelsToTest) {
        try {
          const Model = (await import(`./models/${modelName}.js`)).default;
          const count = await Model.countDocuments();
          modelTests[modelName.toLowerCase()] = `Available (${count} records)`;
        } catch (error) {
          modelTests[modelName.toLowerCase()] = `Error: ${error.message}`;
        }
      }
      
      res.json({
        status: 'healthy',
        uptime: Math.floor(process.uptime()),
        memory: process.memoryUsage(),
        timestamp: new Date().toISOString(),
        environment: process.env.NODE_ENV || 'development',
        database: dbStatus,
        models: modelTests
      });
    } catch (error) {
      res.status(500).json({
        status: 'unhealthy',
        error: error.message,
        timestamp: new Date().toISOString()
      });
    }
  });

  // Stock summary initialization route
  app.get('/init-stock', async (req, res) => {
    try {
      console.log('Initializing stock summary...');
      
      const { createOrUpdateStockSummary } = await import('./controllers/stockSummaryController.js');
      
      const mockReq = { query: req.query, body: req.body, params: req.params };
      let responseData = null;
      let statusCode = 200;
      
      const mockRes = {
        json: (data) => { responseData = data; return mockRes; },
        status: (code) => { statusCode = code; return mockRes; }
      };
      
      await createOrUpdateStockSummary(mockReq, mockRes);
      
      res.status(statusCode).json({
        success: true,
        message: 'Stock summary initialization completed',
        result: responseData,
        timestamp: new Date().toISOString()
      });
      
    } catch (error) {
      console.error('Stock summary initialization failed:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to initialize stock summary',
        error: error.message,
        timestamp: new Date().toISOString()
      });
    }
  });

  // Test route for stock summary API
  app.get('/test-stock', async (req, res) => {
    try {
      const { getStockSummary } = await import('./controllers/stockSummaryController.js');
      
      const mockReq = { query: { limit: req.query.limit || 5, page: 1, ...req.query } };
      let responseData = null;
      let statusCode = 200;
      
      const mockRes = {
        json: (data) => { responseData = data; return mockRes; },
        status: (code) => { statusCode = code; return mockRes; }
      };
      
      await getStockSummary(mockReq, mockRes);
      
      res.status(statusCode).json({
        testSuccess: true,
        testTimestamp: new Date().toISOString(),
        apiResponse: responseData,
        testQuery: mockReq.query
      });
      
    } catch (error) {
      res.status(500).json({
        testSuccess: false,
        error: error.message,
        timestamp: new Date().toISOString()
      });
    }
  });

  // Database collections info endpoint
  app.get('/db-info', async (req, res) => {
    try {
      if (mongoose.connection.readyState !== 1) {
        return res.status(500).json({
          success: false,
          message: 'Database not connected'
        });
      }
      
      const collections = await mongoose.connection.db.listCollections().toArray();
      const collectionInfo = {};
      
      for (const collection of collections) {
        try {
          const count = await mongoose.connection.db.collection(collection.name).countDocuments();
          collectionInfo[collection.name] = {
            name: collection.name,
            count: count,
            type: collection.type || 'collection'
          };
        } catch (err) {
          collectionInfo[collection.name] = {
            name: collection.name,
            error: err.message
          };
        }
      }
      
      res.json({
        success: true,
        database: mongoose.connection.db.databaseName,
        collections: collectionInfo,
        totalCollections: collections.length,
        timestamp: new Date().toISOString()
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message: 'Failed to get database info',
        error: error.message
      });
    }
  });

  // API status endpoint
  app.get('/api-status', (req, res) => {
    const routes = [
      { name: 'Authentication', path: '/api/auth', status: 'active' },
      { name: 'Employees', path: '/api/employees', status: 'active' },
      { name: 'Date Time', path: '/api/datetime', status: 'active' },
      { name: 'Jewels', path: '/api/jewels', status: 'active' },
      { name: 'Personal Loans', path: '/api/personal-loans', status: 'active' },
      { name: 'Saved Loans', path: '/api/saved-loans', status: 'active' },
      { name: 'Stock Summary', path: '/api/stock-summary', status: 'active' },
      { name: 'Collections', path: '/api/collections', status: 'active' },
      { name: 'Overview', path: '/api/overview', status: 'active' }
      
    ];
    
    res.json({
      success: true,
      apiStatus: 'running',
      routes: routes,
      timestamp: new Date().toISOString(),
      version: '2.0.0'
    });
  });
};

// -------- Error handling middleware --------
const setupErrorHandling = async () => {
  // Try to load error middleware
  try {
    const { notFound, errorHandler } = await import("./middleware/errorMiddleware.js");
    app.use(notFound);
    app.use(errorHandler);
    console.log("✅ Error middleware loaded");
  } catch {
    console.warn("⚠️ Error middleware not found, using default handlers");
    
    // Default error handling
    app.use((err, req, res, next) => {
      console.error('Error:', {
        message: err.message,
        stack: err.stack,
        path: req.path,
        method: req.method,
        timestamp: new Date().toISOString()
      });
      
      res.status(err.status || 500).json({
        status: 'error',
        message: err.message || 'Internal Server Error',
        timestamp: new Date().toISOString(),
        path: req.path
      });
    });
    
    // 404 handler
    app.use((req, res) => {
      res.status(404).json({
        status: 'error',
        message: `Route ${req.originalUrl} not found`,
        timestamp: new Date().toISOString()
      });
    });
  }
};

// -------- Main startup function --------
const startServer = async () => {
  try {
    // Connect to MongoDB
    await connectDB();
    
    // Create default admin
    await createDefaultAdmin();
    
    // Load optional routes
    const optionalRoutes = await loadOptionalRoutes();
    
    // Register all routes
    await registerRoutes(optionalRoutes);
    
    // Setup utility routes
    setupUtilityRoutes();
    
    // Setup error handling
    await setupErrorHandling();
    
    // Start server
    const PORT = process.env.PORT || 5000;
    const server = app.listen(PORT, () => {
      console.log(`🚀 Server running on port ${PORT}`);
      console.log(`🔗 Server URL: http://localhost:${PORT}`);
      console.log(`💚 Health Check: http://localhost:${PORT}/health`);
      console.log(`📋 API Status: http://localhost:${PORT}/api-status`);
      console.log('✅ All systems operational!');
    });
    
    // Server error handling
    server.on('error', (err) => {
      if (err.code === 'EADDRINUSE') {
        console.error(`❌ Port ${PORT} is already in use. Please free the port or choose another.`);
        process.exit(1);
      } else {
        console.error('❌ Server startup error:', err);
        process.exit(1);
      }
    });
    
    // Graceful shutdown handlers
    const gracefulShutdown = (signal) => {
      console.log(`Received ${signal}. Performing graceful shutdown...`);
      server.close(() => {
        console.log('Server closed.');
        mongoose.connection.close(() => {
          console.log('MongoDB connection closed.');
          process.exit(0);
        });
      });
    };
    
    process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
    process.on('SIGINT', () => gracefulShutdown('SIGINT'));
    
    process.on('uncaughtException', (err) => {
      console.error('❌ Uncaught Exception:', err);
      process.exit(1);
    });
    
    process.on('unhandledRejection', (err) => {
      console.error('❌ Unhandled Rejection:', err);
      process.exit(1);
    });
    
    return server;
    
  } catch (error) {
    console.error('❌ Server startup failed:', error);
    process.exit(1);
  }
};

// -------- Start the application --------
startServer();

export default app;