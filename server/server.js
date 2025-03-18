const express = require("express");
const mysql = require("mysql2/promise");
const cors = require("cors");
const multer = require("multer");
const nodemailer = require("nodemailer");
const { OAuth2Client } = require("google-auth-library");
const client = new OAuth2Client(
  "671845549558-ceaj5qh7romftff7r5cocnckuqo17cd0.apps.googleusercontent.com"
);
const fs = require("fs");
const path = require("path");
require("dotenv").config();

const app = express();
const port = 5000;

app.use(express.json());
app.use(cors());

// Set up multer for file uploads with memory storage and size limits
const storage = multer.memoryStorage();
const upload = multer({
  storage: storage,
  limits: {
    fieldSize: 25 * 1024 * 1024,
    fileSize: 25 * 1024 * 1024,
  },
});

// Database configuration
const dbConfig = {
  host: "localhost",
  user: "root",
  password: "cams@123",
  database: "CAMS_DB",
  connectionLimit: 10,
  port: 3307,
};

// Initialize database connection pool
const pool = mysql.createPool(dbConfig);
console.log("Database connected successfully");

// Close database connection pool on server shutdown
process.on("SIGINT", async () => {
  if (pool) {
    try {
      await pool.end();
      console.log("Database connection pool closed");
    } catch (err) {
      console.error("Error closing the connection pool:", err);
    }
  }
  process.exit();
});

// Registration
app.post("/register", async (req, res) => {
  const { firstName, lastName, username, password, email } = req.body;

  try {
    const connection = await pool.getConnection();

    // Check if username or email already exists
    const [checkUser] = await connection.execute(
      `SELECT username, uEmail FROM Users WHERE username = ? OR uEmail = ?`,
      [username, email]
    );

    if (checkUser.length > 0) {
      connection.release();
      return res
        .status(409)
        .json({ message: "Username or email already exists", success: false });
    }

    const defaultAvatarBase64 = await getDefaultAvatarBase64();

    // Insert new user
    await connection.execute(
      `INSERT INTO Users (username, password, uEmail, uTitle, userGroup, uStatus, uActivation, uImage)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        username,
        password,
        email,
        "Mr.",
        "Customer",
        "registered",
        "Active",
        defaultAvatarBase64,
      ]
    );

    connection.release();

    res
      .status(201)
      .json({ message: "User registered successfully", success: true });
  } catch (err) {
    console.error("Error during registration:", err);
    res.status(500).json({ message: "Server error", success: false });
  }
});

//Login
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  try {
    const connection = await pool.getConnection();

    // Verify user credentials and fetch userID, userGroup
    const [result] = await connection.execute(
      `SELECT userID, userGroup, uActivation FROM Users
       WHERE (username = ? OR uEmail = ?) AND password = ?`,
      [username, username, password]
    );

    if (result.length > 0) {
      const { userID, userGroup, uActivation } = result[0];

      // Update user status to logged in
      await connection.execute(
        `UPDATE Users SET uStatus = 'login' WHERE username = ? OR uEmail = ?`,
        [username, username]
      );

      connection.release();

      // Respond with userID and userGroup
      res.status(200).json({
        message: "Login Successful",
        success: true,
        userID,
        userGroup,
        uActivation,
      });
    } else {
      connection.release();
      res
        .status(401)
        .json({ message: "Invalid username or password", success: false });
    }
  } catch (err) {
    console.error("Error during login:", err);
    res.status(500).json({ message: "Server error", success: false });
  }
});

//Google login
app.post("/google-login", async (req, res) => {
  const { token } = req.body;

  try {
    // Get user info from Google
    const response = await fetch(
      "https://www.googleapis.com/oauth2/v3/userinfo",
      {
        headers: { Authorization: `Bearer ${token}` },
      }
    );
    const googleUser = await response.json();

    if (!googleUser.email) {
      return res
        .status(401)
        .json({ success: false, message: "Invalid Google token" });
    }

    const { email, given_name, family_name, picture } = googleUser;
    console.log("Google User Data:", googleUser);

    const connection = await pool.getConnection();

    // Check if user exists
    const [result] = await connection.execute(
      "SELECT userID, userGroup, uActivation, username FROM Users WHERE uEmail = ?",
      [email]
    );

    let username;
    if (result.length > 0) {
      // Existing user, update login status
      const {
        userID,
        userGroup,
        uActivation,
        username: existingUsername,
      } = result[0];
      username = existingUsername;

      await connection.execute(
        "UPDATE Users SET uStatus = 'login' WHERE uEmail = ?",
        [email]
      );
      connection.release();

      return res.status(200).json({
        success: true,
        message: "Google Login Successful",
        userID,
        userGroup,
        uActivation,
        username,
      });
    } else {
      const randomSixDigits = generateRandomSixDigits();
      username = given_name
        ? `${given_name}_${randomSixDigits}`
        : `user_${randomSixDigits}`;

      // Insert new Google user
      const [insertResult] = await connection.execute(
        `INSERT INTO Users (uEmail, uFirstName, uLastName, uImage, uTitle, uStatus, userGroup, uActivation, username) 
         VALUES (?, ?, ?, ?, ?, 'login', 'Customer', 'Active', ?)`,
        [
          email,
          given_name || null,
          family_name || null,
          picture || null,
          "Mr.",
          username,
        ]
      );

      const newUserID = insertResult.insertId;
      connection.release();

      return res.status(201).json({
        success: true,
        message: "Google Login Successful, new user created",
        userID: newUserID,
        userGroup: "Customer",
        uActivation: "Active",
        username,
      });
    }
  } catch (error) {
    console.error("Google Login Error:", error);
    return res
      .status(500)
      .json({ success: false, message: "Google Login Failed" });
  }
});

// User logout endpoint
app.post("/logout", async (req, res) => {
  const { userID } = req.body;

  try {
    const connection = await pool.getConnection();

    // Update user status to logged out
    await connection.execute(
      "UPDATE Users SET uStatus = 'logout' WHERE userID = ?",
      [userID]
    );

    connection.release();

    res.status(200).json({ message: "Logout Successful", success: true });
  } catch (err) {
    console.error("Error during logout:", err);
    res.status(500).json({ message: "Server error", success: false });
  }
});

// Fetch list of customers
app.get("/users/customers", async (req, res) => {
  try {
    const connection = await pool.getConnection();

    // Fetch customers
    const [rows] = await connection.execute(`
      SELECT userID, uFirstName, uLastName, uEmail, uPhoneNo, uCountry, uZipCode, uActivation, uGender, uTitle
      FROM Users
      WHERE userGroup = 'Customer'
    `);

    connection.release();

    res.status(200).json(rows);
  } catch (err) {
    console.error("Error fetching customers:", err);
    res.status(500).json({ message: "Server error", success: false });
  }
});

// Fetch list of owners
app.get("/users/owners", async (req, res) => {
  try {
    const connection = await pool.getConnection();

    // Fetch owners
    const [rows] = await connection.execute(`
      SELECT userID, username, uFirstName, uLastName, uEmail, uPhoneNo, uCountry, uZipCode, uGender, userGroup, uTitle
      FROM Users
      WHERE userGroup = 'Owner'
    `);

    connection.release();

    res.status(200).json(rows);
  } catch (err) {
    console.error("Error fetching owners:", err);
    res.status(500).json({ message: "Server error", success: false });
  }
});

// Fetch list of moderators
app.get("/users/moderators", async (req, res) => {
  try {
    const connection = await pool.getConnection();

    // Fetch moderators
    const [rows] = await connection.execute(`
      SELECT userID, username, uFirstName, uLastName, uEmail, uPhoneNo, userGroup, uActivation, uGender, uCountry, uZipCode, uTitle
      FROM Users
      WHERE userGroup = 'Moderator'
    `);

    connection.release();

    res.status(200).json(rows);
  } catch (err) {
    console.error("Error fetching moderators:", err);
    res.status(500).json({ message: "Server error", success: false });
  }
});

// Fetch list of operators (Moderators and Administrators)
app.get("/users/operators", async (req, res) => {
  try {
    const connection = await pool.getConnection();

    // Fetch operators (Moderators and Administrators)
    const [rows] = await connection.execute(`
      SELECT userID, username, uFirstName, uLastName, uEmail, uPhoneNo, userGroup, uActivation, uGender, uCountry, uZipCode, uTitle
      FROM Users
      WHERE userGroup IN ('Moderator', 'Administrator')
    `);

    connection.release();

    res.status(200).json(rows);
  } catch (err) {
    console.error("Error fetching operators:", err);
    res.status(500).json({ message: "Server error", success: false });
  }
});

// Fetch list of administrators
app.get("/users/administrators", async (req, res) => {
  try {
    const connection = await pool.getConnection();

    // Fetch administrators
    const [rows] = await connection.execute(`
      SELECT userID, username, uFirstName, uLastName, uEmail, uPhoneNo, userGroup, uActivation, uGender, uCountry, uZipCode
      FROM Users
      WHERE userGroup = 'Administrator'
    `);

    connection.release();

    res.status(200).json(rows);
  } catch (err) {
    console.error("Error fetching administrators:", err);
    res.status(500).json({ message: "Server error", success: false });
  }
});

// Create moderators
app.post("/users/createModerator", async (req, res) => {
  const {
    firstName,
    lastName,
    username,
    password,
    email,
    phoneNo,
    country,
    zipCode,
  } = req.body;

  try {
    const connection = await pool.getConnection();

    // Check if the username or email already exists
    const [existingUser] = await connection.execute(
      `SELECT username, uEmail FROM Users WHERE username = ? OR uEmail = ?`,
      [username, email]
    );

    if (existingUser.length > 0) {
      connection.release();
      return res
        .status(409)
        .json({ message: "Username or email already exists", success: false });
    }

    // Insert new user into the database
    await connection.execute(
      `INSERT INTO Users (uFirstName, uLastName, username, password, uEmail, uPhoneNo, uCountry, uZipCode, uTitle, userGroup, uStatus, uActivation)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        firstName,
        lastName,
        username,
        password,
        email,
        phoneNo,
        country,
        zipCode,
        "Mr.",
        "Moderator",
        "registered",
        "Active",
      ]
    );

    connection.release();

    res
      .status(201)
      .json({ message: "User registered successfully", success: true });
  } catch (err) {
    console.error("Error during registration:", err);
    res.status(500).json({ message: "Server error", success: false });
  }
});

// Update users by user ID
app.put("/users/updateUser/:userID", async (req, res) => {
  const { userID } = req.params;
  const { firstName, lastName, username, email, phoneNo, country, zipCode } =
    req.body;

  try {
    const connection = await pool.getConnection();

    // Update user details
    const [result] = await connection.execute(
      `UPDATE Users 
       SET uFirstName = ?, 
           uLastName = ?, 
           username = ?, 
           uEmail = ?, 
           uPhoneNo = ?, 
           uCountry = ?, 
           uZipCode = ? 
       WHERE userID = ?`,
      [firstName, lastName, username, email, phoneNo, country, zipCode, userID]
    );

    connection.release();

    if (result.affectedRows > 0) {
      res
        .status(200)
        .json({ message: "User updated successfully", success: true });
    } else {
      res.status(404).json({ message: "User not found", success: false });
    }
  } catch (err) {
    console.error("Error updating user:", err);
    res
      .status(500)
      .json({ error: "Internal Server Error", details: err.message });
  }
});

// Remove users by user ID
app.delete("/users/removeUser/:userID", async (req, res) => {
  const { userID } = req.params;

  try {
    const connection = await pool.getConnection();

    // Check if the user exists
    const [userCheck] = await connection.execute(
      "SELECT userID FROM Users WHERE userID = ?",
      [userID]
    );

    if (userCheck.length === 0) {
      connection.release();
      return res
        .status(404)
        .json({ message: "User not found", success: false });
    }

    // Delete the user
    const [result] = await connection.execute(
      "DELETE FROM Users WHERE userID = ?",
      [userID]
    );

    connection.release();

    if (result.affectedRows > 0) {
      res
        .status(200)
        .json({ message: "User removed successfully", success: true });
    } else {
      res
        .status(400)
        .json({ message: "Failed to remove user", success: false });
    }
  } catch (error) {
    console.error("Error deleting user:", error);
    res.status(500).json({ message: "Server error", success: false });
  }
});

// Suspend users by user ID
app.put("/users/suspendUser/:userID", async (req, res) => {
  try {
    const { userID } = req.params;

    const connection = await pool.getConnection();

    // Update user activation status
    const [result] = await connection.execute(
      "UPDATE Users SET uActivation = 'Inactive' WHERE userID = ?",
      [userID]
    );

    connection.release();

    if (result.affectedRows > 0) {
      res
        .status(200)
        .json({ message: "User suspended successfully", success: true });
    } else {
      res.status(404).json({ message: "User not found", success: false });
    }
  } catch (err) {
    console.error("Error suspending user:", err);
    res.status(500).json({ message: "Server error", success: false });
  }
});

// Activate users by user ID
app.put("/users/activateUser/:userID", async (req, res) => {
  try {
    const { userID } = req.params;

    const connection = await pool.getConnection();

    // Update user activation status
    const [result] = await connection.execute(
      "UPDATE Users SET uActivation = 'Active' WHERE userID = ?",
      [userID]
    );

    connection.release();

    if (result.affectedRows > 0) {
      res
        .status(200)
        .json({ message: "User activated successfully", success: true });
    } else {
      res.status(404).json({ message: "User not found", success: false });
    }
  } catch (err) {
    console.error("Error activating user:", err);
    res.status(500).json({ message: "Server error", success: false });
  }
});

// Properties Listing
app.post(
  "/propertiesListing",
  upload.array("propertyImage", 10),
  async (req, res) => {
    const {
      username,
      propertyPrice,
      propertyAddress,
      clusterName,
      categoryName,
      propertyBedType,
      propertyGuestPaxNo,
      propertyDescription,
      nearbyLocation,
      facilities,
    } = req.body;

    if (!req.files || req.files.length === 0) {
      return res
        .status(400)
        .json({ error: "Please upload at least 5 property images." });
    }

    let connection;
    try {
      connection = await pool.getConnection();

      // Fetch user ID and userGroup for property owner
      const [userResult] = await connection.execute(
        "SELECT userID, userGroup FROM Users WHERE username = ?",
        [username]
      );

      if (userResult.length === 0) {
        return res.status(404).json({ error: "User not found" });
      }

      const { userID, userGroup } = userResult[0];

      // Determine propertyStatus based on userGroup
      const propertyStatus =
        userGroup === "Administrator" ? "Available" : "Pending";

      // Convert images to base64 and concatenate them
      const base64Images = req.files.map((file) =>
        file.buffer.toString("base64")
      );
      const concatenatedImages = base64Images.join(",");

      // Insert into Rate table
      const [rateResult] = await connection.execute(
        "INSERT INTO Rate (rateAmount, rateType, period) VALUES (?, ?, ?)",
        [propertyPrice, "DefaultType", "DefaultPeriod"]
      );
      const rateID = rateResult.insertId;

      // Insert into Categories table
      const [categoryResult] = await connection.execute(
        "INSERT INTO Categories (categoryName, availableStates) VALUES (?, ?)",
        [categoryName, "DefaultStates"]
      );
      const categoryID = categoryResult.insertId;

      // Insert into Clusters table
      const [clusterResult] = await connection.execute(
        "INSERT INTO Clusters (clusterName, clusterState, clusterProvince) VALUES (?, ?, ?)",
        [clusterName, "DefaultState", "DefaultProvince"]
      );
      const clusterID = clusterResult.insertId;

      // Insert new property into Properties table
      const [propertyListingResult] = await connection.execute(
        `INSERT INTO Properties (
          propertyNo, userID, clusterID, categoryID, rateID,
          propertyDescription, propertyAddress,
          propertyBedType, propertyBedImage, propertyGuestPaxNo, propertyImage,
          propertyStatus, nearbyLocation, facilities, policies
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          "1",
          userID,
          clusterID,
          categoryID,
          rateID,
          propertyDescription,
          propertyAddress,
          propertyBedType,
          "1",
          propertyGuestPaxNo,
          concatenatedImages,
          propertyStatus,
          nearbyLocation,
          facilities,
          "policies",
        ]
      );

      const propertyID = propertyListingResult.insertId;

      res
        .status(201)
        .json({ message: "Property created successfully", propertyID });
    } catch (err) {
      console.error("Error inserting property: ", err);
      res
        .status(500)
        .json({ error: "Internal Server Error", details: err.message });
    } finally {
      if (connection) connection.release();
    }
  }
);

// Fetch list of all property listings (Product)
app.get("/product", async (req, res) => {
  let connection;
  try {
    connection = await pool.getConnection();

    const [result] = await connection.execute(`
      SELECT p.*, u.username, u.uImage, r.rateAmount, c.categoryName 
      FROM Properties p
      JOIN Rate r ON p.rateID = r.rateID
      JOIN Categories c ON p.categoryID = c.categoryID
      JOIN Users u ON p.userID = u.userID
      WHERE p.propertyStatus = 'Available'
    `);

    const properties = result.map((property) => ({
      ...property,
      propertyImage: property.propertyImage
        ? property.propertyImage.split(",")
        : [],
    }));

    res.status(200).json(properties);
  } catch (err) {
    console.error("Error fetching properties: ", err);
    res
      .status(500)
      .json({ error: "Internal Server Error", details: err.message });
  } finally {
    if (connection) connection.release();
  }
});

// Fetch list of all property listings (Dashboard)
app.get("/propertiesListingTable", async (req, res) => {
  const username = req.query.username;

  if (!username) {
    return res.status(400).json({ error: "Username is required" });
  }

  let connection;
  try {
    connection = await pool.getConnection();

    // Fetch user ID and userGroup based on username
    const [userResult] = await connection.execute(
      `SELECT userID, userGroup FROM Users WHERE username = ?`,
      [username]
    );

    if (userResult.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    const { userID, userGroup } = userResult[0];

    let query = `
      SELECT 
        p.propertyID, 
        p.propertyAddress, 
        p.nearbyLocation,
        p.propertyBedType, 
        p.propertyGuestPaxNo, 
        p.propertyDescription, 
        p.propertyStatus, 
        p.propertyImage,
        u.uFirstName, 
        u.uLastName,
        u.username,
        r.rateAmount,
        cl.clusterName,
        c.categoryName
      FROM Properties p
      JOIN Users u ON p.userID = u.userID
      JOIN Rate r ON p.rateID = r.rateID
      JOIN Clusters cl ON p.clusterID = cl.clusterID
      JOIN Categories c ON p.categoryID = c.categoryID
    `;

    if (userGroup === "Moderator") {
      // If user is a Moderator, fetch only their properties
      query += ` WHERE p.userID = ?`;
    }

    const [result] = await connection.execute(
      query,
      userGroup === "Moderator" ? [userID] : []
    );

    const properties = result.map((property) => ({
      ...property,
      propertyImage: property.propertyImage
        ? property.propertyImage.split(",")
        : [],
    }));

    res.status(200).json({ properties });
  } catch (err) {
    console.error("Error fetching properties: ", err);
    res
      .status(500)
      .json({ error: "Internal Server Error", details: err.message });
  } finally {
    if (connection) connection.release();
  }
});

// Update an existing property listing by property ID
app.put(
  "/propertiesListing/:propertyID",
  upload.array("propertyImage", 10),
  async (req, res) => {
    const { propertyID } = req.params;
    const {
      propertyAddress,
      propertyPrice,
      propertyDescription,
      nearbyLocation,
      propertyBedType,
      propertyGuestPaxNo,
      clusterName,
      categoryName,
    } = req.body;

    const removedImages = req.body.removedImages
      ? JSON.parse(req.body.removedImages)
      : [];

    let connection;
    try {
      connection = await pool.getConnection();

      // Fetch the current property details
      const [propertyResult] = await connection.execute(
        "SELECT propertyStatus, propertyImage, rateID, clusterID, categoryID FROM Properties WHERE propertyID = ?",
        [propertyID]
      );

      if (propertyResult.length === 0) {
        return res.status(404).json({ error: "Property not found" });
      }

      const { propertyImage, rateID, clusterID, categoryID } =
        propertyResult[0];

      let existingImages = propertyImage ? propertyImage.split(",") : [];

      // Remove deleted images
      existingImages = existingImages.filter(
        (image) => !removedImages.includes(image)
      );

      // Add new uploaded images if any
      if (req.files && req.files.length > 0) {
        const newBase64Images = req.files.map((file) =>
          file.buffer.toString("base64")
        );
        existingImages = [...existingImages, ...newBase64Images];
      }

      const concatenatedImages = existingImages.join(",");

      // Update property details
      await connection.execute(
        `UPDATE Properties 
         SET propertyDescription = ?, 
             propertyAddress = ?, 
             nearbyLocation = ?, 
             propertyBedType = ?, 
             propertyGuestPaxNo = ?, 
             propertyImage = ?
         WHERE propertyID = ?`,
        [
          propertyDescription,
          propertyAddress,
          nearbyLocation,
          propertyBedType,
          propertyGuestPaxNo,
          concatenatedImages,
          propertyID,
        ]
      );

      // Update Rate table
      await connection.execute(
        `UPDATE Rate 
         SET rateAmount = ? 
         WHERE rateID = ?`,
        [propertyPrice, rateID]
      );

      // Update Clusters table
      await connection.execute(
        `UPDATE Clusters
         SET clusterName = ?
         WHERE clusterID = ?`,
        [clusterName, clusterID]
      );

      // Update Categories table
      await connection.execute(
        `UPDATE Categories 
         SET categoryName = ? 
         WHERE categoryID = ?`,
        [categoryName, categoryID]
      );

      res.status(200).json({ message: "Property updated successfully" });
    } catch (err) {
      console.error("Error updating property:", err);
      res
        .status(500)
        .json({ error: "Internal Server Error", details: err.message });
    } finally {
      if (connection) connection.release();
    }
  }
);

// Update property status
app.patch("/updatePropertyStatus/:propertyID", async (req, res) => {
  const { propertyID } = req.params;
  const { propertyStatus } = req.body;

  let connection;
  try {
    connection = await pool.getConnection();

    await connection.execute(
      `UPDATE Properties SET propertyStatus = ? WHERE propertyID = ?`,
      [propertyStatus, propertyID]
    );

    res.status(200).json({ message: "Property status updated successfully" });
  } catch (error) {
    console.error("Error updating property status:", error);
    res.status(500).json({ message: "Internal Server Error" });
  } finally {
    if (connection) connection.release();
  }
});

// Delete a property by propertyID
app.delete("/propertiesListing/:propertyID", async (req, res) => {
  const { propertyID } = req.params;

  let connection;
  try {
    connection = await pool.getConnection();

    // Check if the property exists
    const [propertyCheck] = await connection.execute(
      "SELECT propertyID FROM Properties WHERE propertyID = ?",
      [propertyID]
    );

    if (propertyCheck.length === 0) {
      return res
        .status(404)
        .json({ message: "Property not found", success: false });
    }

    // Delete the property
    await connection.execute("DELETE FROM Properties WHERE propertyID = ?", [
      propertyID,
    ]);

    res
      .status(200)
      .json({ message: "Property deleted successfully", success: true });
  } catch (err) {
    console.error("Error deleting property:", err);
    res.status(500).json({
      message: "Internal Server Error",
      details: err.message,
      success: false,
    });
  } finally {
    if (connection) connection.release(); // Release MySQL connection
  }
});

// Check user status by userID
app.get("/checkStatus", async (req, res) => {
  const { userID } = req.query;

  let connection;
  try {
    connection = await pool.getConnection();

    const [result] = await connection.execute(
      "SELECT uStatus FROM Users WHERE userID = ?",
      [userID]
    );

    if (result.length > 0) {
      res.status(200).json({ uStatus: result[0].uStatus });
    } else {
      res.status(404).json({ message: "User not found" });
    }
  } catch (err) {
    console.error("Error fetching user status:", err);
    res.status(500).json({ message: "Server error" });
  } finally {
    if (connection) connection.release(); // Ensure connection is released
  }
});

// Send contact us email
app.post("/contact_us", async (req, res) => {
  const { name, email, message } = req.body;

  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
  });

  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: process.env.EMAIL_USER,
    subject: `Message from ${name}`,
    html: `
      <h1>New Message from ${name}</h1>
      <p><strong>Message:</strong></p>
      <p>${message}</p>
      <p><strong>Email:</strong> ${email}</p>
    `,
    replyTo: email,
  };

  try {
    await transporter.sendMail(mailOptions);
    res.status(200).json({ message: "Email sent successfully" });
  } catch (error) {
    console.error("Error sending email:", error.response);
    res
      .status(500)
      .json({ message: "Failed to send email", error: error.response });
  }
});

// Send Booking Request Message To Administrator Or Moderator
app.post("/requestBooking/:reservationID", async (req, res) => {
  const { reservationID } = req.params;

  try {
    const [rows] = await pool.execute(
      `SELECT rc.rcLastName, rc.rcTitle, r.checkInDateTime, r.checkOutDateTime, r.request, 
              r.totalPrice, p.propertyAddress, u.uEmail 
       FROM Reservation_Customer_Details rc 
       JOIN Reservation r ON rc.rcID = r.rcID 
       JOIN Properties p ON r.propertyID = p.propertyID 
       JOIN Users u ON u.userID = p.userID 
       WHERE r.reservationID = ?`,
      [reservationID]
    );

    if (rows.length === 0) {
      return res
        .status(404)
        .json({ message: "Reservation or user not found for this property" });
    }

    const {
      rcLastName: customerLastName,
      rcTitle: customerTitle,
      checkInDateTime: reservationCheckInDateTime,
      checkOutDateTime: reservationCheckOutDateTime,
      request: reservationRequest = "-",
      totalPrice: reservationTotalPrice,
      propertyAddress: reservationProperty,
      uEmail: userEmail,
    } = rows[0];

    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: userEmail,
      subject: "Booking Request",
      html: `
      <h1><b>Do You Accept This Booking By ${customerTitle} ${customerLastName}?</b></h1><hr/>
      <p><b>Check In Date:</b> ${reservationCheckInDateTime}</p>
      <p><b>Check Out Date:</b> ${reservationCheckOutDateTime}</p>
      <p><b>Request:</b> ${reservationRequest}</p>
      <p><b>Property Name:</b> ${reservationProperty}</p>
      <p><b>Total Price: <i>RM${reservationTotalPrice}</i></b></p><br/>
      <p><b>Please kindly click the button below to make the decision in <b>12 hours</b> time frame.</b></p>
      <div style="margin: 10px 0;">
        <a href="" style="background-color: green; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; margin-right: 10px;">Accept</a>
        <a href="" style="background-color: red; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Reject</a>
      </div>
      `,
    };

    await transporter.sendMail(mailOptions);
    res.status(200).json({ message: "Email Sent Successfully" });
  } catch (err) {
    console.error("Error sending email: ", err);
    res
      .status(500)
      .json({ message: "Failed to send email", error: err.message });
  }
});

// Send Booking Request Accepted Message To Customer
app.post("/accept_booking/:reservationID", async (req, res) => {
  const { reservationID } = req.params;

  try {
    const [rows] = await pool.execute(
      `SELECT rc.rcLastName, rc.rcEmail, rc.rcTitle, r.checkInDateTime, 
              r.checkOutDateTime, r.reservationBlockTime, p.propertyAddress 
       FROM Reservation_Customer_Details rc 
       JOIN Reservation r ON rc.rcID = r.rcID 
       JOIN Properties p ON r.propertyID = p.propertyID 
       WHERE r.reservationID = ?`,
      [reservationID]
    );

    if (rows.length === 0) {
      return res.status(404).json({
        message:
          "Reservation customer or property not found for this reservation",
      });
    }

    const {
      rcLastName: customerLastName,
      rcEmail: customerEmail,
      rcTitle: customerTitle,
      checkInDateTime: reservationCheckInDate,
      checkOutDateTime: reservationCheckOutDate,
      reservationBlockTime: paymentDueDate,
      propertyAddress: reservationProperty,
    } = rows[0];

    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: customerEmail,
      subject: "Booking Accepted",
      html: `
      <h1><b>Dear ${customerTitle} ${customerLastName},</b></h1><hr/>
      <p>Your booking for <b>${reservationProperty}</b> from <b>${reservationCheckInDate}</b> to <b>${reservationCheckOutDate}</b> has been <span style="color: green">accepted</span>.</p> 
      <p>Please kindly click the button below to make payment before <b>${paymentDueDate}</b> to secure your booking.</p>  
      <a href="" style="background-color: blue; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; margin-right: 10px;">Pay</a>
      `,
    };

    await transporter.sendMail(mailOptions);
    res.status(200).json({ message: "Email Sent Successfully" });
  } catch (err) {
    console.error("Error sending email: ", err);
    res
      .status(500)
      .json({ message: "Failed to send email", error: err.message });
  }
});

// Send New Room Suggestion To Customer
app.post("/suggestNewRoom/:propertyID/:reservationID", async (req, res) => {
  const { propertyID, reservationID } = req.params;

  try {
    const [propertyRows] = await pool.execute(
      `SELECT propertyAddress, propertyPrice, propertyLocation, 
              propertyBedType, propertyGuestPaxNo 
       FROM Properties WHERE propertyID = ?`,
      [propertyID]
    );

    if (propertyRows.length === 0) {
      return res
        .status(404)
        .json({ message: "Property not found for suggestion" });
    }

    const {
      propertyAddress: suggestpropertyAddress,
      propertyPrice: suggestPropertyPrice,
      propertyLocation: suggestPropertyLocation,
      propertyBedType: suggestPropertyBedType,
      propertyGuestPaxNo: suggestPropertyGuestPaxNo,
    } = propertyRows[0];

    const [customerReservationRows] = await pool.execute(
      `SELECT rc.rcLastName, rc.rcEmail, rc.rcTitle, 
              p.propertyAddress, r.checkInDateTime, r.checkOutDateTime 
       FROM Reservation r 
       JOIN Properties p ON p.propertyID = r.propertyID 
       JOIN Reservation_Customer_Details rc ON rc.rcID = r.rcID 
       WHERE r.reservationID = ?`,
      [reservationID]
    );

    if (customerReservationRows.length === 0) {
      return res
        .status(404)
        .json({ message: "User email not found for suggestion" });
    }

    const {
      rcLastName: customerLastName,
      rcEmail: customerEmail,
      rcTitle: customerTitle,
      propertyAddress: reservationProperty,
      checkInDateTime: reservationCheckInDate,
      checkOutDateTime: reservationCheckOutDate,
    } = customerReservationRows[0];

    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: customerEmail,
      subject: "Booking Request Rejected & New Room Suggestion",
      html: `
      <h1><b>Dear ${customerTitle} ${customerLastName},</b></h1><hr/>
      <p>Your booking for <b>${reservationProperty}</b> from <b>${reservationCheckInDate}</b> to <b>${reservationCheckOutDate}</b> has been <span style="color: red">rejected</span> due to room unavailable during the time selected.</p> 
      <p>A similar room with the details below is suggested for consideration:</p> 
      <h3>Property Name: ${suggestpropertyAddress}</h3>
      <p><b>Property Location:</b> ${suggestPropertyLocation}</p>
      <p><b>Bed Type:</b> ${suggestPropertyBedType}</p>
      <p><b>Pax Number:</b> ${suggestPropertyGuestPaxNo}</p>
      <p><b>Price: <i>RM${suggestPropertyPrice}</i></b></p><br/>
      <p>Please kindly make your decision by clicking the buttons below</p>
      <div style="margin: 10px 0;">
        <a href="" style="background-color: blue; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; margin-right: 10px;">Pay</a>
        <a href="" style="background-color: red; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Reject</a>
      </div>
      `,
    };

    await transporter.sendMail(mailOptions);
    res.status(200).json({ message: "Email Sent Successfully" });
  } catch (err) {
    console.error("Error sending email: ", err);
    res
      .status(500)
      .json({ message: "Failed to send email", error: err.message });
  }
});

// Send Properties Listing Request Notification From Moderator
app.post("/propertyListingRequest/:propertyID", async (req, res) => {
  const { propertyID } = req.params;

  try {
    const moderatorResult = await pool
      .request()
      .input("propertyID", sql.Int, propertyID)
      .query(
        `SELECT p.propertyAddress, u.uLastName, u.uTitle, u.userGroup, u.userID
         FROM Property p
         JOIN Users u ON u.userID = p.userID
         WHERE p.propertyID = @propertyID`
      );

    if (moderatorResult.recordset.length === 0) {
      return res.status(404).json({
        message:
          "Property or moderator not found for this property listing request",
      });
    }

    const { propertyAddress, uLastName, uTitle, userGroup } =
      moderatorResult.recordset[0];

    // If the user is not a Moderator, approve automatically
    if (userGroup !== "Moderator") {
      return res.status(200).json({ message: "Property Created Successfully" });
    }

    const administratorResult = await pool
      .request()
      .query(`SELECT uEmail FROM Users WHERE userGroup = 'Administrator'`);

    if (administratorResult.recordset.length === 0) {
      return res.status(404).json({ message: "Administrators not found" });
    }

    const adminEmails = administratorResult.recordset.map(
      (record) => record.uEmail
    );

    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: adminEmails,
      subject: "Property Listing Request",
      html: `
      <h1><b>Dear Administrators,</b></h1><hr/>
      <p>Moderator ${uTitle} ${uLastName} has requested listing a new property: <b>${propertyAddress}</b> on the "Hello Sarawak" app.</p>
      <p>Please review the request and make a decision within <b>12 hours</b>.</p>
      <div style="margin: 10px 0;">
        <a href="" style="background-color: green; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; margin-right: 10px;">Accept</a>
        <a href="" style="background-color: red; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Reject</a>
      </div>
      `,
    };

    await transporter.sendMail(mailOptions);
    res.status(200).json({ message: "Email Sent Successfully" });
  } catch (err) {
    console.error("Error sending email: ", err);
    res
      .status(500)
      .json({ message: "Failed to send email", error: err.message });
  }
});

// Send Properties Listing Request Accepted Notification To Moderator
app.post("/propertyListingAccept/:propertyID", async (req, res) => {
  const { propertyID } = req.params;

  try {
    const result = await pool
      .request()
      .input("propertyID", sql.Int, propertyID)
      .query(
        `SELECT p.propertyAddress, u.uLastName, u.uEmail, u.uTitle 
         FROM Property p 
         JOIN Users u ON u.userID = p.userID 
         WHERE p.propertyID = @propertyID`
      );

    if (result.recordset.length === 0) {
      return res.status(404).json({
        message: "Property or user not found for this property listing request",
      });
    }

    const {
      propertyAddress: property,
      uLastName: moderatorLastName,
      uEmail: moderatorEmail,
      uTitle: moderatorTitle,
    } = result.recordset[0];

    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: moderatorEmail,
      subject: "Property Listing Request Accepted",
      html: `
      <h1><b>Dear ${moderatorTitle} ${moderatorLastName},</b></h1><hr/>
      <p>Your request for property listing of <b>${property}</b> has been <span style="color: green">accepted</span> by the Administrator.</p>
      <p>Please click the button below to view the details of the listed property.</p>
      <a href="" style="background-color: brown; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">View Property</a>
      `,
    };

    await transporter.sendMail(mailOptions);
    res.status(200).json({ message: "Email Sent Successfully" });
  } catch (err) {
    console.error("Error sending email: ", err);
    res
      .status(500)
      .json({ message: "Failed to send email", error: err.message });
  }
});

// Send Properties Listing Request Rejected Notification To Moderator
app.post("/propertyListingReject/:propertyID", async (req, res) => {
  const { propertyID } = req.params;

  try {
    const result = await pool
      .request()
      .input("propertyID", sql.Int, propertyID)
      .query(
        `SELECT p.propertyAddress, u.uLastName, u.uEmail, u.uTitle 
         FROM Property p 
         JOIN Users u ON u.userID = p.userID 
         WHERE p.propertyID = @propertyID`
      );

    if (result.recordset.length === 0) {
      return res.status(404).json({
        message: "Property or user not found for this property listing request",
      });
    }

    const {
      propertyAddress: property,
      uLastName: moderatorLastName,
      uEmail: moderatorEmail,
      uTitle: moderatorTitle,
    } = result.recordset[0];

    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: moderatorEmail,
      subject: "Property Listing Request Rejected",
      html: `
      <h1><b>Dear ${moderatorTitle} ${moderatorLastName},</b></h1><hr/>
      <p>Your request for listing <b>${property}</b> has been <span style="color: red">rejected</span> by the Administrator due to a policy violation.</p>
      <p>Please click the button below to re-list the property with appropriate information within <b>12 hours</b>.</p>
      <a href="" style="background-color: brown; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Re-List Property</a>
      `,
    };

    await transporter.sendMail(mailOptions);
    res.status(200).json({ message: "Email Sent Successfully" });
  } catch (err) {
    console.error("Error sending email: ", err);
    res
      .status(500)
      .json({ message: "Failed to send email", error: err.message });
  }
});

// Send "Suggest" Notification To Operators
app.post("/sendSuggestNotification/:reservationID", async (req, res) => {
  const { userIDs } = req.body;
  const { reservationID } = req.params;

  if (!userIDs || !Array.isArray(userIDs) || userIDs.length === 0) {
    return res.status(400).json({ message: "Invalid userIDs provided" });
  }

  try {
    // Secure query with parameterized values
    const placeholders = userIDs.map(() => "?").join(", "); // Convert to "?, ?, ?"

    const [userResults] = await pool.execute(
      `SELECT uEmail FROM Users WHERE userID IN (${placeholders})`,
      userIDs
    );

    if (userResults.length === 0) {
      return res.status(404).json({ message: "No users found" });
    }

    const selectedEmails = userResults.map((record) => record.uEmail);

    const [reservationResults] = await pool.execute(
      `SELECT p.propertyAddress, r.checkInDateTime, r.checkOutDateTime, 
              rc.rcLastName, rc.rcTitle 
       FROM Properties p 
       JOIN Reservation r ON p.propertyID = r.propertyID 
       JOIN Reservation_Customer_Details rc ON rc.rcID = r.rcID 
       WHERE r.reservationID = ?`,
      [reservationID]
    );

    if (reservationResults.length === 0) {
      return res
        .status(404)
        .json({ message: "No reservation or customer found" });
    }

    const {
      propertyAddress: reservationProperty,
      checkInDateTime,
      checkOutDateTime,
      rcLastName: customerLastName,
      rcTitle: customerTitle,
    } = reservationResults[0];

    // Format dates for better readability
    const formatDate = (date) =>
      new Date(date).toLocaleString("en-US", { timeZone: "Asia/Kuala_Lumpur" });

    const formattedCheckInDate = formatDate(checkInDateTime);
    const formattedCheckOutDate = formatDate(checkOutDateTime);

    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: selectedEmails,
      subject: "Suggestion Available",
      html: `
      <h1><b>Dear Operators,</b></h1><hr/>
      <p>Reservation for <b>${customerTitle} ${customerLastName}</b> is now open for suggestions with the following details:</p>
      <p><b>Property Name:</b> ${reservationProperty}</p>
      <p><b>Check In Date:</b> ${formattedCheckInDate}</p>
      <p><b>Check Out Date:</b> ${formattedCheckOutDate}</p>
      <br/>
      <p>Please click the button below to pick up this suggestion opportunity. This is a first-come, first-served basis.</p>
      <p>If you are <b>not interested</b>, you may simply <b>ignore this email</b>.</p>
      <a href="" style="background-color: blue; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Pick Up</a>
      `,
    };

    await transporter.sendMail(mailOptions);
    res.status(200).json({ message: "Email Sent Successfully" });
  } catch (err) {
    console.error("Error sending email: ", err);
    res
      .status(500)
      .json({ message: "Failed to send email", error: err.message });
  }
});

//Create reservation for property
app.post("/reservation/:userID", async (req, res) => {
  const {
    propertyID,
    checkInDateTime,
    checkOutDateTime,
    request,
    totalPrice,
    adults,
    children,
    rcFirstName,
    rcLastName,
    rcEmail,
    rcPhoneNo,
    rcTitle,
  } = req.body;
  const userID = req.params.userID;

  if (
    !userID ||
    !propertyID ||
    !checkInDateTime ||
    !checkOutDateTime ||
    !rcFirstName ||
    !rcEmail
  ) {
    return res.status(400).json({ error: "Missing required fields" });
  }

  const connection = await pool.getConnection(); // MySQL uses pool.getConnection()

  try {
    await connection.beginTransaction();

    // Insert customer details
    const [customerResult] = await connection.query(
      `INSERT INTO Reservation_Customer_Details 
      (rcFirstName, rcLastName, rcEmail, rcPhoneNo, rcTitle) 
      VALUES (?, ?, ?, ?, ?)`,
      [rcFirstName, rcLastName, rcEmail, rcPhoneNo, rcTitle]
    );

    const rcID = customerResult.insertId; // MySQL uses insertId instead of OUTPUT

    // Corrected reservationBlockTime (Adding 3 days)
    const reservationDateTime = new Date();
    const reservationBlockTime = new Date(
      reservationDateTime.getTime() + 3 * 24 * 60 * 60 * 1000
    );

    // Insert reservation details
    const [reservationResult] = await connection.query(
      `INSERT INTO Reservation 
      (propertyID, checkInDateTime, checkOutDateTime, reservationBlockTime, request, totalPrice, rcID, reservationStatus, userID) 
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        propertyID,
        checkInDateTime,
        checkOutDateTime,
        reservationBlockTime,
        request || null,
        totalPrice,
        rcID,
        "Pending",
        userID,
      ]
    );

    const reservationID = reservationResult.insertId; // MySQL equivalent of OUTPUT

    // Log booking in Audit_Trail
    await connection.query(
      `INSERT INTO Audit_Trail 
      (timestamp, action, userID, entityID, actionType, entityType) 
      VALUES (?, ?, ?, ?, ?, ?)`,
      [
        new Date(),
        `Reservation ${reservationID} created for property ${propertyID}`,
        userID,
        reservationID,
        "Create",
        "Reservation",
      ]
    );

    await connection.commit(); // Commit transaction

    res.status(201).json({
      message: "Reservation and Audit Log created successfully",
      reservationID,
    });
  } catch (err) {
    await connection.rollback(); // Rollback transaction on error
    console.error("Error inserting reservation data:", err);
    res
      .status(500)
      .json({ message: "Internal Server Error", details: err.message });
  } finally {
    connection.release(); // Release MySQL connection
  }
});

// Fetch Book and Pay Log
app.get("/users/booklog", async (req, res) => {
  try {
    const [result] = await pool.execute(`
      SELECT 
        userID, 
        timestamp, 
        action
      FROM Audit_Trail
      WHERE action LIKE '%PropertyID%'
      ORDER BY timestamp DESC
    `);

    // Extract propertyID using regex in JavaScript
    const logs = result.map((log) => {
      const match = log.action.match(/PropertyID\s+(\d+)/);
      return {
        userID: log.userID,
        timestamp: new Date(log.timestamp).toISOString(), // Ensure proper date format
        action: log.action,
        propertyID: match ? parseInt(match[1], 10) : null, // Extract propertyID safely
      };
    });

    res.json(logs);
  } catch (err) {
    console.error("Error fetching Book Log:", err);
    res
      .status(500)
      .json({ message: "Internal Server Error", details: err.message });
  }
});

// Fetch reservations for the logged-in user
app.get("/cart", async (req, res) => {
  const userID = req.query.userID;

  if (!userID || isNaN(userID)) {
    return res.status(400).json({ error: "Invalid or missing userID" });
  }

  try {
    // Fetch reservations by userID from MySQL
    const [reservations] = await pool.query(
      `SELECT 
        r.reservationID,
        r.propertyID,
        p.propertyAddress, 
        p.propertyImage,
        r.checkInDateTime,
        r.checkOutDateTime,
        r.reservationBlockTime,
        r.request,
        r.totalPrice,
        r.reservationStatus,
        r.rcID,
        r.userID
      FROM Reservation r
      JOIN Properties p ON r.propertyID = p.propertyID
      WHERE r.userID = ?`,
      [userID]
    );

    // Process results to format property images as an array
    const formattedReservations = reservations.map((reservation) => ({
      ...reservation,
      propertyImage: reservation.propertyImage
        ? reservation.propertyImage.split(",")
        : [],
    }));

    res.status(200).json({ userID, reservations: formattedReservations });
  } catch (err) {
    console.error("Error fetching reservations by userID:", err);
    res
      .status(500)
      .json({ error: "Internal Server Error", details: err.message });
  }
});

// Fetch all reservations (Dashboard)
app.get("/reservationTable", async (req, res) => {
  const username = req.query.username;

  if (!username) {
    return res.status(400).json({ error: "Username is required" });
  }

  try {
    // Fetch userID and userGroup from the Users table
    const [userResult] = await pool.query(
      `SELECT userID, userGroup FROM Users WHERE username = ?`,
      [username]
    );

    if (userResult.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    const userID = userResult[0].userID;
    const userGroup = userResult[0].userGroup;

    // Base query for fetching reservations
    let query = `
      SELECT 
        r.reservationID,
        r.propertyID,
        p.propertyAddress, 
        p.propertyImage,
        p.userID,
        r.checkInDateTime,
        r.checkOutDateTime,
        r.reservationBlockTime,
        r.request,
        r.totalPrice,
        r.reservationStatus,
        r.rcID,
        rc.rcFirstName,
        rc.rcLastName,
        rc.rcEmail,
        rc.rcPhoneNo,
        rc.rcTitle
      FROM Reservation r
      JOIN Properties p ON r.propertyID = p.propertyID
      JOIN Reservation_Customer_Details rc ON r.rcID = rc.rcID
    `;

    let queryParams = [];

    // Apply filter for Moderators
    if (userGroup === "Moderator") {
      query += ` WHERE p.userID = ? AND r.reservationStatus IN ('Pending', 'Accepted', 'Rejected', 'Canceled', 'Paid')`;
      queryParams.push(userID);
    } else {
      query += ` WHERE r.reservationStatus IN ('Pending', 'Accepted', 'Rejected', 'Canceled', 'Paid')`;
    }

    // Execute the query
    const [reservations] = await pool.query(query, queryParams);

    // Process reservations to split propertyImage into an array
    const formattedReservations = reservations.map((reservation) => ({
      ...reservation,
      propertyImage: reservation.propertyImage
        ? reservation.propertyImage.split(",")
        : [], // Convert comma-separated image string into an array
    }));

    res.status(200).json({ reservations: formattedReservations });
  } catch (err) {
    console.error("Error fetching reservation data:", err);
    res
      .status(500)
      .json({ message: "Internal Server Error", details: err.message });
  }
});

// Update reservation status to "Canceled"
app.put("/cancelReservation/:reservationID", async (req, res) => {
  const { reservationID } = req.params;

  try {
    // Execute update query
    const [result] = await pool.query(
      `UPDATE Reservation SET reservationStatus = ? WHERE reservationID = ?`,
      ["Canceled", reservationID]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "Reservation not found" });
    }

    res.status(200).json({ message: "Reservation status updated to Canceled" });
  } catch (err) {
    console.error("Error updating reservation status:", err);
    res
      .status(500)
      .json({ message: "Internal Server Error", details: err.message });
  }
});

// Update reservation status
app.patch("/updateReservationStatus/:reservationID", async (req, res) => {
  const { reservationID } = req.params;
  const { reservationStatus } = req.body;

  if (!reservationStatus) {
    return res.status(400).json({ message: "Reservation status is required" });
  }

  try {
    const [result] = await pool.query(
      `UPDATE Reservation SET reservationStatus = ? WHERE reservationID = ?`,
      [reservationStatus, reservationID]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "Reservation not found" });
    }

    res
      .status(200)
      .json({ message: "Reservation status updated successfully" });
  } catch (error) {
    console.error("Error updating reservation status:", error);
    res.status(500).json({ message: "Internal Server Error" });
  }
});

// Remove reservation
app.delete("/removeReservation/:reservationID", async (req, res) => {
  const { reservationID } = req.params;

  try {
    const [result] = await pool.query(
      `DELETE FROM Reservation WHERE reservationID = ?`,
      [reservationID]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "Reservation not found" });
    }

    res.status(200).json({ message: "Reservation removed successfully" });
  } catch (err) {
    console.error("Error deleting reservation:", err);
    res
      .status(500)
      .json({ message: "Internal Server Error", details: err.message });
  }
});

// Get Properties Of Particular Administrator For "Suggest"
app.get("/operatorProperties/:userID", async (req, res) => {
  const { userID } = req.params;

  if (!userID) {
    return res.status(400).json({ message: "userID of Operator is not found" });
  }

  try {
    const [result] = await pool.query(
      `SELECT * FROM Property WHERE userID = ? AND propertyStatus = 'Available'`,
      [userID]
    );

    if (result.length === 0) {
      return res
        .status(404)
        .json({ message: "No properties found for this Operator" });
    }

    const propertiesWithSeparatedImages = result.map((property) => ({
      ...property,
      images: property.propertyImage ? property.propertyImage.split(",") : [],
    }));

    res.status(200).json({
      status: "success",
      message: "Properties Retrieved Successfully",
      data: propertiesWithSeparatedImages,
    });
  } catch (err) {
    console.error("Error retrieving properties: ", err);
    res.status(500).json({
      message: "An error occurred while retrieving properties",
      error: err.message,
    });
  }
});

// Get user information
app.get("/getUserInfo/:userID", async (req, res) => {
  const { userID } = req.params;

  try {
    const [result] = await pool.query(
      `SELECT 
          uTitle,
          uFirstName,
          uLastName,
          uEmail,
          uPhoneNo
       FROM Users
       WHERE userID = ?`,
      [userID]
    );

    if (result.length === 0) {
      return res.status(404).json({ message: "User information not found" });
    }

    res.json(result[0]);
  } catch (err) {
    console.error("Error getting user information:", err);
    res.status(500).json({ message: "Server error" });
  }
});

//Forget Password
app.post("/forgot-password", async (req, res) => {
  const { email } = req.body;

  try {
    // Check if user exists
    const [userResult] = await pool.query(
      "SELECT userID, username FROM Users WHERE uEmail = ?",
      [email]
    );

    if (userResult.length === 0) {
      return res.status(404).json({ message: "Email not registered" });
    }

    const { userID, username } = userResult[0];

    // Generate a new temporary password
    const newPassword = Math.random().toString(36).slice(-8);
    const hashedPassword = await bcrypt.hash(newPassword, 10); // Hash password before storing

    // Update password in the database
    await pool.query("UPDATE Users SET password = ? WHERE userID = ?", [
      hashedPassword,
      userID,
    ]);

    // Set up email transporter
    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: "laudarren911@gmail.com",
        pass: "tlld oplc qepx hbzy",
      },
    });

    // Email content
    const mailOptions = {
      from: "laudarren911@gmail.com",
      to: email,
      subject: "Hello Sarawak Password Reset",
      html: `
        <h1>Dear ${username}</h1>
        <p>You have requested a new temporary password. You may use this temporary password for your next login.</p>
        <h2 style="color: #4CAF50; font-size: 24px;">${newPassword}</h2>
        <p>Please use this password to log in and immediately change your password.</p>
        <p>If you did not request a password reset, please contact the administrator immediately.</p>
      `,
    };

    await transporter.sendMail(mailOptions);

    res
      .status(200)
      .json({ message: "New password has been sent to your email" });
  } catch (err) {
    console.error("Reset password error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// Avatar
const getDefaultAvatarBase64 = () => {
  return new Promise((resolve, reject) => {
    const defaultAvatarPath = path.join(
      __dirname,
      "../../Frontend/src/public/avatar.png"
    );
    fs.readFile(defaultAvatarPath, (err, data) => {
      if (err) {
        reject(err);
      } else {
        const base64Data = data.toString("base64");
        resolve(base64Data);
      }
    });
  });
};

const generateRandomSixDigits = () =>
  Math.floor(100000 + Math.random() * 900000);

// Get User Details
app.get("/users/:userID", async (req, res) => {
  const { userID } = req.params;

  if (isNaN(userID)) {
    return res.status(400).json({ message: "Invalid userID" });
  }

  try {
    const [rows] = await pool.execute("SELECT * FROM Users WHERE userID = ?", [
      userID,
    ]);

    if (rows.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    res.status(200).json(rows[0]);
  } catch (err) {
    console.error("Error fetching user data:", err);
    return res.status(500).json({ message: "Internal server error" });
  }
});

// Update Profile
app.put("/users/updateProfile/:userID", async (req, res) => {
  const { userID } = req.params;

  const {
    username,
    password,
    uFirstName,
    uLastName,
    uDOB,
    uTitle,
    uGender,
    uEmail,
    uPhoneNo,
    uCountry,
    uZipCode,
  } = req.body;

  try {
    const query = `
      UPDATE Users SET 
        username = ?, 
        password = ?, 
        uFirstName = ?, 
        uLastName = ?, 
        uDOB = ?, 
        uTitle = ?, 
        uGender = ?, 
        uEmail = ?, 
        uPhoneNo = ?, 
        uCountry = ?, 
        uZipCode = ?
      WHERE userID = ?
    `;

    await pool.execute(query, [
      username,
      password,
      uFirstName,
      uLastName,
      uDOB,
      uTitle,
      uGender,
      uEmail,
      uPhoneNo,
      uCountry,
      uZipCode,
      userID,
    ]);

    res
      .status(200)
      .json({ message: "Profile updated successfully.", success: true });
  } catch (err) {
    console.error("Error updating owner profile:", err);
    res.status(500).json({
      message: "An error occurred while updating the profile.",
      success: false,
    });
  }
});

//Upload Avatar
app.post("/users/uploadAvatar/:userID", async (req, res) => {
  const { userID } = req.params;
  const { uImage } = req.body;

  // Validate userID
  if (isNaN(userID)) {
    console.error("Invalid userID:", userID);
    return res.status(400).json({ message: "Invalid userID" });
  }

  if (!uImage) {
    console.error("No image data received");
    return res.status(400).json({ message: "No image data provided." });
  }

  try {
    const query = `UPDATE Users SET uImage = ? WHERE userID = ?`;
    await pool.execute(query, [uImage, userID]);

    console.log("Avatar uploaded successfully!");
    return res.status(200).json({ message: "Avatar uploaded successfully" });
  } catch (err) {
    console.error("Error uploading avatar:", err);
    return res
      .status(500)
      .json({ message: "Internal server error while uploading avatar." });
  }
});

// Start the server
app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});