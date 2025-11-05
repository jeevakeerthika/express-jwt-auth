import express from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import rateLimit from "express-rate-limit";
import User from "../models/User.js";

const router = express.Router();

function verifyToken(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader)
    return res.status(401).json({ message: "no token provided" });

  const token = authHeader.split(" ")[1];
  // jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
  //   if (err) return res.status(403).json({ message: "Invalid token" });
  //   req.user = decoded;
  //   next();
  // });
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      if (err.name === "TokenExpiredError") {
        return res.status(401).json({ message: "access token expired" });
      } else {
        return res.status(403).json({ message: "invalid token" });
      }
    }

    req.user = decoded;
  });

  next();
}

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, //15min
  max: 5,
  message: "Too many login attempts, try again after 15 mins",
});

router.post("/api/register", async (req, res) => {
  try {
    const { name, email, password, role, adminCode, imageUrl } = req.body;
    // console.log(name, email, password, role, adminCode, imageUrl);
    if (!name || !email || !password || !role || !imageUrl) {
      return res.status(400).json({ message: "all fields are required" });
    }

    let userRole = role;
    if (role === "admin" && adminCode !== process.env.ADMIN_CODE) {
      return res
        .status(403)
        .json({ message: `invalid admin code - ${adminCode}` });
    } else if (role !== "admin") userRole = "user";

    const hashedPassword = await bcrypt.hash(password, 10);

    await User.create({
      name,
      email,
      password: hashedPassword,
      role: userRole,
      imageUrl,
    });

    res.status(200).json({ message: `user created` });
  } catch (error) {
    res.status(500).json({ message: error });
  }
});

router.post("/api/login", loginLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    // console.log(email, password);
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: `user with ${email} not found` });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: `invalid password` });
    }

    const accessToken = jwt.sign(
      { id: user._id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "2m" }
    );

    const refreshToken = jwt.sign(
      { id: user._id },
      process.env.JWT_REFRESH_SECRET,
      { expiresIn: "2d" }
    );

    user.refreshToken = refreshToken;
    await user.save();

    res.status(200).json({ accessToken, refreshToken, role: user.role });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

router.get("/", verifyToken, async (req, res) => {
  try {
    if (req.user.role === "admin") {
      const users = await User.find({}, "-password -refreshToken");
      res.status(200).json(users);
    } else {
      const user = await User.findById(req.user.id, "-password -refreshToken");
      res.status(200).json(user);
    }
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

router.put("/:id", verifyToken, async (req, res) => {
  if (req.user.role !== "admin") {
    return res.status(403).json({ message: "Access denied" });
  }

  const { name, role, imageUrl } = req.body;

  let userRole = "user";
  if (role !== "admin") {
    role = userRole;
  }
  await User.findByIdAndUpdate(
    req.params.id,
    { name, role, imageUrl },
    { new: true }
  );
  res
    .status(200)
    .json({ message: `user with id - ${req.params.id} is edited` });
});

router.delete("/:id", verifyToken, async (req, res) => {
  if (req.user.role !== "admin") {
    return res.status(403).json({ message: "Access denied" });
  }

  await User.findByIdAndDelete(req.params.id);
  res
    .status(200)
    .json({ message: `person with id - ${req.params.id} has been deleted` });
});

router.post("/refresh", async (req, res) => {
  // during login we get to store or access or note down the access token
  const { token } = req.body;
  if (!token) return res.status(401).json({ message: "no refresh token" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_REFRESH_SECRET);
    // access token check
    const user = await User.findById(decoded.id);
    if (!user || user.refreshToken !== token)
      return res.status(403).json({ message: "invalid refresh token" });

    const newAccessToken = jwt.sign(
      { id: user.id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "2min" }
    );
    res.status(200).json({ accessToken: newAccessToken });
  } catch (error) {
    res.status(403).json({ message: "Invalid refresh token" });
  }
});

export default router;

// {
//       "_id": "6900c97a276414474fa70570",
//       "name": "arunUser",
//       "email": "arunUserwebdev@gmail.com",
//       "role": "user",
//       "imageUrl": "heyIrl",
//       "__v": 0
//   },

// {
//       "_id": "6900ca09276414474fa70574",
//       "name": "arunAdmin",
//       "email": "arunAdminwebdev@gmail.com",
//       "role": "admin",
//       "imageUrl": "heyIrl",
//       "__v": 0
//   },

// when we give the access token for the first time we will create token using

// {
// id: of the object
// issue of tokem time,
// expiry time
// }/becomes special charactrer

// sad21212wasdqwqwq

// role

// 1-> access token expired
// 2.> admin trying to edit some object
// 3-> he cannot do that, because access token expired
// 4 -> the we send him to refresh route to get a new access token
// 5-> admin gives the access token to refresh route? no he need not give the access token it should be in trash,
// 6-> refresh route ask for refresh token
// 7 => so admin gives the refresh token, refresh route
// 8  => refresh will verify the refresh token that he got from admin and then it will verify with env jwt refresh token
// if everything matches, refresh route takes the id of the admin who gave the refresh token from the token itself
// and then go to DB and ask for the admins whole object
// from that he can extract the role and id and supply new access token

// {"accessToken":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjY5MDhjNjJhZDM4YWYzODAyNTIzMzA1YSIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTc2MjE4MjcxMiwiZXhwIjoxNzYyMTgyNzcyfQ.kCYJKGXVcNn3kREp9YvVL6B5ZzGmY18rlNq-Z1WKRzQ","refreshToken":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjY5MDhjNjJhZDM4YWYzODAyNTIzMzA1YSIsImlhdCI6MTc2MjE4MjcxMiwiZXhwIjoxNzYyMzU1NTEyfQ.WJCHgIFPvHIOabwDqHYmTN5Xd0LIMkFXraHgoGHckm8","role":"admin"}
