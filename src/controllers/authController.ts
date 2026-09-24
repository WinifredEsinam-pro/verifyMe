import { Request, Response } from "express";
import crypto from "crypto";
import { User } from "../models/User.js";
import { sendVerificationEmail } from "../utils/mailer.js";
import { signToken } from "../utils/jwt.js";

export async function register(req: Request, res: Response): Promise<void> {
  try {
    const { name, email, password } = req.body;

   
    if (!name || !email || !password) {
      res.status(400).json({ message: "Name, email, and password are required" });
      return;
    }

  
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      res.status(409).json({ message: "A user with this email already exists" });
      return;
    }

    
    const rawToken = crypto.randomBytes(32).toString("hex");

    
    const tokenExpires = new Date(Date.now() + 60 * 60 * 1000);

    
    const user = await User.create({
      name,
      email,
      password,
      verificationToken: rawToken,
      verificationTokenExpires: tokenExpires,
    });

    
    try {
      await sendVerificationEmail(user.email, rawToken);
    } catch (emailErr) {
      console.error("Failed to send verification email:", emailErr);
    }

    res.status(201).json({
      message: "User registered successfully. Please verify your email.",
      userId: user._id,
    });
  } catch (err: any) {
   
    if (err.name === "ValidationError") {
      const messages = Object.values(err.errors).map((e: any) => e.message);
      res.status(400).json({ message: messages.join(", ") });
      return;
    }
    console.error("Register error:", err);
    res.status(500).json({ message: "Something went wrong during registration" });
  }
}

export async function verifyEmail(req: Request, res: Response): Promise<void> {
  try {
    const { token } = req.query;

    if (!token || typeof token !== "string") {
      res.status(400).json({ message: "Verification token is required" });
      return;
    }

    
    const user = await User.findOne({
      verificationToken: token,
      verificationTokenExpires: { $gt: new Date() },
    });

    if (!user) {
      res.status(400).json({
        message: "Verification link is invalid or has expired. Please request a new one.",
      });
      return;
    }

    user.isVerified = true;
    user.verificationToken = undefined;
    user.verificationTokenExpires = undefined;
    await user.save();

    res.status(200).json({ message: "Email verified successfully. You can now log in." });
  } catch (err) {
    console.error("Verify email error:", err);
    res.status(500).json({ message: "Something went wrong during verification" });
  }
}

export async function login(req: Request, res: Response): Promise<void> {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      res.status(400).json({ message: "Email and password are required" });
      return;
    }

   
    const user = await User.findOne({ email }).select("+password");

    
    const invalidCredentialsMessage = "Invalid email or password";

    if (!user) {
      res.status(401).json({ message: invalidCredentialsMessage });
      return;
    }

    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      res.status(401).json({ message: invalidCredentialsMessage });
      return;
    }

    if (!user.isVerified) {
      res.status(403).json({
        message: "Please verify your email before logging in",
      });
      return;
    }

    const token = signToken({ userId: user._id.toString() });

    
    res.cookie("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production", 
      sameSite: "strict",
      maxAge: 1 * 24 * 60 * 60 * 1000, 
    });

    res.status(200).json({
      message: "Login successful",
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
      },
    });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ message: "Something went wrong during login" });
  }
}