import { Request, Response } from "express";
import crypto from "crypto";
import { User } from "../models/User.js";
import { sendVerificationEmail, sendLoginOtpEmail } from "../utils/mailer.js";
import { signToken } from "../utils/jwt.js";

function hashOtp(code: string): string {
  return crypto.createHash("sha256").update(code).digest("hex");
}

export async function register(req: Request, res: Response): Promise<void> {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      res.status(400).json({ message: "Name, email, and password are required" });
      return;
    }

    // Check if a user with this email already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      res.status(409).json({ message: "A user with this email already exists" });
      return;
    }

    // Generate a secure verification token
    const rawToken = crypto.randomBytes(32).toString("hex");

    // Token expires in 1 hour
    const tokenExpires = new Date(Date.now() + 60 * 60 * 1000);

    // Create the user
    const user = await User.create({
      name,
      email,
      password,
      verificationToken: rawToken,
      verificationTokenExpires: tokenExpires,
    });

    // Send the verification email
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

    // validation errors (bad email format, weak password, )
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

    // Find a user with this exact token that hasn't expired yet
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

    // Password is correct and the account is verified 
    const otp = crypto.randomInt(100000, 999999).toString();

    user.loginOtpHash = hashOtp(otp);
    user.loginOtpExpires = new Date(Date.now() + 10 * 60 * 1000); 
    await user.save();

    try {
      await sendLoginOtpEmail(user.email, otp);
    } catch (emailErr) {
      console.error("Failed to send login OTP email:", emailErr);
      res.status(500).json({ message: "Could not send login code. Please try again." });
      return;
    }

    res.status(200).json({
      message: "Password correct. A login code has been sent to your email — enter it to finish logging in.",
    });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ message: "Something went wrong during login" });
  }
}

export async function verifyOtp(req: Request, res: Response): Promise<void> {
  try {
    const { email, code } = req.body;

    if (!email || !code) {
      res.status(400).json({ message: "Email and code are required" });
      return;
    }

    const user = await User.findOne({ email }).select("+loginOtpHash +loginOtpExpires");

    const invalidCodeMessage = "Invalid or expired code. Please log in again to request a new one.";

    if (!user || !user.loginOtpHash || !user.loginOtpExpires) {
      res.status(400).json({ message: invalidCodeMessage });
      return;
    }

    if (user.loginOtpExpires.getTime() < Date.now()) {
      res.status(400).json({ message: invalidCodeMessage });
      return;
    }

    if (hashOtp(code) !== user.loginOtpHash) {
      res.status(400).json({ message: invalidCodeMessage });
      return;
    }

    user.loginOtpHash = undefined;
    user.loginOtpExpires = undefined;
    await user.save();

    const token = signToken({ userId: user._id.toString() });

    res.cookie("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 7 * 24 * 60 * 60 * 1000,
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
    console.error("Verify OTP error:", err);
    res.status(500).json({ message: "Something went wrong while verifying the code" });
  }
}

export async function resendOtp(req: Request, res: Response): Promise<void> {
  try {
    const { email } = req.body;

    if (!email) {
      res.status(400).json({ message: "Email is required" });
      return;
    }
    const genericMessage =
      "If a login is currently in progress for that email, a new code has been sent.";

    const user = await User.findOne({ email }).select("+loginOtpHash");

    if (user && user.loginOtpHash) {
      const otp = crypto.randomInt(100000, 999999).toString();

      user.loginOtpHash = hashOtp(otp);
      user.loginOtpExpires = new Date(Date.now() + 10 * 60 * 1000);
      await user.save();

      try {
        await sendLoginOtpEmail(user.email, otp);
      } catch (emailErr) {
        console.error("Failed to resend login OTP email:", emailErr);
      }
    }

    res.status(200).json({ message: genericMessage });
  } catch (err) {
    console.error("Resend OTP error:", err);
    res.status(500).json({ message: "Something went wrong while resending the code" });
  }
}

export async function getProfile(req: Request, res: Response): Promise<void> {
  res.status(200).json({
    user: {
      id: req.user?._id,
      name: req.user?.name,
      email: req.user?.email,
      isVerified: req.user?.isVerified,
    },
  });
}

export async function logout(req: Request, res: Response): Promise<void> {
  try {
    res.clearCookie("token", {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
    });

    res.status(200).json({ message: "Logged out successfully." });
  } catch (err) {
    console.error("Logout error:", err);
    res.status(500).json({ message: "Something went wrong during logout" });
  }
}
export async function resendVerification(req: Request, res: Response): Promise<void> {
  try {
    const { email } = req.body;

    if (!email) {
      res.status(400).json({ message: "Email is required" });
      return;
    }
    const genericMessage =
      "If an account with that email exists and isn't yet verified, a new verification link has been sent.";

    const user = await User.findOne({ email });
    
    if (user && !user.isVerified) {
      const rawToken = crypto.randomBytes(32).toString("hex");
      const tokenExpires = new Date(Date.now() + 60 * 60 * 1000);

      user.verificationToken = rawToken;
      user.verificationTokenExpires = tokenExpires;
      await user.save();

      try {
        await sendVerificationEmail(user.email, rawToken);
      } catch (emailErr) {
        console.error("Failed to resend verification email:", emailErr);
      }
    }

    res.status(200).json({ message: genericMessage });
  } catch (err) {
    console.error("Resend verification error:", err);
    res.status(500).json({ message: "Something went wrong while resending the verification email" });
  }
}