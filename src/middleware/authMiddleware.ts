import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";
import { verifyToken } from "../utils/jwt.js";
import { User } from "../models/User.js";

export async function requireAuth(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    const token = req.cookies?.token;

    if (!token) {
      res.status(401).json({ message: "You must be logged in to access this resource" });
      return;
    }

    let payload;
    try {
      payload = verifyToken(token);
    } catch (err) {
      if (err instanceof jwt.TokenExpiredError) {
        res.status(401).json({ message: "Your session has expired. Please log in again." });
        return;
      }
      res.status(401).json({ message: "Invalid authentication token" });
      return;
    }

    
    const user = await User.findById(payload.userId);

    if (!user) {
      res.status(401).json({ message: "User account no longer exists" });
      return;
    }

    if (!user.isVerified) {
      res.status(403).json({ message: "Please verify your email to access this resource" });
      return;
    }

   
    req.user = user;
    next();
  } catch (err) {
    console.error("Auth middleware error:", err);
    res.status(500).json({ message: "Something went wrong while authenticating" });
  }
}
