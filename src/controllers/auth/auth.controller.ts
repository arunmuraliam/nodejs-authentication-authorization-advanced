import { Request, Response } from "express";
import { loginSchema, registerSchema } from "./auth.schema";
import { User } from "../../models/user.model";
import { comparePassword, hashPassword } from "../../lib/hash";
import jwt from "jsonwebtoken";
import { sendVerificationEmail } from "../../lib/email";
import { createAccessToken, createRefreshToken, verifyRefreshToken } from "../../lib/token";


function getAppUrl() {
    return process.env.APP_URL || `http://localhost:${process.env.PORT}`;
}

export async function registerHandler(req: Request, res: Response) {
    try {
        const result = registerSchema.safeParse(req.body);
        if (!result.success) {
            return res.status(400).json({ message: "Invalid data", error: result.error.message });
        }
        const { name, email, password } = result.data;
        const normalizedEmail = email.toLowerCase().trim();
        const existingUser = await User.findOne({ email: normalizedEmail });
        if (existingUser) {
            return res.status(400).json({ message: "User already exists" });
        }
        const passwordHash = await hashPassword(password);
        const newUser = await User.create({
            name,
            email: normalizedEmail,
            passwordHash,
            role: "user",
            isEmailVerified: false,
            twoFactorEnabled: false
        });

        //email verification
        const verificationToken = jwt.sign({ sub: newUser.id }, process.env.JWT_ACCESS_SECRET!, { expiresIn: "1d" });

        const verifyUrl = `${getAppUrl()}/auth/verify-email?token=${verificationToken}`;

        await sendVerificationEmail(newUser.email, "Verify your email", `Click <a href="${verifyUrl}">here</a> to verify your email`);
        return res.status(201).json({ message: "User registered successfully", user: newUser });
    } catch (error) {
        console.error("Error registering user", error);
        return res.status(500).json({ message: "Internal server error" });
    }
}

export async function verifyEmailHandler(req: Request, res: Response) {
    try {
        const token = req.query.token as string | undefined;
        if (!token || typeof token !== "string") {
            return res.status(400).json({ message: "Invalid token" });
        }

        const payload = jwt.verify(token, process.env.JWT_ACCESS_SECRET!) as { sub: string };
        const user = await User.findById(payload.sub);
        if (!user) {
            return res.status(400).json({ message: "Invalid token" });
        }
        if (user.isEmailVerified) {
            return res.status(400).json({ message: "Email already verified" });
        }
        user.isEmailVerified = true;
        await user.save();
        return res.status(200).json({ message: "Email verified successfully" });
    } catch (error) {
        console.error("Error verifying email", error);
        return res.status(500).json({ message: "Internal server error" });
    }
}

export async function loginHandler(req: Request, res: Response) {
    try {
        const result = loginSchema.safeParse(req.body);
        if (!result.success) {
            return res.status(400).json({ message: "Invalid data", error: result.error.message });
        }
        const { email, password } = result.data;
        const normalizedEmail = email.toLowerCase().trim();
        const user = await User.findOne({ email: normalizedEmail });
        if (!user) {
            return res.status(400).json({ message: "Invalid email or password" });
        }
        const isPasswordValid = await comparePassword(password, user.passwordHash);
        if (!isPasswordValid) {
            return res.status(403).json({ message: "Invalid email or password" });
        }
        if (!user.isEmailVerified) {
            return res.status(400).json({ message: "User email is not verified. Please verify before logging in." });
        }
        const accessToken = createAccessToken(user.id, user.role, user.tokenVersion);
        const refreshToken = createRefreshToken(user.id, user.tokenVersion);

        const isProd = process.env.NODE_ENV === "production";
        res.cookie("refreshToken", refreshToken, { httpOnly: true, secure: isProd, maxAge: 7 * 24 * 60 * 60 * 1000 });
        return res.status(200).json({ message: "Logged in successfully", accessToken, user: { id: user.id, name: user.name, email: user.email, role: user.role, isEmailVerified: user.isEmailVerified, twoFactorEnabled: user.twoFactorEnabled } });
    } catch (error) {
        console.error("Error logging in", error);
        return res.status(500).json({ message: "Internal server error" });
    }
}

export async function refreshHandler(req: Request, res: Response) {
    try {
        const token = req.cookies?.refreshToken as string | undefined;

        if (!token) {
            return res.status(401).json({ message: "Refresh token missing" });
        }

        const payload = verifyRefreshToken(token);

        const user = await User.findById(payload.sub);

        if (!user) {
            return res.status(401).json({ message: "User not found" });
        }

        if (user.tokenVersion !== payload.tokenVersion) {
            return res.status(401).json({ message: "Refresh token invalidated" });
        }

        const newAccessToken = createAccessToken(
            user.id,
            user.role,
            user.tokenVersion
        );
        const newRefreshToken = createRefreshToken(user.id, user.tokenVersion);

        const isProd = process.env.NODE_ENV === "production";
        res.cookie("refreshToken", newRefreshToken, { httpOnly: true, secure: isProd, maxAge: 7 * 24 * 60 * 60 * 1000 });
        return res.status(200).json({ message: "Token Refreshed", accessToken: newAccessToken, user: { id: user.id, name: user.name, email: user.email, role: user.role, isEmailVerified: user.isEmailVerified, twoFactorEnabled: user.twoFactorEnabled } });
    } catch (error) {
        console.error("Error in getting refresh token", error);
        return res.status(500).json({ message: "Internal server error" });
    }
}

export async function logoutHandler(req: Request, res: Response) {
    res.clearCookie("refreshToken", { path: '/' });

    return res.status(200).json({
        message: "Logged out",
    })
}