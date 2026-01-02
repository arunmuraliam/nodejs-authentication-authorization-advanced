import { Request, Response } from "express";
import { registerSchema } from "./auth.schema";
import { User } from "../../models/user.model";
import { hashPassword } from "../../lib/hash";

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
        const newUser = await User.create({ name, email: normalizedEmail, passwordHash, role: "user", isEmailVerified: false, twoFactorEnabled: false });
        res.json(newUser);
    } catch (error) {
        console.error("Error registering user", error);
        return res.status(500).json({ message: "Internal server error" });
    }
}