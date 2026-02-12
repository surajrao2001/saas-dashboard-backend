import { Request, Response, NextFunction } from "express";
import { z } from "zod";
import { prisma } from "../db/prisma";
import * as authService from "../services/auth.service";
import { ConflictError } from "../utils/errors";

const registerSchema = z.object({
  email: z.string().email(),
  password: z.string().min(6),
  name: z.string().optional(),
});

const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(1),
});

const refreshSchema = z.object({
  refresh_token: z.string().min(1),
});

const forgotPasswordSchema = z.object({
  email: z.string().email(),
});

const resetPasswordSchema = z.object({
  token: z.string().min(1),
  password: z.string().min(6),
});

function toUserResponse(user: { id: string; email: string; name: string | null; role: string }) {
  return { id: user.id, email: user.email, name: user.name, role: user.role };
}

export async function register(req: Request, res: Response, next: NextFunction) {
  try {
    const body = registerSchema.parse(req.body);
    const existing = await prisma.user.findUnique({ where: { email: body.email } });
    if (existing) throw new ConflictError("Email already registered");
    const passwordHash = await authService.hashPassword(body.password);
    const user = await prisma.user.create({
      data: { email: body.email, passwordHash, name: body.name },
    });
    const accessToken = authService.signAccessToken(user.id, user.role);
    const refreshToken = authService.signRefreshToken(user.id);
    await authService.createRefreshTokenRecord(user.id, refreshToken);
    res.json({
      access_token: accessToken,
      refresh_token: refreshToken,
      user: toUserResponse(user),
    });
  } catch (e) {
    next(e);
  }
}

export async function login(req: Request, res: Response, next: NextFunction) {
  try {
    const body = loginSchema.parse(req.body);
    const user = await prisma.user.findUnique({ where: { email: body.email } });
    if (!user) return next(new ConflictError("Invalid email or password"));
    const valid = await authService.verifyPassword(body.password, user.passwordHash);
    if (!valid) return next(new ConflictError("Invalid email or password"));
    const accessToken = authService.signAccessToken(user.id, user.role);
    const refreshToken = authService.signRefreshToken(user.id);
    await authService.createRefreshTokenRecord(user.id, refreshToken);
    res.json({
      access_token: accessToken,
      refresh_token: refreshToken,
      user: toUserResponse(user),
    });
  } catch (e) {
    next(e);
  }
}

export async function refreshToken(req: Request, res: Response, next: NextFunction) {
  try {
    const body = refreshSchema.parse(req.body);
    const { userId } = authService.verifyRefreshToken(body.refresh_token);
    const record = await prisma.refreshToken.findUnique({
      where: { token: body.refresh_token },
      include: { user: true },
    });
    if (!record || record.userId !== userId) {
      return next(new ConflictError("Invalid refresh token"));
    }
    const user = await prisma.user.findUnique({ where: { id: userId } });
    if (!user) return next(new ConflictError("User not found"));
    await authService.deleteRefreshToken(body.refresh_token);
    const accessToken = authService.signAccessToken(user.id, user.role);
    const refreshToken = authService.signRefreshToken(user.id);
    await authService.createRefreshTokenRecord(user.id, refreshToken);
    res.json({
      access_token: accessToken,
      refresh_token: refreshToken,
    });
  } catch (e) {
    next(e);
  }
}

export async function forgotPassword(req: Request, res: Response, next: NextFunction) {
  try {
    const body = forgotPasswordSchema.parse(req.body);
    const user = await prisma.user.findUnique({ where: { email: body.email } });
    // Always return success to avoid email enumeration
    if (!user) {
      return res.json({ message: "If an account exists with that email, you will receive a password reset link." });
    }
    const token = authService.createPasswordResetToken();
    await authService.savePasswordResetToken(user.id, token);
    // TODO: Send email with reset link. For now we return the link in dev (optional).
    const resetLink = `${process.env.FRONTEND_URL || "http://localhost:5173"}/reset-password?token=${token}`;
    if (process.env.NODE_ENV === "development") {
      return res.json({ message: "If an account exists with that email, you will receive a password reset link.", resetLink });
    }
    res.json({ message: "If an account exists with that email, you will receive a password reset link." });
  } catch (e) {
    next(e);
  }
}

export async function resetPassword(req: Request, res: Response, next: NextFunction) {
  try {
    const body = resetPasswordSchema.parse(req.body);
    const record = await authService.findValidPasswordResetToken(body.token);
    if (!record) {
      return next(new ConflictError("Invalid or expired reset token"));
    }
    await authService.updateUserPassword(record.userId, body.password);
    await authService.deletePasswordResetToken(body.token);
    res.json({ message: "Password has been reset successfully." });
  } catch (e) {
    next(e);
  }
}
