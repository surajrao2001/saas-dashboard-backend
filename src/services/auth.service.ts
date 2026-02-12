import bcrypt from "bcrypt";
import crypto from "crypto";
import jwt from "jsonwebtoken";
import { prisma } from "../db/prisma";
import { env } from "../config/env";
import type { Role } from "@prisma/client";

const PASSWORD_RESET_EXPIRY_HOURS = 1;

const SALT_ROUNDS = 10;

export async function hashPassword(password: string): Promise<string> {
  return bcrypt.hash(password, SALT_ROUNDS);
}

export async function verifyPassword(password: string, hash: string): Promise<boolean> {
  return bcrypt.compare(password, hash);
}

export function signAccessToken(userId: string, role: Role): string {
  return jwt.sign(
    { sub: userId, role },
    env.JWT_ACCESS_SECRET,
    { expiresIn: "15m" }
  );
}

export function signRefreshToken(userId: string): string {
  return jwt.sign(
    { sub: userId, type: "refresh" },
    env.JWT_REFRESH_SECRET,
    { expiresIn: "7d" }
  );
}

export function verifyAccessToken(token: string): { userId: string; role: Role } {
  const payload = jwt.verify(token, env.JWT_ACCESS_SECRET) as { sub: string; role: Role };
  return { userId: payload.sub, role: payload.role };
}

export function verifyRefreshToken(token: string): { userId: string } {
  const payload = jwt.verify(token, env.JWT_REFRESH_SECRET) as { sub: string; type: string };
  if (payload.type !== "refresh") throw new Error("Invalid token type");
  return { userId: payload.sub };
}

export async function createRefreshTokenRecord(userId: string, token: string): Promise<void> {
  const decoded = jwt.decode(token) as { exp?: number };
  const expiresAt = decoded?.exp ? new Date(decoded.exp * 1000) : new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
  await prisma.refreshToken.create({
    data: { token, userId, expiresAt },
  });
}

export async function deleteRefreshToken(token: string): Promise<void> {
  await prisma.refreshToken.deleteMany({ where: { token } });
}

export function createPasswordResetToken(): string {
  return crypto.randomBytes(32).toString("hex");
}

export async function savePasswordResetToken(userId: string, token: string): Promise<void> {
  const expiresAt = new Date(Date.now() + PASSWORD_RESET_EXPIRY_HOURS * 60 * 60 * 1000);
  await prisma.passwordResetToken.create({
    data: { token, userId, expiresAt },
  });
}

export async function findValidPasswordResetToken(token: string): Promise<{ userId: string } | null> {
  const record = await prisma.passwordResetToken.findUnique({
    where: { token },
  });
  if (!record || record.expiresAt < new Date()) return null;
  return { userId: record.userId };
}

export async function deletePasswordResetToken(token: string): Promise<void> {
  await prisma.passwordResetToken.deleteMany({ where: { token } });
}

export async function updateUserPassword(userId: string, newPassword: string): Promise<void> {
  const passwordHash = await hashPassword(newPassword);
  await prisma.user.update({
    where: { id: userId },
    data: { passwordHash },
  });
}
