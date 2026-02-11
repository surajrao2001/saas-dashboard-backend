import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { prisma } from "../db/prisma";
import { env } from "../config/env";
import type { Role } from "@prisma/client";

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
