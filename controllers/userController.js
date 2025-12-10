import { PrismaClient } from '@prisma/client';
const prisma = new PrismaClient();

export async function listUsers(req, res, next) {
  try {
    const users = await prisma.user.findMany();
    res.json(users);
  } catch (err) {
    next(err);
  }
}

export async function getUser(req, res, next) {
  try {
    const { id } = req.params;
    const user = await prisma.user.findUnique({ where: { id } });
    if (!user) return res.status(404).json({ error: 'Not found' });
    res.json(user);
  } catch (err) { next(err); }
}

export async function createUser(req, res, next) {
  try {
    const data = req.body;
    const user = await prisma.user.create({ data });
    res.status(201).json(user);
  } catch (err) { next(err); }
}

export async function updateUser(req, res, next) {
  try {
    const { id } = req.params;
    const data = req.body;
    const user = await prisma.user.update({ where: { id }, data });
    res.json(user);
  } catch (err) { next(err); }
}

export async function deleteUser(req, res, next) {
  try {
    const { id } = req.params;
    await prisma.user.delete({ where: { id } });
    res.json({ success: true });
  } catch (err) { next(err); }
}
