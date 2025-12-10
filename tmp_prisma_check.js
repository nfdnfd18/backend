import { PrismaClient } from '@prisma/client';

(async function(){
  const prisma = new PrismaClient();
  try {
    const email = 'e2e_try_1756144419402@test.local';
    const found = await prisma.user.findUnique({ where: { email } });
    if (!found) {
      console.log('no user found for', email);
    } else {
      console.log('user found', { id: found.id, email: found.email, username: found.username, passwordHash: found.password });
    }
  } catch(e) {
    console.error('err', e.message || e);
  } finally {
    await prisma.$disconnect();
  }
})();
