import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcryptjs';

(async function(){
  const prisma = new PrismaClient();
  try {
    const email = 'e2e_try_1756144419402@test.local';
    const plain = 'TestPass123!';
    const hash = await bcrypt.hash(plain, 10);
    const updated = await prisma.user.update({ where: { email }, data: { password: hash } });
    console.log('updated password for', updated.email);
  } catch(e) {
    console.error('err', e.message || e);
  } finally {
    await prisma.$disconnect();
  }
})();
