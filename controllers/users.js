const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

/* ...existing code... */

// Update user handler (PATCH/PUT)
async function updateUser(req, res) {
  const id = req.params.id;
  // Log incoming payload for debugging
  console.log('[updateUser] incoming body:', JSON.stringify(req.body));

  // Whitelist the allowed fields to avoid accidental DB errors
  const allowed = ['username','email','firstName','lastName','phone','avatar','headerImage','bio'];
  const data = {};
  for (const key of allowed) {
    if (Object.prototype.hasOwnProperty.call(req.body, key)) {
      data[key] = req.body[key];
    }
  }

  try {
    // Basic validation example: ensure email is valid when provided
    if (data.email && !/^\S+@\S+\.\S+$/.test(data.email)) {
      return res.status(400).json({ error: 'Invalid email' });
    }

    const updated = await prisma.user.update({
      where: { id: id },
      data,
    });

    return res.json(updated);
  } catch (err) {
    // Log full error server-side for diagnostics
    console.error('[updateUser] failed to update user', err);
    // Return sanitized message to client
    return res.status(500).json({ error: 'Unable to update user' });
  }
}

/* ...existing code... */
module.exports = { /* ...existing exports..., */ updateUser };