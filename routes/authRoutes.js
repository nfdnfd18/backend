import express from 'express';
import * as authController from '../controllers/authController.js';

const router = express.Router();

router.post('/login', authController.login);
router.post('/register', authController.register);
router.post('/logout', authController.logout);
// Bluesky OAuth flow (start and callback)
router.get('/bluesky/start', authController.blueskyStart);
router.get('/bluesky/callback', authController.blueskyCallback);
// Google OAuth flow (start and callback)
router.get('/google/start', authController.googleStart);
router.get('/google/callback', authController.googleCallback);
// debug: return canonicalized client id and probe endpoints
router.get('/bluesky/debug-client', authController.blueskyDebugClient);
// redirect to hosted client metadata JSON for quick inspection
router.get('/bluesky/metadata', (_req, res) => {
	res.redirect('/.well-known/client-metadata.json');
});

export default router;
