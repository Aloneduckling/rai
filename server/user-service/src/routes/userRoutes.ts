import express from 'express';
import authUser from '../middlewares/authUser';
import limiter from '../middlewares/ratelimiter';
import { signup, signin, verifyEmail, sendOTP, createGuest, generateGoogleAuthURL, googleOAuthCallback, logout } from '../controllers/userControllers';
const userRouter = express.Router();

userRouter.use('/otp', limiter);

/*
    TODO
    - Routes:
        1. Signup
        2. Signin
        3. guest-registration
        4. oauth signup
    - Middlewares:
        Authentication
    - Input Validation using zod
*/

userRouter.post('/signup', signup);

userRouter.post('/verify', authUser, verifyEmail);

userRouter.get('/otp', authUser, sendOTP);

//signin and signup with google OAuth2.0
userRouter.get('/auth/google', generateGoogleAuthURL);

userRouter.get('/auth/google/callback', googleOAuthCallback);

userRouter.post('/signin', signin);

userRouter.post('/guest', createGuest);

userRouter.post('/logout', logout);

export default userRouter;