import express from 'express';
import authUser from '../middlewares/authUser';
import { signup, signin, verifyEmail, sendOTP, createGuest, generateGoogleAuthURL, googleOAuthCallback } from '../controllers/userControllers';
const userRouter = express.Router();

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

export default userRouter;