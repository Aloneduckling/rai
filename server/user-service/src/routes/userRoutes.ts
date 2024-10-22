import express from 'express';
import authUser from '../middlewares/authUser';
import { signup, signin, verifyEmail, sendOTP, signinWithGoogle } from '../controllers/userControllers';
import passport from 'passport';
import '../utils/passport'; //passport config


const userRouter = express.Router();

userRouter.use(passport.initialize());

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

userRouter.get('/auth/google', passport.authenticate('google', {
    scope: ['profile', 'email']
}));

userRouter.get('/auth/google/callback', passport.authenticate('google', {
    failureRedirect: '/signin'
}), signinWithGoogle);

userRouter.post('/signin', signin);

export default userRouter;