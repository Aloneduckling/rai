import express from 'express';
import authUser from '../middlewares/authUser';
import { signup, signin, verifyEmail, sendOTP } from '../controllers/userControllers';

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

userRouter.post('/signin', signin);

export default userRouter;