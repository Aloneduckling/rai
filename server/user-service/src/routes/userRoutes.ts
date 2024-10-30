import express from 'express';
import authUser from '../middlewares/authUser';
import { signup, signin, verifyEmail, sendOTP, createGuest } from '../controllers/userControllers';

import { OAuth2Client } from 'google-auth-library';
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

userRouter.get('/auth/google', async (req, res) => {
    res.header('Access-Control-Allow-Origin', 'http://localhost:5173');
    res.header('Reffer-Policy', 'no-reffer-when-downgrade');

    const redirectURL = "http:127.0.0.1:3000/api/v1/user/auth/google/callback";

    const oAuth2Client = new OAuth2Client(
        process.env.GOOGLE_CLIENT_ID,
        process.env.GOOGLE_CLIENT_SECRET,
        redirectURL
    );

    const authorizeURL = oAuth2Client.generateAuthUrl({
        access_type: 'offline',
        scope: 'https://www.googleapis.com/auth/userinfo.profile',
        prompt: 'consent'
    });

    res.json({ url: authorizeURL });

});


userRouter.get('/auth/google/callback', async (req, res) => {
    const code = req.query.code;
    try {
        const redirectURL = "http:127.0.0.1:3000/api/v1/user/auth/google/callback";

        const oAuth2Client = new OAuth2Client(
            process.env.GOOGLE_CLIENT_ID,
            process.env.GOOGLE_CLIENT_SECRET,
            redirectURL
        );

        const temp = await oAuth2Client.getToken(code as string);
        oAuth2Client.setCredentials(temp.tokens);
        const user = oAuth2Client.credentials;
        console.log(user);

        const response = await fetch(`https://www.googleapis.com/oauth2/v3/userinfo?access_token${user.access_token}`);
        const data = await response.json();
        //save the token wherever you need
        return res.status(200).json(data)
        
    } catch (error) {
        console.log(error);
        return res.status(500).json({ message: "internal server error" });
    }
    
});

userRouter.post('/signin', signin);

userRouter.post('/guest', createGuest);

export default userRouter;