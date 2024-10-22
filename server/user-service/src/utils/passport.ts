import passport from 'passport';
import { Strategy as GoogleStratergy } from 'passport-google-oauth20';

import prisma from '../db';

//store the access and refresh token provided by google and use them for login

passport.use(new GoogleStratergy({
    clientID: process.env.GOOGLE_CLIENT_ID as string,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET as string,
    callbackURL: '/api/v1/user/auth/google/callback'
}, async (accessToken, refreshToken, profile, done) => {
   
    // check if user exists or not
    let user = await prisma.user.findFirst({
        where: {
            googleID: profile.id
        }
    });

    if(user){
        return done(null, user.id);
    }
    
    const profilePicture = profile.photos ? profile.photos[0].value : " ";
    const emailPresent = profile.emails ? true : false;
    
    if(!emailPresent){
        return done("Cannot find email");
    }

    user = await prisma.user.create({
        data:{
            googleID: profile.id,
            email: profile.emails![0].value,
            username: profile.displayName,
            profilePicture,
            isGuest: false,
            emailVerified: true
        }
    });
    const userId = user.id;
    return done(null, userId);
    
}
));