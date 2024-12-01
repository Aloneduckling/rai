import { Request, Response } from "express";
import { z } from 'zod';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import prisma from "../db"
import crypto from 'crypto';
import axios from 'axios'

//util imports
import logger from "../utils/logger";
import { RequestProtected } from "../middlewares/authUser";
import sendVerificationEmail from "../utils/sendVerificationEmail";
import { auth, OAuth2Client } from "google-auth-library";
import { User } from "@prisma/client";



export const signup = async (req: Request, res: Response) => {
    try {
        const signupSchema = z.object({
            email: z.string().email(),
            password: z.string().min(6).max(32),
            username: z.string().min(3).max(24)
        }).required();
        
        type signupUserSchema = z.infer<typeof signupSchema>;
        
        //parse the schema
        const { error, data: userData } = signupSchema.safeParse(req.body);

        if(error){
            res.status(400).json({ message: "invalid inputs" });
        }
        
        //check if the user exists or not
        const isUser = await prisma.user.findFirst({
            where: {
                email: userData?.email
            }
        });

        

        if(isUser){
            return res.status(409).json({ message: "this email is already in use" });
        }

        //hash the password
        const hashedPassword = await bcrypt.hash(userData?.password as string, 10);

        //check if the user is guest or not
        //the guest user will have a cookie
        const { accessToken: authToken } = req.cookies;
        let result: User | null = null;
        try {
            //if the user had a guest account then do the following
            const { userId } = jwt.verify(authToken, process.env.JWT_AUTH_TOKEN_SECRET as string) as { userId: string };
            
            //check if the user exists or not
            const isGuestValid = await prisma.user.findFirst({
                where: {
                    id: userId
                }
            });

            if(isGuestValid){
                //update the details of the guest account
                result = await prisma.user.update({
                    where: {
                        id: userId
                    },
                    data: {
                        ...userData as signupUserSchema,
                        password: hashedPassword,
                        isGuest: false,
                        guestIP: null
                    }
                });
            }

        } catch (error) {
            logger(error);
            result = null;
        }

        //add the data to the db
        if(!result){
            result = await prisma.user.create({
                data: {
                    ...userData as signupUserSchema,
                    password: hashedPassword,
                    isGuest: false
                }
            });
        }


        //send email verification (should be a function in itself as it will be used again)
        
        //create an OTP and save it in the DB, OTP would be a 4 digit string
        const hexString = crypto.randomBytes(4);
        //this will give us a random buffer of 4 bytes of hex numbers
        //eg <Buffer b4 01 28 c1> => <Buffer 180 1 28 193>
        //we will then mod each buffer byte with 10 to get the number
        //using crypto for this because it generated better random numbers
        
        let OTP = "";
        for(let i = 0; i < hexString.length; i++){
            OTP += hexString[i] % 10;
        }


        const nowDate = new Date();
        const expiaryTime = new Date( nowDate.getTime() + 3 * 60000 );

        await prisma.account.create({
            data: {
                otp: OTP,
                otpExpiry: expiaryTime,
                userId: result.id
            }
        });

        const params = {
            username: userData?.username as string,
            email: userData?.email as string,
            OTP
        };


        //send verification email (email with OTP)
        sendVerificationEmail(params);

        //generate access token and refresh token
        const accessToken = jwt.sign({ userId: result.id }, process.env.JWT_AUTH_TOKEN_SECRET as string, { expiresIn: '15m' });
        const refreshToken = jwt.sign({ userId: result.id }, process.env.JWT_REFRESH_TOKEN_SECRET as string);

        //set them in the cookies
        res.cookie('accessToken', accessToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "prod",
            sameSite: "strict"
        });

        res.cookie('refreshToken', refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "prod",
            sameSite: "strict"
        });
        
        //send 201 code for succesfull login
        return res.status(201).json({ message: "Account created successfully, please verify your email" });

    } catch (error) {
        logger(error);
        return res.status(500).json({ message: "internal server error" });
    }
    
}

export const signin = async (req: Request, res: Response) => {
    try {
        const signinSchema = z.object({
            email: z.string().email(),
            password: z.string().min(6).max(32)
        });

        const { error, data: signinData } = signinSchema.safeParse(req.body);

        if(error){
            return  res.status(400).json({ message: "invalid inputs" });
        }
        
        //fetch user from db
        const userData = await prisma.user.findFirst({
            where: {
                email: signinData.email
            }
        })
        
        //check if the user exists or not
        if(!userData?.email){
            return res.status(404).json({
                message: "user not found"
            });
        }

        //match password
        const isValid = await bcrypt.compare(signinData.password, userData.password as string);
        
        if(!isValid){
            return res.status(401).json({ message: "incorrect password" });
        }
        
        //generate auth and refresh token
        const accessToken = jwt.sign({ userId: userData.id }, process.env.JWT_AUTH_TOKEN_SECRET as string, { expiresIn: '15m' });
        const refreshToken = jwt.sign({ userId: userData.id }, process.env.JWT_REFRESH_TOKEN_SECRET as string);

        //set them in the cookies
        res.cookie('accessToken', accessToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "prod",
            sameSite: "strict"
        });

        res.cookie('refreshToken', refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "prod",
            sameSite: "strict"
        });
        

        
        //send a 200 response

        return res.json({
            message: "login success"
        });

    } catch (error) {
        return res.status(500).json({ message: "internal server error" });
    }
}

export const verifyEmail = async (req: RequestProtected, res: Response) => {
    try {
        const userId = req.userId;
        const otpValidationSchema = z.string().length(4) //otp consists of 4 letters

        //input validation
        const { error, data: otp } = otpValidationSchema.safeParse(req.body.otp);

        if(error){
            logger(error);
            return res.status(400).json({ message: "invalid inputs" });
        }

        const dbOTP = await prisma.account.findFirst({
            where: {
                userId: userId
            }
        });
        
        //check if the OTP is expired or not
        const otpExpired = new Date(dbOTP?.otpExpiry as Date).getTime() < new Date().getTime();

        //if otp is expired or wrong otp has been entered
        if(dbOTP?.otp !== otp || otpExpired){
            return res.status(400).json({ message: "OTP expired or invalid OTP entered, OTPs are valid for 3 minuets only" });
        }

        //Correct OTP entered, invalidate it in the db and verify the email
        //Should we set the otp and otpExpiary to null? or should we delete the entry.
        //If i want to limit the number of OTPs then I have to keep the track of the requested OTPs
        //For this I can use redis. I can use a mixture of both. Redis for keeping count of OTP requests
        //and Database to store the OTPs. I will set it to null later
        //we would have to use a prisma transaction here, I will use nested writes
        await prisma.user.update({
            where: {
              id: userId,
            },
            data: {
              emailVerified: true,
              Account: {
                update: {
                  otp: null,
                  otpExpiry: null,
                },
              },
            },
        });

        return res.status(200).json({ message: "Email verified successfully" });

    } catch (error) {
        logger(error);
        return res.status(500).json({ message: "internal server error" });
    }
}

//re-send otp for verification
export const sendOTP = async (req: RequestProtected, res: Response) => {
    try {
        //TODO: request 5 OTPs in 30 mins, invalidate old OTPs by setting them null
        //redis will keep the count of OTPs requested in last 30mins and when we hit the 30 min mark
        //using rate limiting in memory here(☝️) instead of redis store
        //we will invalidate the OTP count

        

        const userId = req.userId;
        
        //get user details
        const userData = await prisma.user.findFirst({
            where: {
                id: userId
            }
        });

        if(!userData) {
            return res.status(404).json({ message: "user not found" });
        }

        //if user verified then don't send the OTP
        if(userData.emailVerified){
            return res.status(409).json({ message: "email already verified" });
        }

        //generate OTP
        const hexString = crypto.randomBytes(4);

        let OTP = "";
        for(let i = 0; i < hexString.length; i++){
            OTP += hexString[i] % 10;
        }

        const nowDate = new Date();
        const expiaryTime = new Date( nowDate.getTime() + 3 * 60000 );

        //create a new OTP
        //we are overwriting the previous OTP, this will ensure that only ONE otp is assigned at
        //a given moment for a user
        await prisma.account.update({
            where: {
                userId: userId
            },
            data: {
                otp: OTP,
                otpExpiry: expiaryTime
            }
        });

        //sendVerificationEmail
        const params = {
            username: userData?.username as string,
            email: userData?.email as string,
            OTP
        };

        sendVerificationEmail(params);

        return res.status(200).json({ message: "OTP sent to the email successfully" });

    } catch (error) {
        logger(error);
        return res.status(500).json({ message: "internal server error" });
    }
}

export const createGuest = async (req: Request, res: Response) => {
    try {
        //extract the IP address
        // TODO: Study and refine the guestIP logic for rate limiting
        const guestIP = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
        
        const guestUsername = crypto.randomBytes(3).toString('hex');

        const guest = await prisma.user.create({
            data: {
                guestIP: guestIP as string,
                username: guestUsername
            }
        });

        //create auth token only for the guest account
        //this authToken would act as an identifier for the guest account
        const accessToken = jwt.sign({ userId: guest.id }, process.env.JWT_AUTH_TOKEN_SECRET as string);
        
        
        //set them in the cookies
        res.cookie('accessToken', accessToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "prod",
            sameSite: "strict"
        });


        return res.status(201).json({ message: "logged in as guest, if you want your account saved please create an account" });

    } catch (error) {
        logger(error);
        return res.status(500).json({ message: "internal server error" });
    }
}

export const generateGoogleAuthURL = async (req: Request, res: Response) => {
    try {
        res.header('Access-Control-Allow-Origin', process.env.FRONTEND_URL);
        res.header('Reffer-Policy', 'no-reffer-when-downgrade');
    
        const redirectURL = `${process.env.BACKEND_URL}/api/v1/user/auth/google/callback`;
    
        const oAuth2Client = new OAuth2Client(
            process.env.GOOGLE_CLIENT_ID,
            process.env.GOOGLE_CLIENT_SECRET,
            redirectURL
        );
    
        const authorizeURL = oAuth2Client.generateAuthUrl({
            access_type: 'offline',
            scope: 'https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/userinfo.email',
            prompt: 'consent'
        });

        res.status(200).json({ url: authorizeURL });
    } catch (error) {
        logger(error);
        return res.status(500).json({ message: "internal server error" });
    }
    
}

export const googleOAuthCallback = async (req: Request, res: Response) => {
    const code = req.query.code;
    try {
        const redirectURL = `${process.env.BACKEND_URL}/api/v1/user/auth/google/callback`;

        const oAuth2Client = new OAuth2Client(
            process.env.GOOGLE_CLIENT_ID,
            process.env.GOOGLE_CLIENT_SECRET,
            redirectURL
        );

        const oauthToken = await oAuth2Client.getToken(code as string);
        oAuth2Client.setCredentials(oauthToken.tokens);
        const user = oAuth2Client.credentials;


        const response = await axios.get(`https://www.googleapis.com/oauth2/v3/userinfo?access_token=${user.access_token}`);
        
        //save the token wherever you need
        //data.data has the data needed
        interface UserGoogleOAuthData {
            sub: string;
            name: string;
            given_name: string;
            family_name: string;
            picture: string;
            email: string;
            email_verified: boolean;
        }

        const userData: UserGoogleOAuthData = response.data;

        let foundUser: User | null = null;
        let newUser: User | null = null;

        //check if they are registered with an email
        foundUser = await prisma.user.findFirst({
            where: {
                email: userData.email
            }
        });
        

        if(!foundUser){
            //if user not registered with email then create a new user
            newUser = await prisma.user.create({
                data: {
                    username: userData.name,
                    email: userData.email ?? null,
                    googleID: userData.sub,
                    profilePicture: userData.picture,
                    emailVerified: true,
                    isGuest: false
                }
            });

        }else{
            //else update the user's profile and fill in the data obtained from OAuth
            foundUser = await prisma.user.update({
                where: {
                    id: foundUser.id
                },
                data: {
                    googleID: userData.sub,
                    email: userData.email,
                    emailVerified: true,
                    profilePicture: userData.picture,
                    isGuest: false,
                    guestIP: null
                }
            });
        }
        

        //extract the id and then create a token
        const userId = newUser ? newUser.id : foundUser?.id;


        //generate auth and refresh token
        const accessToken = jwt.sign({ userId }, process.env.JWT_AUTH_TOKEN_SECRET as string, { expiresIn: '15m' });
        const refreshToken = jwt.sign({ userId }, process.env.JWT_REFRESH_TOKEN_SECRET as string);

        //set them in the cookies
        res.cookie('accessToken', accessToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "prod",
            sameSite: "strict"
        });

        res.cookie('refreshToken', refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "prod",
            sameSite: "strict"
        });
        
        if(newUser){
            return res.status(201).json({ message: "signed up successfully" });
        }

        return res.status(200).json({ message: "logged in successfully" });

    } catch (error) {
        console.log(error);
        return res.status(500).json({ message: "internal server error" });
    }

}

export const logout = async (req: Request, res: Response) => {
    try {
        res.clearCookie('authToken', {
            httpOnly: true,
            secure: process.env.NODE_ENV === "prod",
            sameSite: "strict"
        });
        res.clearCookie('refreshToken', {
            httpOnly: true,
            secure: process.env.NODE_ENV === "prod",
            sameSite: "strict"
        });

        return res.status(204).json();

    } catch (error) {
        logger(error);
        return res.status(500).json({ message: "internal server error" });
    }
    
}