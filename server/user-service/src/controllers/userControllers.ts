import { Request, Response } from "express";
import { z } from 'zod';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import prisma from "../db"
import crypto from 'crypto';


//util imports
import logger from "../utils/logger";
import { RequestProtected } from "../middlewares/authUser";
import sendVerificationEmail from "../utils/sendVerificationEmail";


//TODO: Add email verification on signup
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

        //add the data to the db
        const result = await prisma.user.create({
            data: {
                ...userData as signupUserSchema,
                password: hashedPassword,
                isGuest: false
            }
        });


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
        //TODO:
        //save this OTP in the DB along with the expiration time
        //we will have to create an Account collection that will handle all this thing
        //the User collection will handle all the user related stuff

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
        const refreshToken = jwt.sign({ userId: result.id }, process.env.JWT_REFRESH_TOKEN_SECRET as string, { expiresIn: '15m' });

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
        const refreshToken = jwt.sign({ userId: userData.id }, process.env.JWT_REFRESH_TOKEN_SECRET as string, { expiresIn: '15m' });

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

//TODO: test this function and route
export const verifyEmail = async (req: RequestProtected, res: Response) => {
    try {
        const userId = req.userId;
        const otpValidationSchema = z.string().length(4) //otp consists of 4 letters

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

        if(dbOTP?.otp !== otp || otpExpired){
            return res.status(400).json({ message: "OTP expired or invalid OTP entered, OTPs are valid for 3 minuets only" });
        }

        //Correct OTP entered, invalidate it in the db and verify the email
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
        const userId = req.userId;
        
        //get user details
        const userData = await prisma.user.findFirst({
            where: {
                id: userId
            }
        });

        //generate OTP
        const hexString = crypto.randomBytes(4);

        let OTP = "";
        for(let i = 0; i < hexString.length; i++){
            OTP += hexString[i] % 10;
        }

        const nowDate = new Date();
        const expiaryTime = new Date( nowDate.getTime() + 3 * 60000 );

        //create a new OTP

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
        const guestIP = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
        
        const guestUsername = crypto.randomBytes(3).toString('hex');

        const guest = await prisma.user.create({
            data: {
                guestIP: guestIP as string,
                username: guestUsername
            }
        });

        //create refresh token and auth token
        const accessToken = jwt.sign({ userId: guest.id }, process.env.JWT_AUTH_TOKEN_SECRET as string, { expiresIn: '15m' });
        const refreshToken = jwt.sign({ userId: guest.id }, process.env.JWT_REFRESH_TOKEN_SECRET as string, { expiresIn: '15m' });
        
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

        return res.status(201).json({ message: "logged in as guest, if you want your account saved please create an account" });

    } catch (error) {
        logger(error);
        return res.status(500).json({ message: "internal server error" });
    }
}


//TODO:
// when the guest creates an account their guest account should be converted to the registered account
// Implement the email verification on signup
// Implement O-Auth login/sign-up
// Test the routes
