import { Request, Response } from "express";
import { z } from 'zod';
import jwt from 'jsonwebtoken';

import prisma from "../db"

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
        
        //add the data to the db
        const result = await prisma.user.create({
            data: {
                ...userData as signupUserSchema
            }
        });

        //temp
        console.log(result);

        //generate access token and refresh token
        const accessToken = jwt.sign({ userId: result.id }, process.env.JWT_AUTH_TOKEN_SECRET as string, { expiresIn: '15m' });
        const refreshToken = jwt.sign({ userId: result.id }, process.env.JWT_REFRESH_TOKEN_SECRET as string, { expiresIn: '15m' });

        //set them in the cookies
        res.cookie('accessToken', accessToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "strict"
        });

        res.cookie('refreshToken', refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "strict"
        });
        
        //send 201 code for succesfull login
        return res.status(201).json({ message: "user created successfully" });

    } catch (error) {
        return res.status(500).json({ message: "internal server error" });
    }
    
}