import { NextFunction, Request, Response } from "express";
import jwt from 'jsonwebtoken';


export default async function authUser (req: Request, res: Response, next: NextFunction) {
    const { authToken } = req.cookies;

    try {
        if(!authToken) return res.status(401).json({ message: "unauthorized" });
        
        const { userId } = jwt.verify(authToken, process.env.JWT_AUTH_TOKEN_SECRET as string) as { userId: string } ;

        req[userId] = userId;
        
        return next();

    } catch (error) {
        console.log(error);
        return res.status(403).json({ message: "unauthorized user" });
    }

}