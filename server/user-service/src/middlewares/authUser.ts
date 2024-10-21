import { NextFunction, Request, Response } from "express";
import jwt from 'jsonwebtoken';


export interface RequestProtected extends Request{
    userId?: string;
}

export default async function authUser (req: RequestProtected, res: Response, next: NextFunction) {
    const { accessToken } = req.cookies;

    try {
        if(!accessToken) return res.status(401).json({ message: "unauthorized" });
        
        const { userId } = jwt.verify(accessToken, process.env.JWT_AUTH_TOKEN_SECRET as string) as { userId: string } ;

        req.userId = userId;
        
        return next();

    } catch (error) {
        console.log(error);
        return res.status(403).json({ message: "unauthorized user" });
    }

}