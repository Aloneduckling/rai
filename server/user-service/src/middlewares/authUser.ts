import { NextFunction, Request, Response } from "express";
import jwt, { TokenExpiredError } from 'jsonwebtoken';
import logger from "../utils/logger";


export interface RequestProtected extends Request{
    userId?: string;
}

export default async function authUser (req: RequestProtected, res: Response, next: NextFunction) {
    const { accessToken } = req.cookies;

    try {

        if(!accessToken) return res.status(401).json({ message: "unauthorized" });
        
        const { userId } = jwt.verify(accessToken, process.env.JWT_AUTH_TOKEN_SECRET as string) as { userId: string };

        req.userId = userId;
        
        return next();

    } catch (error) {
        if(error instanceof TokenExpiredError){
            //regenerate the token and refresh token
            const { refreshToken } = req.cookies;

            try {
                const { userId } = jwt.verify(refreshToken, process.env.JWT_REFRESH_TOKEN_SECRET as string) as { userId: string };
                
                //generate auth and refresh token
                const newAccessToken = jwt.sign({ userId }, process.env.JWT_AUTH_TOKEN_SECRET as string, { expiresIn: '15m' });
                const newRefreshToken = jwt.sign({ userId }, process.env.JWT_REFRESH_TOKEN_SECRET as string);

                //set them in the cookies
                res.cookie('accessToken', newAccessToken, {
                    httpOnly: true,
                    secure: process.env.NODE_ENV === "prod",
                    sameSite: "strict"
                });

                res.cookie('refreshToken', newRefreshToken, {
                    httpOnly: true,
                    secure: process.env.NODE_ENV === "prod",
                    sameSite: "strict"
                });

                req.userId = userId;

                return next();
            } catch (error) {
                //throw the error, user unauthorized in other cases
                throw error;
            }

            
        }
        logger(error);
        return res.status(403).json({ message: "unauthorized user" });
    }

}