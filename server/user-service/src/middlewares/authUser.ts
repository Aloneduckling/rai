import express, { NextFunction, Request, Response } from "express";

export default async function authUser (req: Request, res: Response, next: NextFunction) {
    //auth the user here, the auth token, refresh token thing
    //move ahead

    console.log("running middleware");
    return next();
}