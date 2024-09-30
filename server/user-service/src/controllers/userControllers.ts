import { Request, Response } from "express";


export const signup = async (req: Request, res: Response) => {
    //perform signin here
    res.send("running signup function");
}