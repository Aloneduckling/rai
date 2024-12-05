import express, { Request, Response } from "express";
import dotenv from 'dotenv';
import cors from 'cors'
import cookieParser from 'cookie-parser'
dotenv.config();

import userRouter from "./routes/userRoutes";

const app = express();

app.use(express.json());
app.use(cors());
app.use(cookieParser());

app.use('/api/v1/user', userRouter);
app.get('/hello', (req, res) => {
    return res.send("hello bhai");
})

app.all('*', (req: Request, res: Response) => {
    return res.status(404).json({ message: "Route Not found!" });
});

export default app;