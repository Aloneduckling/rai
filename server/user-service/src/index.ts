import express, { Request, Response } from "express";
import dotenv from 'dotenv';
import cors from 'cors'

import userRouter from "./routes/userRoutes";

dotenv.config();
const app = express();

app.use(express.json());
app.use(cors());

app.use('/api/v1/user', userRouter);

app.all('*', (req: Request, res: Response) => {
    return res.status(404).json({ message: "Route Not found!" });
});


app.listen(process.env.PORT, () => console.log('server running') );