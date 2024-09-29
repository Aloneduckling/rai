import express, { Request, Response } from "express";
import dotenv from 'dotenv';
import prisma from "../db";

dotenv.config();
const app = express();

/*
    TODO
    - Routes:
        1. Signup
        2. Signin
        3. guest-registration
        4. oauth signup
    - Middlewares:
        Authentication
    - Input Validation using zod
*/


app.listen(3000, () => console.log('server running') );