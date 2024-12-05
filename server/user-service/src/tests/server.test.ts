import request from "supertest";
import { afterAll, afterEach, beforeAll, describe, expect, it } from '@jest/globals'
import app from "../index";
import prisma from './prismaTestClient';


beforeAll(async () => {
    await prisma.$connect();
    console.log('Testing DB Connected')
}, 10000);

afterEach(async () => {
    // Clean up the database after each test
    await prisma.account.deleteMany();
    await prisma.user.deleteMany();
});

afterAll(async () => {
    await prisma.$disconnect();
});
  

describe("Express server running test", () => {
    it("GET /hello should return `hello world`", async () => {
        const res = await request(app).get('/hello');
        expect(res.status).toBe(200);
        expect(res.text).toBe("hello bhai");
    });
});


describe("route mismatch handling", () => {
    it("GET /api/v1/mismatch should return 404 route not found error", async () => {
        const res = await request(app).get('/api/v1/mismatch');
        expect(res.status).toBe(404);
        expect(res.body).toMatchObject({ message: "Route Not found!" });
    });
});

// user service routes begin

//signup
describe("Signup", () => {
    it('signup new user with email', async () => {

        const userData = {
            email: "shantanukaushikonc@gmail.com",
            password: "someRandomPassword",
            username: "username"
        }

        const res = await request(app).post('/api/v1/user/signup').send(userData);
        expect(res.status).toBe(201);
        expect(res.body).toMatchObject({ message: "Account created successfully, please verify your email" });

        //check the set-cookie header
        const cookies = res.headers['set-cookie'];
        expect(cookies).toBeDefined();
    }, 10000);

    it('OTP creation check', async () => {
        const userData = {
            email: "shantanukaushikonc@gmail.com",
            password: "someRandomPassword",
            username: "username"
        }

        const res = await request(app).post('/api/v1/user/signup').send(userData);
        expect(res.status).toBe(201);
        expect(res.body).toMatchObject({ message: "Account created successfully, please verify your email" });

        const otp = await prisma.account.findFirst();
        expect(otp).toBeDefined();
    }, 10000);

    it('duplicate email check', async () => {
        const userData = {
            email: "shantanukaushikonc@gmail.com",
            password: "someRandomPassword",
            username: "username"
        }

        const res = await request(app).post('/api/v1/user/signup').send(userData);
        expect(res.status).toBe(201);
        expect(res.body).toMatchObject({ message: "Account created successfully, please verify your email" });

        const res_repeat = await request(app).post('/api/v1/user/signup').send(userData);
        expect(res_repeat.status).toBe(409);
        expect(res_repeat.body).toMatchObject({ message: "this email is already in use" });
    }, 10000);

    it('invalid input check', async () => {
        const userData = {
            email: "shantanukaushikonc@gmail.com",
            password: "someRandomPassword",
        }

        const res = await request(app).post('/api/v1/user/signup').send(userData);
        expect(res.status).toBe(400);
        expect(res.body).toMatchObject({ message: "invalid inputs" });
    }, 10000);
});

//signin
describe("Signin", () => { 
    it("successfull signin", async () => {
        const userData = {
            email: "shantanukaushikonc@gmail.com",
            password: "someRandomPassword",
            username: "username"
        }

        const signinData = {
            email: "shantanukaushikonc@gmail.com",
            password: "someRandomPassword",
        }

        const resSignup = await request(app).post('/api/v1/user/signup').send(userData);
        expect(resSignup.status).toBe(201);
        expect(resSignup.body).toMatchObject({ message: "Account created successfully, please verify your email" });

        const resSignin = await request(app).post('/api/v1/user/signin').send(userData);
        expect(resSignin.status).toBe(200);
        expect(resSignin.body).toMatchObject({ message: "login success" });

        //check the set-cookie header
        const cookies = resSignin.headers['set-cookie'];
        expect(cookies).toBeDefined();
    }, 10000);
});

//verifyEmail
describe("verifyEmail", () => {
    it("verify the email", async () => {

        //create new user
        const userData = {
            email: "shantanukaushikonc@gmail.com",
            password: "someRandomPassword",
            username: "username"
        }

        const resSignup = await request(app).post('/api/v1/user/signup').send(userData);
        expect(resSignup.status).toBe(201);
        expect(resSignup.body).toMatchObject({ message: "Account created successfully, please verify your email" });

        //get the OTP from the db
        let dbOTP = await prisma.account.findFirst();
        const otp = dbOTP?.otp;

        //extract the set-cookie header
        const cookies = resSignup.headers['set-cookie'];
        expect(cookies).toBeDefined();

        //make a post request with the extracted cookies
        const resVerify = await request(app)
                                .post('/api/v1/user/verify')
                                .set("Cookie", cookies)
                                .send({ otp });

        expect(resVerify.status).toBe(200);
        expect(resVerify.body).toMatchObject({ message: "Email verified successfully" });

        //check if the OTP is set to null
        dbOTP = await prisma.account.findFirst();
        expect(dbOTP?.otp).toBe(null);

    }, 10000);
});

//sendOTP
describe("sendOTP", () => { 
    it('send OTP to the email', async () => {
        //create a user
        const userData = {
            email: "shantanukaushikonc@gmail.com",
            password: "someRandomPassword",
            username: "username"
        }

        const resSignup = await request(app).post('/api/v1/user/signup').send(userData);
        expect(resSignup.status).toBe(201);
        expect(resSignup.body).toMatchObject({ message: "Account created successfully, please verify your email" });

        //copy over the cookies recieved
        const cookies = resSignup.headers['set-cookie'];
        expect(cookies).toBeDefined();

        //make a get request with the extracted cookies
        //create a request to /api/v1/user/otp endpoint
        const resOTP = await request(app)
                                .get('/api/v1/user/otp')
                                .set("Cookie", cookies);

        expect(resOTP.status).toBe(200);
        expect(resOTP.body).toMatchObject({ message: "OTP sent to the email successfully" });

        //check the db
       const otp = await prisma.account.findFirst();
       expect(otp).toBeDefined();
    }, 10000);
});

//createGuest
describe("createGuest", () => {
    it('create guest account', async () => {
        //check the respone
        const res = await request(app).post('/api/v1/user/guest').send();
        expect(res.status).toBe(201);
        expect(res.body).toMatchObject({ message: "logged in as guest, if you want your account saved please create an account" });

        //check the db
        const user = await prisma.user.findFirst();
        expect(user?.isGuest).toBe(true);
    }, 10000);
})