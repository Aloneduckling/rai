import { transporter } from "./nodemailer";
import path from "path";
import ejs from 'ejs'
import logger from "./logger";


interface sendVerificationEmailParams {
    username: string;
    email: string;
    OTP: string;
}

const sendVerificationEmail = async ({ username, email, OTP }: sendVerificationEmailParams) => {
    //get the email template
    const templatePath = path.join(__dirname, '../templates/emailVerification.ejs');

    const emailHTML = await ejs.renderFile(templatePath, {username: username, email: email, otp: OTP});
     
    try {
        await transporter.sendMail({
            from: "Rai <noreply@rai.shantanuk.software>",
            to: email,
            subject: `Hi ${username} please verify your email`,
            text: 'Please verify your email',
            html: emailHTML
        });
    } catch (error) {
        logger("error sending email", error);
    }
};


export default sendVerificationEmail;