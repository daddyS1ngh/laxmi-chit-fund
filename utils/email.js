const nodemailer = require('nodemailer');

const sendEmail = async options => {


    // 1) Create a transporter
    const transporter = nodemailer.createTransport({
        service: 'gmail',
        secure: true,
        port: 465,
        auth: {
            user: 'farukhumar277@gmail.com',
            pass: process.env.EMAIL_PASSWORD // Use the generated "App Password" if 2FA is enabled
        }
    });

    // 2) Define the email options
    const mailOptions = {
        from: 'farukhumar277@gmail.com',
        to: options.email,
        subject: options.subject,
        text: options.message
    };

    // 3) Actually send the email
    transporter.sendMail(mailOptions, (err, info) => {
        if (err) {
            console.log(err);
        } else {
            console.log(`Email sent successfully to ${options.email} ${info.response}`);
        }
    });
};

module.exports = sendEmail;
