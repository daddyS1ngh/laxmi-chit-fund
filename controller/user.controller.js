const jwt = require("jsonwebtoken");
const { resp } = require('../utils/common-function');
const helper = require('../utils/helper');
const sendEmail = require('../utils/email');
const userModel = require("../model/user.model");
const _ = require("lodash");
const moment = require("moment");
const { promisify } = require("util");

const signToken = (id) => {
    return jwt.sign({ id }, process.env.JWT_SECRET, {
        expiresIn: process.env.JWT_EXPIRES_IN,
    });
};

const createSendToken = (user, statusCode, res) => {
    const account = user.userId;

    const token = signToken(account);
    const cookieOptions = {
        expires: new Date(
            Date.now() + process.env.JWT_COOKIE_EXPIRES_IN * 24 * 36e5
        ),
        httpOnly: true,
    };
    if (process.env.NODE_ENV === "production") cookieOptions.secure = true;

    res.cookie("jwt", token, cookieOptions);

    // Remove password from output
    user.token = token;
    account.password = undefined;
    user.save();
    const data = {
        accessToken: user.token,
        username: user.username,
        email: user.email
    };

    res
        .status(statusCode)
        .json(resp(200, data, "logged in successfully!"));
};

exports.signup = async (req, res, next) => {
    const { username, email, password, confirmPassword } = req.body;
    const requiredFields = [
        "username",
        "email",
        "password",
        "confirmPassword",
    ];

    const missingFields = [];

    requiredFields.forEach((field) => {
        if (!req.body[field]) {
            missingFields.push(field);
        }
    });

    if (missingFields.length > 0) {
        const errorMessage = `Please provide the following required fields: 
        ${missingFields.join(", ")}`;
        return res.status(200).json({ status: "fail", message: errorMessage })
    }

    if (password !== confirmPassword) {
        return res.status(200).json(
            {
                status: "fail",
                message: "Password and Confirm Password do not match"
            }
        )
    }

    const userExists = await userModel.findOne({ email });
    let otp;

    if (userExists && userExists.otpVerify == true) {
        return res.status(200).json(
            {
                status: "fail",
                message: "user already exist and verified try to login or reset password"
            }
        )
    } else if (userExists && userExists.otpVerify == false) {
        otp = helper.generateOTP();
        userExists.otp = otp;
        userExists.save();

    } else {
        otp = helper.generateOTP();

        const user = new userModel(req.body);
        user.otp = otp;
        await user.save();
    }

    const message = ` Signup account otp  -- >   ${otp}`;
    try {
        await sendEmail({
            email: email,
            subject: "Your password reset otp (valid for 10 min)",
            message,
        });

        res.status(200).json({
            status: "success",
            message: "otp sent to email!",
            otp
        });


    } catch (err) {
        return res.status(200).json(
            {
                status: "fail",
                message: "There was an error sending the email. Try again later!"
            }
        );
    }
};

exports.verifyOtp = async (req, res, next) => {
    try {
        let = { email, otp } = _.pick(req.body, ["email", "otp"]);

        if (!email || !otp) {

            return res.status(200).json({ status: "fail", message: "Please Enter email and otp" })
        }

        const user = await userModel.findOne({
            email,
            otp,
        });


        if (!user) {
            return res.status(200).json({ status: "fail", message: "User not found" })
        } else if (!user.otpVerify) {
            try {
                const token = signToken(user.userId);
                user.token = token;
                user.otpVerify = true;

                req.headers.authorization = `Bearer ${user.token}`;
                await user.save();

                res.status(200).json(
                    resp(
                        200,
                        {
                            username: user.username,
                            email: user.email,
                            accessToken: user.token,
                            mode: "Signup"
                        },
                        "Registered Succesasfully !"
                    )
                );
            } catch (error) {
                console.log(error);
                return res.status(200).json({ status: "fail", message: error.message })
            }

        } else if (user.otpVerify) {
            await user.save();
            res.status(200).json(
                resp(
                    200,
                    { message: "Otp verified Success", mode: "Reset" },
                    " verified success"
                )
            );

        } else {
            return res.status(200).json({ status: "fail", message: "OTP is already verified!" })
        }
    } catch (error) {
        console.log(error);
        return res.status(200).json({ status: "fail", message: error.message })
    }
};

exports.resendOtp = async (req, res, next) => {
    let { email } = _.pick(req.body, ["email"]);
    const user = await userModel.findOne({ email });

    user.otpGeneratedAt = moment();
    const otp = helper.generateOTP();
    user.otp = otp;
    await user.save();

    const message = ` Signup account otp  -- >   ${otp}`;
    try {
        await sendEmail({
            email: email,
            subject: "Your password reset otp (valid for 10 min)",
            message,
        });

        res.status(200).json({
            status: "success",
            message: "otp sent to email!",
            otp
        });
    } catch (err) {
        return res.status(200).json(
            {
                status: "fail",
                message: "There was an error sending the email. Try again later!"
            }
        );
    }
};

exports.login = async (req, res, next) => {
    const { email, password } = req.body;

    // 1) Check if email and password exist
    if (!email || !password) {
        return res.status(200).json({ status: "fail", message: "Please provide email and password!" })
        // return next(new AppError("Please provide email and password!", 200));
    }
    // 2) Check if user exists && password is correct
    const user = await userModel.findOne({ email }).select("+password");
    if (!user) {
        return res.status(200).json({ status: "fail", message: "users not found" });
    }


    // 3) Check Is OTP verify or not
    if (!user.otpVerify) {
        return res.status(200).json({ status: "fail", message: "OTP is not verified" })
        // return next(new AppError("OTP is not verified", 410));
    }
    //added decoded the passsword and than compare with orignal password

    if (!user || !(await user.correctPassword(password, user.password))) {
        return res.status(200).json({ status: "fail", message: "Incorrect email or password" })
        // return next(new AppError("Incorrect email or password", 401));
    }

    // 3) If everything ok, send token to client
    createSendToken(user, 200, res);
};

exports.forgotPassword = async (req, res, next) => {
    const user = await userModel.findOne({ email: req.body.email });
    if (!user) {
        return res.status(200).json(
            {
                status: "fail",
                message: "There is no user with email address. or otp is not verify yet."
            }
        );
    }

    // 2) Generate the otp
    const otp = helper.generateOTP();

    const message = `reset the email password with the verify otp  ${otp}`;
    user.otp = otp;

    await user.save();
    try {
        await sendEmail({
            email: user.email,
            subject: "Your password reset otp (valid for 10 min)",
            message,
        });
        res.status(200).json({
            status: "success",
            message: "otp sent to email!",
            otp
        });
    } catch (err) {
        user.passwordResetToken = undefined;
        user.passwordResetExpires = undefined;
        await user.save({ validateBeforeSave: false });
        return res.status(200).json(
            {
                status: "fail",
                message: "There was an error sending the email. Try again later!"
            }
        );
    }
};

exports.resetPassword = async (req, res, next) => {
    try {
        const { email, password, passwordConfirm } = req.body;
        const newUser = await userModel.findOne({ email, otpVerify: true });

        // 2) If token has not expired, and there is user,set the new password
        if (!newUser) {
            return res.status(200).json({ status: "fail", message: "Token is invalid or has expired." });
            // return next(new AppError("Token is invalid or has expired.", 200));
        } else if (password !== passwordConfirm) {
            return res.status(200).json({ message: "password didn't match to confirm password!", status: "failed" })
        } else {
            const token = signToken(newUser.userId);
            newUser.token = token;
            newUser.password = password;
            newUser.passwordConfirm = passwordConfirm;
            newUser.passwordResetToken = undefined;
            newUser.passwordResetExpires = undefined;
            newUser.passwordChangedAt = Date.now();
            await newUser.save();
            return res.status(200).json({ message: "password Changed Successfully!", status: "success" })
        }
    } catch (error) {
        console.error(error);
        res.json({ error: error.message });
    }
};

exports.protect = async (req, res, next) => {
    // 1) Getting token and check of it's there
    let token;
    if (req.headers.authorization) {
        token = req.headers.authorization.split(" ")[1];
    } else if (req.cookies.jwt) {
        token = req.cookies.jwt;
    }

    if (!token) {
        return res.status(200).json(
            {
                status: "fail",
                message: "You are not logged in! Please log in to get access."
            }
        )
    }

    // 2) Verification token
    const decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET);

    // 3) Check if user still exists
    const currentUser = await userModel.findOne({ userId: decoded.id });
    if (!currentUser) {
        return res.status(200).json(
            {
                status: "fail",
                message: "The user belonging to this token does no longer exist."
            }
        );
    }

    // 4) Check if user changed password after the token was issued
    if (currentUser.changedPasswordAfter(decoded.iat)) {
        return res.status(200).json(
            {
                status: "fail",
                message: "User recently changed password! Please log in again."
            }
        );
    }

    // GRANT ACCESS TO PROTECTED ROUTE
    req.user = currentUser;
    next();
};

exports.updatePassword = async (req, res, next) => {
    try {
        const { email, currentPassword, newPassword } = req.body;

        // Check if all required fields are present
        if (!email || !currentPassword || !newPassword) {
            return res.status(400).json({ error: 'Missing required fields' });
        }

        // Find the user by email and select the password field
        const user = await userModel.findOne({ email }).select('+password');

        // Check if user exists
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Check if current password matches
        const isPasswordCorrect = await user.correctPassword(currentPassword, user.password);
        if (!isPasswordCorrect) {
            return res.status(401).json({ error: 'Incorrect current password' });
        }

        // Update password
        user.password = newPassword;
        user.passwordChangedAt = Date.now(); // Update password changed timestamp
        await user.save();

        res.status(200).json({ message: 'Password updated successfully' });
    } catch (error) {
        console.error('Error updating password:', error);
        res.status(500).json({ message: error.message });
    }
};

