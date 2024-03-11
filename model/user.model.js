const mongoose = require("mongoose");
const validator = require("validator");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const { v4: uuidv4 } = require("uuid");

const userSchema = mongoose.Schema(
    {
        username: {
            type: String,
            require: true,
        },

        email: {
            type: String,
            trim: true,
            lowercase: true,
            validate: [validator.isEmail, "please provide your valid email"],
        },

        userId: {
            type: String,
            default: uuidv4,
            unique: true,
        },

        password: {
            type: String,
            minlength: 8,
            select: false,
        },

        passwordConfirm: {
            type: String,
            validate: {
                //This only works on CREATE and SAVE!
                validator: function (el) {
                    return el === this.password;
                },
                message: "Password are not the same!",
            },
        },

        otp: {
            type: Number,
            default: false,
        },

        otpVerify: {
            type: Boolean,
            default: false,
        },

        otpGeneratedAt: {
            type: Date,
            default: new Date().toISOString(),
        },
        token: {
            type: String,
            default: null,
        },
        passwordChangedAt: Date,
        passwordResetToken: String,
        passwordResetExpires: Date,
    },
    {
        versionKey: false,
        timestamps: true,
        versionKey: false
    },
    { versionKey: false }
);

userSchema.pre("save", async function (next) {
    if (!this.isModified("password")) return next();
    this.password = await bcrypt.hash(this.password, 12);
    this.passwordConfirm = undefined;
    next();
});

userSchema.pre("save", function (next) {
    if (!this.isModified("password") || this.isNew) return next();
    this.passwordChangedAt = Date.now() - 1000;
    next();
});

userSchema.methods.correctPassword = async function (
    candidatePassword,
    userPassword
) {
    return await bcrypt.compare(candidatePassword, userPassword);
};

userSchema.methods.changedPasswordAfter = function (JWTTimeStamps) {
    if (this.passwordChangedAt) {
        const changedTimestamp = parseInt(
            this.passwordChangedAt.getTime() / 1000,
            10
        );
        return JWTTimeStamps < changedTimestamp;
    }
    return false;
};

userSchema.methods.createPasswordResetToken = function () {
    const resetToken = crypto.randomBytes(32).toString("hex");
    this.passwordResetToken = crypto
        .createHash("sha256")
        .update(resetToken)
        .digest("hex");
    console.log({ resetToken }, this.passwordResetToken);
    this.passwordResetExpires = Date.now() + 10 * 60 * 1000;
    return resetToken;
};

module.exports = mongoose.model("users", userSchema);
