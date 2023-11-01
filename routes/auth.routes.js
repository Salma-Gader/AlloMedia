const { verifySignUp } = require("../middlewares");
const controller = require("../controllers/auth.controller");
const express = require('express');
const router = express.Router()


module.exports = function(app) {
    // app.use(function(req, res, next) {
    //     res.header(
    //         "Access-Control-Allow-Headers",
    //         "Origin, Content-Type, Accept"
    //     );
    //     next();
    // });

    app.post(
        "/api/auth/signup", [
            verifySignUp.checkDuplicateUsernameOrEmail,
            // verifySignUp.checkRolesExisted
        ],
        controller.signup
    );

    app.post("/api/auth/signin", controller.signin);

    // app.post("/api/auth/signout", controller.signout);
    app.get("/api/auth/verifemail", controller.verifyEmail);
    // app.post("/api/auth/reset-password", controller.resetPassword)
    app.post('/api/auth/forget-password', controller.forgetPassword)
    app.post('/api/auth/reset-password', controller.resetPassword)
};