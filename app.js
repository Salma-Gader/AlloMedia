const express = require("express");

const cors = require("cors");
const cookieSession = require("cookie-session");
const app = express();
const db = require("./models");
const dbConfig = require("./config/db.config");
const nodemailer = require('nodemailer');
const { verify } = require("jsonwebtoken");
const swaggerUi = require('swagger-ui-express');
const swaggerJsdoc = require('swagger-jsdoc');
require('dotenv').config();
const Role = db.role;
const corsOptions = {
    origin: 'http://localhost:8000',
};
app.use(cors(corsOptions));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(
    cookieSession({
        name: "alloMedia-session",
        keys: ["COOKIE_SECRET"],
        httpOnly: true
    })
);

app.get("/", (req, res) => {
    res.json({ message: "Welcome to alloMedia application." });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}.`);
});


db.mongoose
    .connect(process.env.DB_URL
        //     `mongodb://${dbConfig.HOST}:${dbConfig.PORT}/${dbConfig.DB}`, {
        //     useNewUrlParser: true,
        //     useUnifiedTopology: true
        // }
    )
    .then(() => {
        console.log("Successfully connect to MongoDB.");
        initial();
    })
    .catch(err => {
        console.error("Connection error", err);
        process.exit();
    });


function initial() {
    Role.estimatedDocumentCount()
        .then(count => {
            if (count === 0) {
                const roles = ["user", "delivery", "admin"];

                roles.forEach(roleName => {
                    new Role({
                            name: roleName
                        }).save()
                        .then(() => {
                            console.log(`Added '${roleName}' to roles collection`);
                        })
                        .catch(err => {
                            console.error("Error adding role", err);
                        });
                });
            }
        })
        .catch(err => {
            console.error("Error getting document count", err);
        });
}



const options = {
    definition: {
        openapi: '3.0.0',
        info: {
            title: 'API Documentation',
            version: '1.0.0',
            description: 'Documentation for the API endpoints',
        },
        servers: [{
            url: 'http://localhost:3000/'
        }]
    },
    apis: ['./swagger/swagger.yaml'],
};

const specs = swaggerJsdoc(options);
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(specs));

require('./routes/auth.routes')(app);
require('./routes/user.routes')(app);