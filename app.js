const express = require("express");
const mongoose = require("mongoose");
const app = express();
const session = require("express-session");
const passport = require("passport");
const bodyParser = require("body-parser");
app.use(bodyParser.json());
const flash = require("connect-flash");
app.use(express.urlencoded({ extended: false }));
var cookieParser = require("cookie-parser");
app.use(cookieParser("ssh! some secret string"));
const bcrypt = require("bcrypt");
const saltRounds = 10;
const jwt = require("jsonwebtoken");
const LocalStrategy = require("passport-local").Strategy;
const GoogleStrategy = require("passport-google-oauth20").Strategy;
app.set("view engine", "ejs");
const path = require("path");
app.use(express.static(path.join(__dirname, "public")));
app.set("views", path.join(__dirname, "views"));
const Course = require("./models/Course");
const User = require("./models/User");
app.use(flash());
app.use(
  session({
    secret: "my-secret-super-key-21728172615261562",
    resave: false,
    saveUninitialized: true,
    cookie: {
      maxAge: 1 * 60 * 60 *1000,
    },
  })
);

require('dotenv').config();


const auth = require("./auth");

app.use(function (request, response, next) {
  response.locals.messages = request.flash();
  next();
});

app.use(passport.initialize());
app.use(passport.session());

const uri = process.env.MONGODB_URL;

async function connect() {
  try {
    await mongoose.connect(uri);
    console.log("Connected to MongoDB");
  } catch (error) {
    console.error(error);
  }
}

connect();

const generateToken = (user) => {
  return jwt.sign(
    { userId: user._id, email: user.email },
    "my-secret-super-key-21728172615261562",
    { expiresIn: "1h" }
  );
};

passport.use(
  new LocalStrategy(async (email, password, done) => {
    try {
      const user = await User.findOne({ email: email });

      if (!user) {
        return done(null, false, { message: "Incorrect email or password" });
      }

      const passwordMatch = await bcrypt.compare(password, user.password);

      if (!passwordMatch) {
        return done(null, false, { message: "Incorrect email or password" });
      }
      const token = generateToken(user);
      return res.json({
        success: true,
        message: "Authentication successful",
        token: token,
      });
    } catch (error) {
      return done(error);
    }
  })
);

passport.use(
  new GoogleStrategy(
    {
      clientID:process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.CALLBACK_URL,
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        let user = await User.findOne({ googleId: profile.id });
        // console.log(profile)
        if (!user) {
          user = new User({
            name: profile.displayName,
            email: profile.emails[0].value,
            googleId: profile.id,
          });
          await user.save();
        }
        return done(null, user);
      } catch (error) {
        return done(error);
      }
    }
  )
);

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (error) {
    done(error);
  }
});

app.get("/", (req, res) => {
  const authToken = req.cookies.authToken;

  if (!authToken) {
    return res.render("home");
  }

  try {
    const decoded = jwt.verify(authToken, "my-secret-super-key-21728172615261562");
    req.user = decoded;
    // return res.redirect("/dashboard");
    res.redirect("/dashboard?token=" + authToken);
  } catch (error) {
    console.error('Error verifying JWT:', error);
    return res.render("home");
  }
});


app.get("/register", (req, res) => {
  res.render("register");
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.post("/users", async (request, response) => {
  const name = request.body.name;
  const mail = request.body.email;
  const pwd = request.body.password;

  if (!name) {
    request.flash("error", "Please make sure you enter name");
    return response.redirect("/register");
  }
  if (!mail) {
    request.flash("error", "Please make sure you enter Email-ID");
    return response.redirect("/register");
  }
  if (!pwd) {
    request.flash("error", "Please make sure you enter valid password");
    return response.redirect("/register");
  }

  const hashedpwd = await bcrypt.hash(pwd, saltRounds);
  let existuser = false;
  try {
    const user = await User.findOne({ email: mail });
    if (user) {
      existuser = true;
    }

    if (!existuser) {
      try {
        const newUser = new User({
          name: name,
          email: mail,
          password: hashedpwd,
        });
        await newUser.save();
        const token = generateToken(newUser);
        newUser.token = token;
        response.redirect("/dashboard?token=" + token);
      } catch (err) {
        console.log("Error in saving the data", err);
      }
    } else {
      request.flash("error", "User account exists on same email id");
      return response.redirect("/register");
    }
  } catch (error) {
    console.log(error);
    request.flash("error", error.message);
    return response.redirect("/register");
  }
});

app.get("/signout", (request, response, next) => {
  request.logout((err) => {
    if (err) {
      return next(err);
    }
    response.clearCookie("authToken");
    response.redirect("/");
  });
});

app.post("/session", async (request, response) => {
  if (!request.body.email) {
    request.flash("error", "please enter email");
    return response.redirect("/login");
  } else if (!request.body.password) {
    request.flash("error", "please enter password");
    return response.redirect("/login");
  } else {
    try {
      const user = await User.findOne({ email: request.body.email });
      if (
        user &&
        (await bcrypt.compare(request.body.password, user.password))
      ) {
        const token = generateToken(user);
        response.redirect(`/dashboard?token=${token}`);
      } else {
        request.flash("error", "invalid credentials");
        return response.redirect("/login");
      }
    } catch (err) {
      console.log(err);
    }
  }
});

app.get(
  "/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);
app.get(
  "/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/login" }),
  async (req, res) => {
    try {
      const user = req.user;
      if (!user) {
        throw new Error("User not found");
      }
      const token = generateToken(user);
      res.redirect(`/dashboard?token=${token}`);
    } catch (error) {
      console.error("Error during Google sign-in callback:", error);
      res.redirect("/login");
    }
  }
);

app.get("/dashboard", auth, (req, res) => {
  Course.find()
    .then((courses) => {
      // console.log('Courses:', courses);
      if (req.accepts("html")) {
        res.cookie("authToken", req.query.token, {
          maxAge: 24 * 60 * 60 * 1000,
          httpOnly: true,
          secure: true
        });
        res.render("dashboard", {
          data: courses,
        });
      } else {
        res.json({
          courses,
        });
      }
    })
    .catch((error) => {
      console.error("Error finding courses:", error);
      res.status(500).send("Internal Server Error");
    });
});

//for adding course details
app.post("/courses", async (req, res) => {
  try {
    const title = req.body.title;
    const duration = req.body.duration;
    // console.log(req.body)
    if (!title || !duration) {
      return res
        .status(400)
        .json({ error: "Title and duration are required." });
    }
    const newCourse = new Course({ title, duration });
    const savedCourse = await newCourse.save();
    res.status(201).json(savedCourse);
  } catch (error) {
    console.error("Error saving course:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

module.exports = app;
