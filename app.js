const express = require("express");
const { ObjectId, MongoClient } = require("mongodb");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const app = express();

app.use(express.json());
app.use(cors());

let client;
const initializeDBAndServer = async () => {
  const uri = "mongodb://localhost:27017/";

  client = new MongoClient(uri);

  try {
    await client.connect();
    console.log("Connected to MongoDB.....");
    app.listen(3005, () => {
      console.log("Server running on port: 3005");
    });
  } catch (error) {
    console.error("Error connecting to MongoDB:", error);
    process.exit(1);
  }
};

initializeDBAndServer();

const authenticateToken = (request, response, next) => {
  const authHeader = request.headers["authorization"];
  if (authHeader) {
    const jwtToken = authHeader.split(" ")[1];
    jwt.verify(jwtToken, "MY_SECRET_TOKEN", (error, payload) => {
      if (error) {
        console.error("JWT verification error:", error);
        return response.status(401).send({ error: "Invalid JWT Token" });
      }
      request.userId = payload.userId;
      next();
    });
  } else {
    response.status(401).send({ error: "Authorization header missing" });
  }
};

app.post("/register", async (request, response) => {
  try {
    const collection = client.db("authentication").collection("users");
    const userDetails = request.body;
    const { email } = userDetails;
    const isUserExist = await collection.findOne({ email });
    if (!isUserExist) {
      const hashedPassword = await bcrypt.hash(userDetails.password, 10);
      userDetails.password = hashedPassword;
      const result = await collection.insertOne(userDetails);
      response.status(200).send({
        yourId: result.insertedId,
        message: "User registered successfully",
      });
    } else {
      response
        .status(401)
        .send({ errorMsg: "User with this Email ID already exists" });
    }
  } catch (error) {
    console.error("Registration error:", error);
    response.status(500).send({ error: "Internal server error" });
  }
});

app.post("/login", async (request, response) => {
  try {
    const collection = client.db("authentication").collection("users");
    const { email, password } = request.body;
    const user = await collection.findOne({ email });
    if (!user) {
      return response
        .status(401)
        .send({ errorMsg: "User with this Email ID doesn't exist" });
    }
    const isPasswordMatched = await bcrypt.compare(password, user.password);
    if (isPasswordMatched) {
      const token = jwt.sign({ userId: user._id }, "MY_SECRET_TOKEN");
      response.status(200).send({ jwtToken: token, userId: user._id });
      console.log("User login Succesfully");
    } else {
      response.status(401).send({ errorMsg: "Incorrect password" });
    }
  } catch (error) {
    console.error("Login error:", error);
    response.status(500).send({ error: "Internal server error" });
  }
});

app.get(
  "/getUserData/:userId",
  authenticateToken,
  async (request, response) => {
    try {
      const collection = client.db("authentication").collection("users");
      const { userId } = request.params;
      const user = await collection.findOne({ _id: new ObjectId(userId) });
      if (user) {
        response.status(200).send({ username: user.username });
        console.log(authenticateToken);
        console.log({ username: user.username }, userId);
      } else {
        response.status(404).send({ error: "User not found" });
      }
    } catch (error) {
      console.error("Error fetching user data:", error);
      response.status(500).send({ error: "Internal server error" });
    }
  }
);

//GET all users
app.get("/getUsersData/", authenticateToken, async (request, response) => {
  try {
    const collection = client.db("authentication").collection("users");
    const responseObject = await collection.find();
    const data = await responseObject.toArray();
    if (data) {
      response.status(200).send(data);
      console.log(data);
    } else {
      response.status(404).send({ error: "User not found" });
    }
  } catch (error) {
    console.log("Error fetching user data:", error);
    response.status(500).send({ error: "Internal server error" });
  }
});

module.exports = app;
