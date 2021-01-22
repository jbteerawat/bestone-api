const express = require("express");
const app = express();
const mysql = require("mysql");
const cors = require("cors");

const session = require("express-session");

const bcrypt = require("bcrypt");
const saltRounds = 10;

const jwt = require("jsonwebtoken");
const jwtKey = "jwtSecretZ";
const expiredToken = 60 * 60 * 24; // 1 day

const { response } = require("express");
const dotenv = require("dotenv");
dotenv.config();

const nodemailer = require("nodemailer");

app.use(cors());
// app.use(cors({
//   origin: CLIENT_ORIGIN
// }))

app.use(express.json());

app.use(
  session({
    key: "userId",
    secret: "subscribe",
    resave: false,
    saveUninitialized: false,
    cookie: {
      expires: 60 * 60 * 24,
    },
  })
);

const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_DATABASE,
});

let transporter = nodemailer.createTransport({
  host: process.env.MAIL_HOST,
  port: process.env.MAIL_PORT,
  secure: false,
  requireTLS: true,
  auth: {
    user: process.env.MAIL_USER,
    pass: process.env.MAIL_PASS,
  },
});

const sentMail = (to, subject, html, from) => {
  let mailOptions = {
    from: from || process.env.MAIL_USER,
    to: to,
    subject: subject,
    html: html,
  };

  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      return console.log(error.message);
    }
    console.log("Email sent success: " + info.response);
  });
};

// middleware
const verifyJWT = (req, res, next) => {
  const token = req.headers["x-access-token"];

  if (!token) {
    res.send({
      auth: false,
      message: "Need a token, please give the token!",
    });
  } else {
    jwt.verify(token, jwtKey, (err, decoded) => {
      if (err) {
        res.json({ auth: false, message: "Failed to authenticate." });
      } else {
        const id = decoded.id;
        const token = jwt.sign({ id }, jwtKey, {
          expiresIn: expiredToken,
        });

        req.userId = id;
        req.token = token;
        next();
      }
    });
  }
};

app.get("/isUserAuth", verifyJWT, (req, res) => {
  res.send("Okay, Are are authenticatied.");
});

app.get("/checkLogin", verifyJWT, (req, res) => {
  res.send({
    auth: true,
    status: "OK",
    userId: req.userId,
    token: req.token,
  });
});

app.post("/login", (req, res) => {
  // encode pass
  // const pass = "admin";
  // bcrypt.hash(pass, saltRounds, (err, hash) => {
  //   console.log(err);
  //   if (!err) {
  //     console.log(hash);
  //   } else {
  //     console.log(err);
  //   }
  // });

  db.query(
    "SELECT id, username, password, role_id FROM users WHERE username = ? AND is_delete = 0 AND is_active = 1",
    req.body.username,
    (err, result) => {
      if (err) {
        console.log(err);
      } else {
        if (result.length) {
          bcrypt.compare(
            req.body.password,
            result[0].password,
            (error, response) => {
              if (response) {
                const id = result[0].id;
                const token = jwt.sign({ id }, jwtKey, {
                  expiresIn: expiredToken,
                });

                res.json({
                  auth: true,
                  token: token,
                  result: {
                    id: result[0].id,
                    username: result[0].username,
                    password: result[0].password,
                    role: result[0].role,
                  },
                });
              } else {
                res.send({
                  auth: false,
                  message: "Wrong username/password combination!",
                });
              }
            }
          );
        } else {
          res.send({
            auth: false,
            message: "User doesn't exist.",
          });
        }
      }
    }
  );
});

app.get("/api/users", (req, res) => {
  db.query(
    "SELECT `(is_delete)?+.+` FROM users WHERE is_active = 1 AND is_delete = 0",
    (err, result) => {
      if (err) {
        console.log(err);
      } else {
        res.send(result);
      }
    }
  );
});

app.get("/api/faqs", (req, res) => {
  db.query(
    "SELECT id, question, answer FROM faqs WHERE is_active = 1 AND is_delete = 0",
    (err, result) => {
      if (err) {
        console.log(err);
      } else {
        res.send(result);
      }
    }
  );
});

app.post("/faq/create", (req, res) => {
  const question = req.body.question;
  const answer = req.body.answer;

  db.query(
    "INSERT INTO faqs (question, answer) VALUES (?, ?)",
    [question, answer],
    (err, result) => {
      if (err) {
        console.log(err);
        res.send({ status: "ERROR", message: err.message });
      } else {
        console.log("faq inserted: ", result.insertId);
        res.send({ status: "OK", insertId: result.insertId });
      }
    }
  );
});

app.put("/faq/update", (req, res) => {
  db.query(
    "UPDATE faqs SET question = ?, answer = ? WHERE id = ?",
    [req.body.question, req.body.answer, req.body.id],
    (err, result) => {
      if (err) {
        console.log(err);
        res.send({ status: "ERROR", message: err.message });
      } else {
        console.log("faq updated");
        console.log(result.affectedRows + " record(s) updated");
        res.send({ status: "OK" });
      }
    }
  );
});

app.delete("/faq/delete/:id", (req, res) => {
  const id = req.params.id;
  db.query("UPDATE faqs SET is_delete = 1 WHERE id = ?", id, (err, result) => {
    if (err) {
      console.log(err);
      res.send({ status: "ERROR", message: err.message });
    } else {
      console.log("faq deleted");
      console.log(result.affectedRows + " record(s) updated");
      res.send({ status: "OK" });
    }
  });
});

app.get("/api/detail", (req, res) => {
  const detail_id = 1;
  db.query(
    "SELECT id, sitename, address, latitude, longitude, email FROM base_details WHERE id = ? AND is_active = 1 AND is_delete = 0",
    [detail_id],
    (err, result) => {
      if (err) {
        console.log(err);
      } else {
        res.send(result[0]);
      }
    }
  );
});

app.put("/detail/update", (req, res) => {
  db.query(
    "UPDATE base_details SET sitename = ?, address = ?, latitude = ?, longitude = ?, email = ? WHERE id = ?",
    [
      req.body.sitename,
      req.body.address,
      req.body.latitude,
      req.body.longitude,
      req.body.email,
      req.body.id,
    ],
    (err, result) => {
      if (err) {
        console.log(err);
        res.send({ status: "ERROR", message: err.message });
      } else {
        console.log("base_details is updated");
        console.log(result.affectedRows + " record(s) updated");
        res.send({ status: "OK" });
      }
    }
  );
});

app.post("/review/create", (req, res) => {
  db.query(
    "INSERT INTO reviews (profile_url, name, review_text, review_description) VALUES (?, ?, ?, ?)",
    [
      req.body.profileUrl,
      req.body.name,
      req.body.reviewText,
      req.body.reviewDescription,
    ],
    (err, result) => {
      if (err) {
        console.log(err);
        res.send({ status: "ERROR", message: err.message });
      } else {
        console.log("review inserted: ", result.insertId);
        res.send({ status: "OK", insertId: result.insertId });
      }
    }
  );
});

app.get("/api/reviews", (req, res) => {
  db.query(
    "SELECT id, profile_url, name, review_text, review_description FROM reviews WHERE is_active = 1 AND is_delete = 0",
    (err, result) => {
      if (err) {
        console.log(err);
      } else {
        res.send(result);
      }
    }
  );
});

app.put("/review/update", (req, res) => {
  db.query(
    "UPDATE reviews SET name = ?, review_text = ?, review_description = ?, profile_url = ? WHERE id = ?",
    [
      req.body.name,
      req.body.reviewText,
      req.body.reviewDescription,
      req.body.profileUrl,
      req.body.id,
    ],
    (err, result) => {
      if (err) {
        console.log(err);
        res.send({ status: "ERROR", message: err.message });
      } else {
        console.log("review updated");
        console.log(result.affectedRows + " record(s) updated");
        res.send({ status: "OK" });
      }
    }
  );
});

app.delete("/review/delete/:id", (req, res) => {
  const id = req.params.id;
  db.query(
    "UPDATE reviews SET is_delete = 1 WHERE id = ?",
    id,
    (err, result) => {
      if (err) {
        console.log(err);
        res.send({ status: "ERROR", message: err.message });
      } else {
        console.log("review deleted");
        console.log(result.affectedRows + " record(s) updated");
        res.send({ status: "OK" });
      }
    }
  );
});

app.post("/contact/create", (req, res) => {
  (async () => {
    try {
      let car_spec_id = await getBrandId(req.body);
      if (!car_spec_id) {
        car_spec_id = await insertBrand(req.body);
      }

      let insertSuccess = await insertCarContacts({ ...req.body, car_spec_id });
      if (insertSuccess) {
        res.send({
          status: "OK",
        });

        contactSentMail(req.body);
      } else {
        res.send({
          status: "ERROR",
        });
      }
    } catch (err) {
      console.error(err);
      res.send(err);
    }
  })();
});

const contactSentMail = (body) => {
  db.query(
    "SELECT id, email FROM base_details WHERE is_active = 1 AND is_delete = 0",
    (err, result) => {
      if (err) {
        console.log(err);
      } else {
        if (result.length && result[0].email) {
          console.log("Sending mail...");
          const mail = {
            to: result[0].email,
            subject: "มีรายการคำขอประเมินราคาเข้ามาใหม่",
            html: `
          <h4>รายละเอียดคำขอประเมินราคา:</h4>
          <p>ยี่ห้อรถยนต์: ${body.brand}</p>
          <p>รุ่นรถยนต์: ${body.model}</p>
          <p>เบอรโทรศัพท์: ${body.telephoneNumber}</p>
          <br />
          <a href="${process.env.PATH_ADMIN}">คลิกที่นี่เพื่อไปยังหน้าติดต่อเรา</a>
          `,
          };
          sentMail(mail.to, mail.subject, mail.html);
        } else {
          console.log("Cannot sent mail, please set the email before!");
        }
      }
    }
  );
};

const insertCarContacts = (data) => {
  return new Promise((resolve, reject) => {
    db.query(
      "INSERT INTO car_contacts (car_spec_id, telephone_number) VALUES (?, ?)",
      [data.car_spec_id, data.telephoneNumber],
      (err, result) => {
        if (err) reject(err);
        else {
          console.log("car_contacts inserted: ", result.insertId);
          resolve(true);
        }
      }
    );
  });
};

const insertBrand = (data) => {
  return new Promise((resolve, reject) => {
    db.query(
      "INSERT INTO car_specs (brand, model) VALUES (?, ?)",
      [data.brand, data.model],
      (err, result) => {
        if (err) reject(err);
        else {
          console.log("car_specs inserted: ", result.insertId);
          resolve(result.insertId);
        }
      }
    );
  });
};

const getBrandId = (data) => {
  return new Promise((resolve, reject) => {
    db.query(
      `SELECT id, brand, model FROM car_specs WHERE brand LIKE '${data.brand}' AND model LIKE '${data.model}' AND is_active = 1 AND is_delete = 0`,
      (err, result) => {
        if (err) reject(err);
        else {
          if (result.length) resolve(result[0].id);
          else resolve(0);
        }
      }
    );
  });
};

app.get("/api/carspec/brands", (req, res) => {
  db.query(
    "SELECT id, brand, model FROM car_specs WHERE is_active = 1 AND is_delete = 0 GROUP BY brand ORDER BY brand",
    (err, result) => {
      if (err) {
        console.log(err);
      } else {
        res.send(result);
      }
    }
  );
});

app.post("/carspec/models", (req, res) => {
  const brandName = req.body.brandName;
  db.query(
    "SELECT id, brand, model FROM car_specs WHERE brand LIKE ? AND is_active = 1 AND is_delete = 0 ORDER BY model",
    [brandName],
    (err, result) => {
      if (err) {
        console.log(err);
      } else {
        res.send(result);
      }
    }
  );
});

app.get("/api/contacts", (req, res) => {
  db.query(
    `SELECT car_contacts.id, car_contacts.telephone_number, car_contacts.status_id, car_contacts.created_at, 
    car_contacts.updated_at, car_specs.brand, car_specs.model, contact_statuses.name as status 
    FROM car_contacts 
    INNER JOIN car_specs ON car_contacts.car_spec_id = car_specs.id 
    INNER JOIN contact_statuses ON car_contacts.status_id = contact_statuses.id 
    WHERE car_contacts.is_active = 1 AND car_contacts.is_delete = 0 
    ORDER BY car_contacts.id DESC`,
    (err, result) => {
      if (err) {
        console.log(err);
      } else {
        res.send(result);
      }
    }
  );
});

app.put("/contact/status/update", (req, res) => {
  db.query(
    "UPDATE car_contacts SET status_id = ? WHERE id = ?",
    [req.body.statusId, req.body.contactId],
    (err, result) => {
      if (err) {
        console.log(err);
        res.send({ status: "ERROR", message: err.message });
      } else {
        console.log("car_contacts updated");
        console.log(result.affectedRows + " record(s) updated");
        res.send({ status: "OK" });
      }
    }
  );
});

app.get("/api/contact/statuses", (req, res) => {
  db.query(
    "SELECT id, name FROM contact_statuses WHERE is_active = 1 AND is_delete = 0",
    (err, result) => {
      if (err) {
        console.log(err);
      } else {
        res.send(result);
      }
    }
  );
});

app.delete("/contact/delete/:id", (req, res) => {
  const id = req.params.id;
  db.query(
    "UPDATE car_contacts SET is_delete = 1 WHERE id = ?",
    id,
    (err, result) => {
      if (err) {
        console.log(err);
        res.send({ status: "ERROR", message: err.message });
      } else {
        console.log("car_contacts deleted");
        console.log(result.affectedRows + " record(s) updated");
        res.send({ status: "OK" });
      }
    }
  );
});

const port = process.env.PORT || 8080;

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
