const { Pool } = require("pg");

const pool = new Pool({

user: "postgres",
host: "localhost",
database: "PhishProof",
password: "Birtamode",
port: 5433,

});

module.exports = pool;
