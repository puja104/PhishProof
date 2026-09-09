const express = require("express");
const session = require("express-session");
const bcrypt = require("bcrypt");
const cors = require("cors");
const pool = require("./db");

const app = express();

// MIDDLEWARE
app.use(express.json());

app.use(cors({
    origin: ["http://127.0.0.1:5500", "http://localhost:5500"],
    credentials: true
}));

app.use(session({
    secret: "supersecret",
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: false,
        sameSite: "lax"
    }
}));

// AUTH MIDDLEWARE
function isAuthenticated(req, res, next) {
    if (!req.session.user_id)
        return res.status(401).send("Not logged in");
    next();
}

function isAdmin(req, res, next) {
    if (req.session.role !== 'admin')
        return res.status(403).json({ error: "Admin access required" });
    next();
}

// REGISTER
app.post("/register", async (req, res) => {
    try {
        const { username, first_name, last_name, phone, email, password } = req.body;
        const hash = await bcrypt.hash(password, 10);

        await pool.query(`
            INSERT INTO users
            (username, first_name, last_name, phone, email, password_hash)
            VALUES ($1,$2,$3,$4,$5,$6)
        `, [username, first_name, last_name, phone, email, hash]);

        res.send("Registered successfully");
    } catch(err) {
        console.log(err);
        res.status(500).send("Registration failed");
    }
});

// LOGIN
app.post("/login", async (req, res) => {
    try{
        const { email, password } = req.body;
        const result = await pool.query(
            "SELECT * FROM users WHERE email=$1",
            [email]
        );

        if(result.rows.length === 0)
            return res.status(400).json({ message: "User not found" });

        const user = result.rows[0];
        const valid = await bcrypt.compare(password, user.password_hash);

        if(!valid)
            return res.status(400).json({ message: "Wrong password" });

        req.session.user_id = user.user_id;
        req.session.role = user.role || 'user';
        res.json({ message: "Login success", has_avatar: !!user.avatar, role: user.role || 'user' });
    } catch(err){
        console.log(err);
        res.status(500).json({ message: "Login failed" });
    }
});

// GET CURRENT USER + DASHBOARD STATS + SCENARIO PROGRESS
app.get("/me", isAuthenticated, async (req, res) => {
    try {
        const user_id = req.session.user_id;

        // User info
        const userResult = await pool.query(
            "SELECT user_id, username, first_name, avatar FROM users WHERE user_id=$1",
            [user_id]
        );
        const user = userResult.rows[0];
        if (typeof user.avatar === "string") user.avatar = JSON.parse(user.avatar);

        // ── PHISHING STATS ──
        const phishStatsResult = await pool.query(
            `SELECT COUNT(*) AS total_attempts,
                    COUNT(*) FILTER (WHERE is_correct = TRUE) AS correct_attempts,
                    COALESCE(SUM(points), 0) AS total_points
             FROM attempts WHERE user_id=$1`,
            [user_id]
        );
        const phishStats = phishStatsResult.rows[0];
        const phish_attempts = parseInt(phishStats.total_attempts) || 0;
        const phish_correct = parseInt(phishStats.correct_attempts) || 0;
        const phish_points = parseInt(phishStats.total_points) || 0;

        // ── SMISHING STATS ──
        const smishStatsResult = await pool.query(
            `SELECT COUNT(*) AS total_attempts,
                    COUNT(*) FILTER (WHERE is_correct = TRUE) AS correct_attempts,
                    COALESCE(SUM(points), 0) AS total_points
             FROM smishing_attempts WHERE user_id=$1`,
            [user_id]
        );
        const smishStats = smishStatsResult.rows[0];
        const smish_attempts = parseInt(smishStats.total_attempts) || 0;
        const smish_correct = parseInt(smishStats.correct_attempts) || 0;
        const smish_points = parseInt(smishStats.total_points) || 0;

        // ── COMBINED STATS ──
        const total_attempts = phish_attempts + smish_attempts;
        const correct_attempts = phish_correct + smish_correct;
        const total_points = phish_points + smish_points;
        const score = total_attempts > 0 ? Math.round((correct_attempts / total_attempts) * 100) : 0;

        // ── PHISHING MASTERY ──
        const allPhishTypesResult = await pool.query(
            `SELECT DISTINCT phishing_type FROM scenarios WHERE is_active = TRUE AND phishing_type IS NOT NULL AND phishing_type != 'safe'`
        );
        const allPhishTypes = allPhishTypesResult.rows.map(r => r.phishing_type);

        const phishMasteryResult = await pool.query(
            `SELECT s.phishing_type, s.difficulty_level
             FROM attempts a
             JOIN scenarios s ON s.scenario_id = a.scenario_id
             WHERE a.user_id = $1 AND a.is_correct = TRUE AND s.phishing_type IS NOT NULL AND s.phishing_type != 'safe'
             GROUP BY s.phishing_type, s.difficulty_level`,
            [user_id]
        );
        const phishMasteryMap = {};
        phishMasteryResult.rows.forEach(r => {
            if (!phishMasteryMap[r.phishing_type]) phishMasteryMap[r.phishing_type] = {};
            phishMasteryMap[r.phishing_type][r.difficulty_level] = true;
        });
        const phishMastery = allPhishTypes.map(t => {
            const m = phishMasteryMap[t] || {};
            const passedCount = (m.easy ? 1 : 0) + (m.medium ? 1 : 0) + (m.hard ? 1 : 0);
            return {
                category: t,
                type: "phishing",
                easy_passed: m.easy || false,
                medium_passed: m.medium || false,
                hard_passed: m.hard || false,
                passed: passedCount,
                required: 3,
                mastered: passedCount === 3
            };
        });

        // ── SMISHING MASTERY ──
        const allSmishTypesResult = await pool.query(
            `SELECT DISTINCT smishing_type FROM smishing_scenarios WHERE smishing_type IS NOT NULL`
        );
        const allSmishTypes = allSmishTypesResult.rows.map(r => r.smishing_type);

        const smishMasteryResult = await pool.query(
            `SELECT ss.smishing_type, ss.difficulty_level
             FROM smishing_attempts sa
             JOIN smishing_scenarios ss ON ss.id = sa.scenario_id
             WHERE sa.user_id = $1 AND sa.is_correct = TRUE
             GROUP BY ss.smishing_type, ss.difficulty_level`,
            [user_id]
        );
        const smishMasteryMap = {};
        smishMasteryResult.rows.forEach(r => {
            if (!smishMasteryMap[r.smishing_type]) smishMasteryMap[r.smishing_type] = {};
            smishMasteryMap[r.smishing_type][r.difficulty_level] = true;
        });
        const smishMastery = allSmishTypes.map(t => {
            const m = smishMasteryMap[t] || {};
            const passedCount = (m.easy ? 1 : 0) + (m.medium ? 1 : 0) + (m.hard ? 1 : 0);
            return {
                category: t,
                type: "smishing",
                easy_passed: m.easy || false,
                medium_passed: m.medium || false,
                hard_passed: m.hard || false,
                passed: passedCount,
                required: 3,
                mastered: passedCount === 3
            };
        });

        // ── COMBINED MASTERY ──
        const mastery = [...phishMastery, ...smishMastery];
        const totalCategories = mastery.length;
        const masteredCount = mastery.filter(m => m.mastered).length;
        const trainingComplete = masteredCount === totalCategories;

        res.json({
            ...user,
            total_attempts,
            correct_attempts,
            total_points,
            score,
            risk: score >= 80 ? "Low" : score >= 50 ? "Medium" : "High",
            mastery,
            mastered_count: masteredCount,
            total_categories: totalCategories,
            training_complete: trainingComplete
        });
    } catch(err) {
        console.log(err);
        res.status(500).send("Failed to load user info");
    }
});

// ── CATEGORY-BASED SCENARIO SELECTION ──
// User picks a category → gets easy, then medium, then hard.
// If they get one wrong, they get another of that difficulty before moving on.
// Category is "mastered" when they pass easy + medium + hard.
// ?category=urgency&difficulty=easy
app.get("/scenario/next", isAuthenticated, async (req, res) => {
  try {
    const user_id = req.session.user_id;
    const category = req.query.category;
    const difficulty = req.query.difficulty;

    if (!category || !difficulty) {
      return res.status(400).json({ error: "category and difficulty are required" });
    }

    // Fetch scenario for this category + difficulty
    // Includes both phishing scenarios of this type AND safe emails assigned to this category
    const result = await pool.query(
      `SELECT s.scenario_id, s.title, s.email_subject, s.sender_name, s.sender_email,
              s.email_body, s.is_phishing, s.indicators, s.difficulty_level, s.phishing_type,
              s.feedback, s.points_value
       FROM scenarios s
       WHERE s.is_active = TRUE
         AND s.phishing_type = $2
         AND s.difficulty_level = $3
         AND s.scenario_id NOT IN (
           SELECT a.scenario_id FROM attempts a
           WHERE a.user_id = $1 AND a.is_correct = TRUE
         )
       ORDER BY RANDOM()
       LIMIT 1`,
      [user_id, category, difficulty]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: "No scenarios available for this category/difficulty" });
    }

    const scenario = result.rows[0];
    if (typeof scenario.indicators === "string") {
      scenario.indicators = JSON.parse(scenario.indicators);
    }
    if (!scenario.indicators) scenario.indicators = [];

    console.log(`[scenario/next] user=${user_id}, category=${category}, difficulty=${difficulty}, scenario_id=${scenario.scenario_id}`);

    res.json(scenario);
  } catch (err) {
    console.error("[scenario/next] ERROR:", err);
    res.status(500).send("Server error");
  }
});


// ── GET CATEGORY PROGRESS for a specific category ──
// Returns which difficulties the user has passed for this category
app.get("/category/progress", isAuthenticated, async (req, res) => {
  try {
    const user_id = req.session.user_id;
    const category = req.query.category;

    if (!category) return res.status(400).json({ error: "category is required" });

    // Check which difficulties user has gotten correct for this category
    const progressResult = await pool.query(
      `SELECT s.difficulty_level,
              COUNT(DISTINCT a.scenario_id) AS correct_count
       FROM attempts a
       JOIN scenarios s ON s.scenario_id = a.scenario_id
       WHERE a.user_id = $1 AND a.is_correct = TRUE AND s.phishing_type = $2
       GROUP BY s.difficulty_level`,
      [user_id, category]
    );

    const passed = {};
    progressResult.rows.forEach(r => {
      passed[r.difficulty_level] = parseInt(r.correct_count) > 0;
    });

    res.json({
      category,
      easy_passed: passed.easy || false,
      medium_passed: passed.medium || false,
      hard_passed: passed.hard || false,
      mastered: (passed.easy || false) && (passed.medium || false) && (passed.hard || false)
    });
  } catch (err) {
    console.error(err);
    res.status(500).send("Server error");
  }
});

// SUBMIT SCENARIO ATTEMPT — difficulty-scaled scoring
app.post("/scenario/submit", isAuthenticated, async (req, res) => {
  try {
    const { scenario_id, selected_indicators, time_spent, user_answer } = req.body;
    const user_id = req.session.user_id;

    const scenarioResult = await pool.query(
      "SELECT indicators, is_phishing, feedback, difficulty_level, points_value FROM scenarios WHERE scenario_id = $1",
      [scenario_id]
    );

    if (scenarioResult.rows.length === 0)
      return res.status(404).send("Scenario not found");

    const scenario = scenarioResult.rows[0];
    let correctIndicators = scenario.indicators;
    if (typeof correctIndicators === "string")
      correctIndicators = JSON.parse(correctIndicators);
    if (!correctIndicators) correctIndicators = [];

    const is_correct = user_answer === scenario.is_phishing;
    const safeSelectedIndicators = selected_indicators || [];

    const correctFound = safeSelectedIndicators.filter(ind =>
      correctIndicators.some(ci => ci.toLowerCase() === ind.toLowerCase())
    );
    const indicatorScore = correctIndicators.length > 0
      ? Math.round((correctFound.length / correctIndicators.length) * 100)
      : 0;

    // ── DIFFICULTY-SCALED POINTS ──
    const difficulty = scenario.difficulty_level || "medium";

    // Multipliers based on difficulty
    const difficultyConfig = {
      easy:   { verdict: 30,  indicator: 5,  speedFast: 10, speedMed: 5,  firstTry: 10 },
      medium: { verdict: 50,  indicator: 10, speedFast: 20, speedMed: 10, firstTry: 25 },
      hard:   { verdict: 80,  indicator: 15, speedFast: 30, speedMed: 15, firstTry: 40 }
    };
    const cfg = difficultyConfig[difficulty] || difficultyConfig.medium;

    let points = 0;
    let pointsBreakdown = [];

    if (is_correct) {
      // Correct verdict
      points += cfg.verdict;
      pointsBreakdown.push({ label: "Correct verdict", pts: cfg.verdict });

      // Indicator points
      if (correctFound.length > 0) {
        const indicatorPts = correctFound.length * cfg.indicator;
        points += indicatorPts;
        pointsBreakdown.push({ label: `${correctFound.length} indicator(s) found`, pts: indicatorPts });
      }

      // Speed bonus
      if (time_spent <= 60) {
        points += cfg.speedFast;
        pointsBreakdown.push({ label: "Speed bonus (under 60s)", pts: cfg.speedFast });
      } else if (time_spent <= 120) {
        points += cfg.speedMed;
        pointsBreakdown.push({ label: "Speed bonus (under 2 min)", pts: cfg.speedMed });
      }

      // First try bonus
      const prevAttempts = await pool.query(
        "SELECT COUNT(*) AS cnt FROM attempts WHERE user_id=$1 AND scenario_id=$2",
        [user_id, scenario_id]
      );
      if (parseInt(prevAttempts.rows[0].cnt) === 0) {
        points += cfg.firstTry;
        pointsBreakdown.push({ label: "First try bonus", pts: cfg.firstTry });
      }
    } else {
      pointsBreakdown.push({ label: "Incorrect verdict", pts: 0 });
    }

    // Record attempt
    await pool.query(
      `INSERT INTO attempts (user_id, scenario_id, user_answer, is_correct, indicators_selected, time_spent, points)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [user_id, scenario_id, user_answer, is_correct, JSON.stringify(safeSelectedIndicators), time_spent, points]
    );

    res.json({
      score: indicatorScore,
      points,
      points_breakdown: pointsBreakdown,
      difficulty,
      is_correct,
      is_phishing: scenario.is_phishing,
      total_indicators: correctIndicators.length,
      found: correctFound.length,
      missed: correctIndicators.filter(ci =>
        !safeSelectedIndicators.some(si => si.toLowerCase() === ci.toLowerCase())
      ),
      feedback: scenario.feedback
    });
  } catch (err) {
    console.error("[submit] ERROR:", err);
    res.status(500).json({ error: err.message });
  }
});


// CREATE SCENARIO (inserts directly into scenarios table)
app.post("/scenario/create", isAuthenticated, async (req, res) => {
  try {
    const { title, sender_name, sender_email, email_subject, email_body, is_phishing, phishing_type, difficulty_level, indicators, feedback } = req.body;

    if (!title || !sender_name || !sender_email || !email_subject || !email_body || is_phishing === undefined || !difficulty_level || !feedback) {
      return res.status(400).json({ error: "All fields are required." });
    }

    let indicatorsArray;
    try {
      indicatorsArray = JSON.parse(indicators);
      if (!Array.isArray(indicatorsArray)) throw new Error();
    } catch {
      return res.status(400).json({ error: "Indicators must be a valid JSON array, e.g. [\"word1\", \"word2\"]" });
    }

    const points_value = difficulty_level === "easy" ? 10 : difficulty_level === "medium" ? 20 : 30;

    const result = await pool.query(
      `INSERT INTO scenarios (title, sender_name, sender_email, email_subject, email_body, is_phishing, phishing_type, difficulty_level, indicators, feedback, points_value, is_active)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,TRUE) RETURNING scenario_id`,
      [title, sender_name, sender_email, email_subject, email_body, is_phishing, phishing_type || null, difficulty_level, JSON.stringify(indicatorsArray), feedback, points_value]
    );

    res.json({ success: true, scenario_id: result.rows[0].scenario_id });
  } catch (err) {
    console.error("[create scenario] ERROR:", err);
    res.status(500).json({ error: err.message });
  }
});

// ADMIN: Get all pending scenarios
app.get("/admin/pending", isAuthenticated, isAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT ps.*, u.first_name, u.last_name, u.username
       FROM pending_scenarios ps
       LEFT JOIN users u ON u.user_id = ps.submitted_by
       WHERE ps.status = 'pending'
       ORDER BY ps.created_at DESC`
    );
    res.json(result.rows);
  } catch (err) {
    console.error("[admin pending] ERROR:", err);
    res.status(500).json({ error: err.message });
  }
});

// ADMIN: Approve a pending scenario (move to scenarios table)
app.post("/admin/approve/:id", isAuthenticated, isAdmin, async (req, res) => {
  try {
    const { id } = req.params;

    const pending = await pool.query("SELECT * FROM pending_scenarios WHERE id=$1 AND status='pending'", [id]);
    if (pending.rows.length === 0) return res.status(404).json({ error: "Pending scenario not found" });

    const p = pending.rows[0];

    await pool.query(
      `INSERT INTO scenarios (title, sender_name, sender_email, email_subject, email_body, is_phishing, phishing_type, difficulty_level, indicators, feedback, points_value)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
      [p.title, p.sender_name, p.sender_email, p.email_subject, p.email_body, p.is_phishing, p.phishing_type, p.difficulty_level, p.indicators, p.feedback, p.points_value]
    );

    await pool.query("UPDATE pending_scenarios SET status='approved' WHERE id=$1", [id]);

    res.json({ success: true, message: "Scenario approved and added to database" });
  } catch (err) {
    console.error("[admin approve] ERROR:", err);
    res.status(500).json({ error: err.message });
  }
});

// ADMIN: Reject a pending scenario
app.post("/admin/reject/:id", isAuthenticated, isAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    await pool.query("UPDATE pending_scenarios SET status='rejected' WHERE id=$1 AND status='pending'", [id]);
    res.json({ success: true, message: "Scenario rejected" });
  } catch (err) {
    console.error("[admin reject] ERROR:", err);
    res.status(500).json({ error: err.message });
  }
});

// ADMIN: Create scenario directly (goes straight into scenarios table)
app.post("/admin/scenario/create", isAuthenticated, isAdmin, async (req, res) => {
  try {
    const { title, sender_name, sender_email, email_subject, email_body, is_phishing, phishing_type, difficulty_level, indicators, feedback } = req.body;

    if (!title || !sender_name || !sender_email || !email_subject || !email_body || is_phishing === undefined || !difficulty_level || !feedback) {
      return res.status(400).json({ error: "All fields are required." });
    }

    let indicatorsArray;
    try {
      indicatorsArray = JSON.parse(indicators);
      if (!Array.isArray(indicatorsArray)) throw new Error();
    } catch {
      return res.status(400).json({ error: "Indicators must be a valid JSON array." });
    }

    const points_value = difficulty_level === "easy" ? 10 : difficulty_level === "medium" ? 20 : 30;

    const result = await pool.query(
      `INSERT INTO scenarios (title, sender_name, sender_email, email_subject, email_body, is_phishing, phishing_type, difficulty_level, indicators, feedback, points_value)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING scenario_id`,
      [title, sender_name, sender_email, email_subject, email_body, is_phishing, phishing_type || null, difficulty_level, JSON.stringify(indicatorsArray), feedback, points_value]
    );

    res.json({ success: true, scenario_id: result.rows[0].scenario_id });
  } catch (err) {
    console.error("[admin create scenario] ERROR:", err);
    res.status(500).json({ error: err.message });
  }
});


// GET USER SETTINGS
app.get("/settings", isAuthenticated, async (req, res) => {
    try {
        const result = await pool.query(
            "SELECT first_name, last_name, email, phone FROM users WHERE user_id=$1",
            [req.session.user_id]
        );
        res.json(result.rows[0]);
    } catch (err) {
        console.error(err);
        res.status(500).send("Server error");
    }
});

// UPDATE PROFILE
app.post("/settings/profile", isAuthenticated, async (req, res) => {
    const { first_name, last_name, phone } = req.body;

    try {
        await pool.query(
            "UPDATE users SET first_name=$1, last_name=$2, phone=$3 WHERE user_id=$4",
            [first_name, last_name, phone, req.session.user_id]
        );
        res.json({ success: true });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false });
    }
});

// CHANGE PASSWORD
app.post("/settings/password", isAuthenticated, async (req, res) => {
    const { currentPassword, newPassword } = req.body;

    try {
        const result = await pool.query(
            "SELECT password_hash FROM users WHERE user_id=$1",
            [req.session.user_id]
        );
        const user = result.rows[0];

        const match = await bcrypt.compare(currentPassword, user.password_hash);
        if (!match) return res.status(400).json({ success: false, message: "Current password is incorrect" });

        const hashed = await bcrypt.hash(newPassword, 10);
        await pool.query(
            "UPDATE users SET password_hash=$1 WHERE user_id=$2",
            [hashed, req.session.user_id]
        );

        res.json({ success: true });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false });
    }
});

// LEADERBOARD
// Returns top employees ranked by total points, with accuracy and categories mastered
app.get("/leaderboard", isAuthenticated, async (req, res) => {
  try {
    const user_id = req.session.user_id;

    // Get all users with combined phishing + smishing stats
    const result = await pool.query(
      `SELECT
          u.user_id,
          u.first_name,
          u.last_name,
          u.username,
          u.avatar::text AS avatar,
          COALESCE(p.total_attempts, 0) + COALESCE(s.total_attempts, 0) AS total_attempts,
          COALESCE(p.correct_attempts, 0) + COALESCE(s.correct_attempts, 0) AS correct_attempts,
          COALESCE(p.total_points, 0) + COALESCE(s.total_points, 0) AS total_points
       FROM users u
       LEFT JOIN (
          SELECT user_id,
                 COUNT(*) AS total_attempts,
                 COUNT(*) FILTER (WHERE is_correct = TRUE) AS correct_attempts,
                 COALESCE(SUM(points), 0) AS total_points
          FROM attempts GROUP BY user_id
       ) p ON p.user_id = u.user_id
       LEFT JOIN (
          SELECT user_id,
                 COUNT(*) AS total_attempts,
                 COUNT(*) FILTER (WHERE is_correct = TRUE) AS correct_attempts,
                 COALESCE(SUM(points), 0) AS total_points
          FROM smishing_attempts GROUP BY user_id
       ) s ON s.user_id = u.user_id
       WHERE u.role != 'admin' OR u.role IS NULL
       ORDER BY (COALESCE(p.total_points, 0) + COALESCE(s.total_points, 0)) DESC`
    );

    // Phishing mastery per user
    const phishMasteryResult = await pool.query(
      `SELECT a.user_id, s.phishing_type, s.difficulty_level
       FROM attempts a
       JOIN scenarios s ON s.scenario_id = a.scenario_id
       WHERE a.is_correct = TRUE AND s.phishing_type IS NOT NULL
       GROUP BY a.user_id, s.phishing_type, s.difficulty_level`
    );

    // Smishing mastery per user
    const smishMasteryResult = await pool.query(
      `SELECT sa.user_id, ss.smishing_type, ss.difficulty_level
       FROM smishing_attempts sa
       JOIN smishing_scenarios ss ON ss.id = sa.scenario_id
       WHERE sa.is_correct = TRUE AND ss.smishing_type IS NOT NULL
       GROUP BY sa.user_id, ss.smishing_type, ss.difficulty_level`
    );

    // Build mastery map per user for phishing
    const userPhishMastery = {};
    phishMasteryResult.rows.forEach(r => {
      if (!userPhishMastery[r.user_id]) userPhishMastery[r.user_id] = {};
      if (!userPhishMastery[r.user_id][r.phishing_type]) userPhishMastery[r.user_id][r.phishing_type] = {};
      userPhishMastery[r.user_id][r.phishing_type][r.difficulty_level] = true;
    });

    // Build mastery map per user for smishing
    const userSmishMastery = {};
    smishMasteryResult.rows.forEach(r => {
      if (!userSmishMastery[r.user_id]) userSmishMastery[r.user_id] = {};
      if (!userSmishMastery[r.user_id][r.smishing_type]) userSmishMastery[r.user_id][r.smishing_type] = {};
      userSmishMastery[r.user_id][r.smishing_type][r.difficulty_level] = true;
    });

    // Count mastered categories per user (phishing + smishing combined)
    const leaderboard = result.rows.map((row, index) => {
      const totalAttempts = parseInt(row.total_attempts) || 0;
      const correctAttempts = parseInt(row.correct_attempts) || 0;
      const accuracy = totalAttempts > 0 ? Math.round((correctAttempts / totalAttempts) * 100) : 0;

      // Count phishing mastered
      const pm = userPhishMastery[row.user_id] || {};
      let masteredCount = 0;
      Object.keys(pm).forEach(type => {
        if (pm[type].easy && pm[type].medium && pm[type].hard) masteredCount++;
      });

      // Count smishing mastered
      const sm = userSmishMastery[row.user_id] || {};
      Object.keys(sm).forEach(type => {
        if (sm[type].easy && sm[type].medium && sm[type].hard) masteredCount++;
      });

      let avatar = row.avatar;
      if (typeof avatar === "string") try { avatar = JSON.parse(avatar); } catch(e) { avatar = null; }

      return {
        rank: index + 1,
        user_id: row.user_id,
        name: row.first_name && row.last_name
          ? row.first_name + " " + row.last_name
          : row.first_name || row.username || "User",
        avatar: avatar || null,
        total_points: parseInt(row.total_points) || 0,
        accuracy,
        total_attempts: totalAttempts,
        correct_attempts: correctAttempts,
        categories_mastered: masteredCount,
        is_you: row.user_id === user_id
      };
    });

    res.json(leaderboard);
  } catch (err) {
    console.error("[leaderboard] ERROR:", err);
    res.status(500).json({ error: err.message });
  }
});

// ── GET AVATAR ──
app.get("/avatar", isAuthenticated, async (req, res) => {
    try {
        const result = await pool.query(
            "SELECT avatar FROM users WHERE user_id=$1",
            [req.session.user_id]
        );
        res.json({ avatar: result.rows[0].avatar || null });
    } catch (err) {
        console.error(err);
        res.status(500).send("Server error");
    }
});

// ── SAVE AVATAR ──
app.post("/avatar", isAuthenticated, async (req, res) => {
    try {
        const { avatar } = req.body;
        await pool.query(
            "UPDATE users SET avatar=$1 WHERE user_id=$2",
            [JSON.stringify(avatar), req.session.user_id]
        );
        res.json({ success: true });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false });
    }
});


// ── AUTO-CREATE smishing_attempts TABLE ──
(async () => {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS smishing_attempts (
        attempt_id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(user_id),
        scenario_id INTEGER NOT NULL,
        user_answer BOOLEAN,
        is_correct BOOLEAN,
        indicators_selected TEXT DEFAULT '[]',
        time_spent INTEGER DEFAULT 0,
        points INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);
    console.log("smishing_attempts table ready");
  } catch (err) {
    console.error("Error creating smishing_attempts table:", err);
  }
})();

// ── SMISHING: Get user mastery (separate from phishing) ──
app.get("/me/smishing", isAuthenticated, async (req, res) => {
  try {
    const user_id = req.session.user_id;

    // Get all distinct smishing_type categories from smishing_scenarios
    const allTypesResult = await pool.query(
      `SELECT DISTINCT smishing_type FROM smishing_scenarios WHERE smishing_type IS NOT NULL`
    );
    const allCategories = allTypesResult.rows.map(r => r.smishing_type);

    // Get which difficulties user passed per smishing_type
    const masteryResult = await pool.query(
      `SELECT ss.smishing_type, ss.difficulty_level
       FROM smishing_attempts sa
       JOIN smishing_scenarios ss ON ss.id = sa.scenario_id
       WHERE sa.user_id = $1 AND sa.is_correct = TRUE
       GROUP BY ss.smishing_type, ss.difficulty_level`,
      [user_id]
    );

    const masteryMap = {};
    masteryResult.rows.forEach(r => {
      if (!masteryMap[r.smishing_type]) masteryMap[r.smishing_type] = {};
      masteryMap[r.smishing_type][r.difficulty_level] = true;
    });

    const mastery = allCategories.map(t => {
      const m = masteryMap[t] || {};
      const passedCount = (m.easy ? 1 : 0) + (m.medium ? 1 : 0) + (m.hard ? 1 : 0);
      return {
        category: t,
        easy_passed: m.easy || false,
        medium_passed: m.medium || false,
        hard_passed: m.hard || false,
        passed: passedCount,
        required: 3,
        mastered: passedCount === 3
      };
    });

    res.json({ mastery });
  } catch (err) {
    console.error("[me/smishing] ERROR:", err);
    res.status(500).send("Failed to load smishing mastery");
  }
});

// ── SMISHING: Get next scenario for a category + difficulty ──
app.get("/smishing/next", isAuthenticated, async (req, res) => {
  try {
    const user_id = req.session.user_id;
    const category = req.query.category;
    const difficulty = req.query.difficulty;

    if (!category || !difficulty) {
      return res.status(400).json({ error: "category and difficulty are required" });
    }

    // Try requested difficulty first, then fall back to any available difficulty
    let result = await pool.query(
      `SELECT *
       FROM smishing_scenarios
       WHERE smishing_type = $2
         AND difficulty_level = $3
         AND id NOT IN (
           SELECT sa.scenario_id FROM smishing_attempts sa
           WHERE sa.user_id = $1 AND sa.is_correct = TRUE
         )
       ORDER BY RANDOM()
       LIMIT 1`,
      [user_id, category, difficulty]
    );

    // Fallback: if no scenario at requested difficulty, try any difficulty for this category
    if (result.rows.length === 0) {
      result = await pool.query(
        `SELECT *
         FROM smishing_scenarios
         WHERE smishing_type = $2
           AND id NOT IN (
             SELECT sa.scenario_id FROM smishing_attempts sa
             WHERE sa.user_id = $1 AND sa.is_correct = TRUE
           )
         ORDER BY RANDOM()
         LIMIT 1`,
        [user_id, category]
      );
    }

    if (result.rows.length === 0) {
      return res.status(404).json({ message: "No scenarios available for this category" });
    }

    res.json(result.rows[0]);
  } catch (err) {
    console.error("[smishing/next] ERROR:", err);
    res.status(500).send("Server error");
  }
});

// ── SMISHING: Submit answer ──
app.post("/smishing/submit", isAuthenticated, async (req, res) => {
  try {
    const { scenario_id, user_answer, selected_indicators, time_spent } = req.body;
    const user_id = req.session.user_id;

    const scenarioResult = await pool.query(
      "SELECT * FROM smishing_scenarios WHERE id = $1",
      [scenario_id]
    );

    if (scenarioResult.rows.length === 0)
      return res.status(404).send("Scenario not found");

    const scenario = scenarioResult.rows[0];

    // Parse indicators
    let correctIndicators = scenario.indicators;
    if (typeof correctIndicators === "string")
      correctIndicators = JSON.parse(correctIndicators);
    if (!correctIndicators) correctIndicators = [];

    const is_correct = user_answer === scenario.is_smishing;
    const safeSelectedIndicators = selected_indicators || [];

    // Compare selected indicators with correct ones
    const correctFound = safeSelectedIndicators.filter(ind =>
      correctIndicators.some(ci => ci.toLowerCase() === ind.toLowerCase())
    );
    const indicatorScore = correctIndicators.length > 0
      ? Math.round((correctFound.length / correctIndicators.length) * 100)
      : 0;

    // Points calculation
    const difficulty = scenario.difficulty_level || "easy";
    const difficultyConfig = {
      easy:   { verdict: 30,  indicator: 5,  speedFast: 10, speedMed: 5,  firstTry: 10 },
      medium: { verdict: 50,  indicator: 10, speedFast: 20, speedMed: 10, firstTry: 25 },
      hard:   { verdict: 80,  indicator: 15, speedFast: 30, speedMed: 15, firstTry: 40 }
    };
    const cfg = difficultyConfig[difficulty] || difficultyConfig.easy;

    let points = 0;
    let pointsBreakdown = [];

    if (is_correct) {
      points += cfg.verdict;
      pointsBreakdown.push({ label: "Correct verdict", pts: cfg.verdict });

      // Indicator points
      if (correctFound.length > 0) {
        const indicatorPts = correctFound.length * cfg.indicator;
        points += indicatorPts;
        pointsBreakdown.push({ label: `${correctFound.length} indicator(s) found`, pts: indicatorPts });
      }

      if (time_spent <= 60) {
        points += cfg.speedFast;
        pointsBreakdown.push({ label: "Speed bonus (under 60s)", pts: cfg.speedFast });
      } else if (time_spent <= 120) {
        points += cfg.speedMed;
        pointsBreakdown.push({ label: "Speed bonus (under 2 min)", pts: cfg.speedMed });
      }

      const prevAttempts = await pool.query(
        "SELECT COUNT(*) AS cnt FROM smishing_attempts WHERE user_id=$1 AND scenario_id=$2",
        [user_id, scenario_id]
      );
      if (parseInt(prevAttempts.rows[0].cnt) === 0) {
        points += cfg.firstTry;
        pointsBreakdown.push({ label: "First try bonus", pts: cfg.firstTry });
      }
    } else {
      pointsBreakdown.push({ label: "Incorrect verdict", pts: 0 });
    }

    // Record attempt in smishing_attempts (NOT in attempts)
    await pool.query(
      `INSERT INTO smishing_attempts (user_id, scenario_id, user_answer, is_correct, indicators_selected, time_spent, points)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [user_id, scenario_id, user_answer, is_correct, JSON.stringify(safeSelectedIndicators), time_spent, points]
    );

    res.json({
      score: indicatorScore,
      is_correct,
      is_smishing: scenario.is_smishing,
      points,
      points_breakdown: pointsBreakdown,
      difficulty,
      total_indicators: correctIndicators.length,
      found: correctFound.length,
      missed: correctIndicators.filter(ci =>
        !safeSelectedIndicators.some(si => si.toLowerCase() === ci.toLowerCase())
      ),
      feedback: scenario.feedback || ""
    });
  } catch (err) {
    console.error("[smishing/submit] ERROR:", err);
    res.status(500).json({ error: err.message });
  }
});

// GET one smishing scenario by id
app.get("/smishing/:id", async (req, res) => {
  const { id } = req.params;

  const result = await pool.query(
    "SELECT * FROM smishing_scenarios WHERE id = $1",
    [id]
  );

  res.json(result.rows[0]);
});

// LOGOUT
app.get("/logout", (req, res) => {
    req.session.destroy();
    res.send("Logged out");
});

// START SERVER
app.listen(5000, () => {
    console.log("Server running on port 5000");
});
