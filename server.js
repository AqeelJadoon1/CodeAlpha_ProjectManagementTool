const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const db = require("./db");

const app = express();
const server = http.createServer(app);
const io = new Server(server);
const PORT = 3000;

app.use(express.json());
app.use(
  session({
    secret: "change-this-to-a-long-random-string",
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 1000 * 60 * 60 * 24 * 7 },
  }),
);
app.use(express.static("public"));

function requireLogin(req, res, next) {
  if (!req.session.userId)
    return res.status(401).json({ error: "Please log in" });
  next();
}

function getRole(projectId, userId) {
  const row = db
    .prepare(
      "SELECT role FROM project_members WHERE project_id = ? AND user_id = ?",
    )
    .get(projectId, userId);
  return row ? row.role : null;
}

function getUserName(userId) {
  const row = db.prepare("SELECT name FROM users WHERE id = ?").get(userId);
  return row ? row.name : "Someone";
}

function requireRole(allowedRoles) {
  return (req, res, next) => {
    const role = getRole(req.params.id, req.session.userId);
    if (!role)
      return res.status(403).json({ error: "Not a member of this project" });
    if (!allowedRoles.includes(role)) {
      return res
        .status(403)
        .json({ error: "You do not have permission to do this" });
    }
    req.projectRole = role;
    next();
  };
}

// ---------- REAL-TIME (Socket.io) ----------
io.on("connection", (socket) => {
  socket.on("join-project", (projectId) => {
    socket.join("project-" + projectId);
  });
});

function broadcastBoardUpdate(projectId, message) {
  io.to("project-" + projectId).emit("board-updated", { message });
}

// ---------- AUTH ----------
app.post("/api/register", (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) {
    return res
      .status(400)
      .json({ error: "Name, email and password are required" });
  }
  if (password.length < 6) {
    return res
      .status(400)
      .json({ error: "Password must be at least 6 characters" });
  }
  const existing = db
    .prepare("SELECT id FROM users WHERE email = ?")
    .get(email);
  if (existing)
    return res.status(400).json({ error: "That email is already registered" });

  const hash = bcrypt.hashSync(password, 10);
  const result = db
    .prepare("INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)")
    .run(name, email, hash);

  req.session.userId = result.lastInsertRowid;
  res.json({ id: result.lastInsertRowid, name, email });
});

app.post("/api/login", (req, res) => {
  const { email, password } = req.body;
  const user = db.prepare("SELECT * FROM users WHERE email = ?").get(email);
  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({ error: "Wrong email or password" });
  }
  req.session.userId = user.id;
  res.json({ id: user.id, name: user.name, email: user.email });
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get("/api/me", (req, res) => {
  if (!req.session.userId) return res.json(null);
  const user = db
    .prepare("SELECT id, name, email FROM users WHERE id = ?")
    .get(req.session.userId);
  res.json(user || null);
});

app.get("/api/users/lookup", requireLogin, (req, res) => {
  const user = db
    .prepare("SELECT id, name, email FROM users WHERE email = ?")
    .get(req.query.email);
  res.json(user || null);
});

// ---------- PROJECTS ----------
app.post("/api/projects", requireLogin, (req, res) => {
  const { name, description } = req.body;
  if (!name || !name.trim())
    return res.status(400).json({ error: "Project name is required" });

  const createProject = db.transaction(() => {
    const project = db
      .prepare(
        "INSERT INTO projects (name, description, owner_id) VALUES (?, ?, ?)",
      )
      .run(name.trim(), description || "", req.session.userId);

    db.prepare(
      "INSERT INTO project_members (project_id, user_id, role) VALUES (?, ?, ?)",
    ).run(project.lastInsertRowid, req.session.userId, "owner");

    return project.lastInsertRowid;
  });

  res.json({ id: createProject() });
});

app.get("/api/projects", requireLogin, (req, res) => {
  const projects = db
    .prepare(
      `
    SELECT projects.id, projects.name, projects.description,
           project_members.role,
           (SELECT COUNT(*) FROM tasks WHERE tasks.project_id = projects.id) AS task_count
    FROM projects
    JOIN project_members ON project_members.project_id = projects.id
    WHERE project_members.user_id = ?
    ORDER BY projects.created_at DESC
  `,
    )
    .all(req.session.userId);
  res.json(projects);
});

app.get("/api/projects/:id", requireLogin, (req, res) => {
  const role = getRole(req.params.id, req.session.userId);
  if (!role)
    return res.status(403).json({ error: "Not a member of this project" });

  const project = db
    .prepare("SELECT * FROM projects WHERE id = ?")
    .get(req.params.id);
  const members = db
    .prepare(
      `
    SELECT users.id, users.name, users.email, project_members.role
    FROM project_members
    JOIN users ON users.id = project_members.user_id
    WHERE project_members.project_id = ?
  `,
    )
    .all(req.params.id);

  res.json({ ...project, myRole: role, members });
});

app.post(
  "/api/projects/:id/members",
  requireRole(["owner", "admin"]),
  (req, res) => {
    const { userId, role } = req.body;
    const targetUser = db
      .prepare("SELECT id FROM users WHERE id = ?")
      .get(userId);
    if (!targetUser) return res.status(404).json({ error: "User not found" });

    db.prepare(
      "INSERT OR IGNORE INTO project_members (project_id, user_id, role) VALUES (?, ?, ?)",
    ).run(req.params.id, userId, role === "admin" ? "admin" : "member");
    res.json({ ok: true });
  },
);

app.delete(
  "/api/projects/:id/members/:userId",
  requireRole(["owner", "admin"]),
  (req, res) => {
    const targetRole = getRole(req.params.id, req.params.userId);
    if (targetRole === "owner") {
      return res.status(400).json({ error: "Can't remove the project owner" });
    }
    db.prepare(
      "DELETE FROM project_members WHERE project_id = ? AND user_id = ?",
    ).run(req.params.id, req.params.userId);
    res.json({ ok: true });
  },
);

// ---------- TASKS ----------
app.post("/api/projects/:id/tasks", requireLogin, (req, res) => {
  const role = getRole(req.params.id, req.session.userId);
  if (!role)
    return res.status(403).json({ error: "Not a member of this project" });

  const { title, description, assigneeIds } = req.body;
  if (!title || !title.trim())
    return res.status(400).json({ error: "Task title is required" });

  const createTask = db.transaction(() => {
    const task = db
      .prepare(
        `
      INSERT INTO tasks (project_id, title, description, created_by)
      VALUES (?, ?, ?, ?)
    `,
      )
      .run(req.params.id, title.trim(), description || "", req.session.userId);

    const assignStmt = db.prepare(
      "INSERT OR IGNORE INTO task_assignees (task_id, user_id) VALUES (?, ?)",
    );
    (assigneeIds || []).forEach((userId) => {
      if (getRole(req.params.id, userId)) {
        assignStmt.run(task.lastInsertRowid, userId);
      }
    });

    return task.lastInsertRowid;
  });

  const newId = createTask();
  broadcastBoardUpdate(
    req.params.id,
    `${getUserName(req.session.userId)} created "${title.trim()}"`,
  );
  res.json({ id: newId });
});

app.get("/api/projects/:id/tasks", requireLogin, (req, res) => {
  const role = getRole(req.params.id, req.session.userId);
  if (!role)
    return res.status(403).json({ error: "Not a member of this project" });

  const tasks = db
    .prepare(
      `
    SELECT tasks.id, tasks.title, tasks.description, tasks.status, tasks.created_at,
           (SELECT COUNT(*) FROM task_comments WHERE task_comments.task_id = tasks.id) AS comment_count
    FROM tasks
    WHERE tasks.project_id = ?
    ORDER BY tasks.created_at DESC
  `,
    )
    .all(req.params.id);

  const getAssignees = db.prepare(`
    SELECT users.id, users.name FROM task_assignees
    JOIN users ON users.id = task_assignees.user_id
    WHERE task_assignees.task_id = ?
  `);
  tasks.forEach((task) => {
    task.assignees = getAssignees.all(task.id);
  });

  res.json(tasks);
});

app.patch("/api/tasks/:id/status", requireLogin, (req, res) => {
  const { status } = req.body;
  if (!["todo", "in_progress", "done"].includes(status)) {
    return res.status(400).json({ error: "Invalid status" });
  }

  const task = db
    .prepare("SELECT * FROM tasks WHERE id = ?")
    .get(req.params.id);
  if (!task) return res.status(404).json({ error: "Task not found" });

  const role = getRole(task.project_id, req.session.userId);
  if (!role)
    return res.status(403).json({ error: "Not a member of this project" });

  db.prepare("UPDATE tasks SET status = ? WHERE id = ?").run(
    status,
    req.params.id,
  );
  broadcastBoardUpdate(
    task.project_id,
    `${getUserName(req.session.userId)} moved "${task.title}" to ${status.replace("_", " ")}`,
  );
  res.json({ ok: true });
});

// ---------- TASK COMMENTS ----------
app.post("/api/tasks/:id/comments", requireLogin, (req, res) => {
  const { content } = req.body;
  if (!content || !content.trim())
    return res.status(400).json({ error: "Comment cannot be empty" });

  const task = db
    .prepare("SELECT * FROM tasks WHERE id = ?")
    .get(req.params.id);
  if (!task) return res.status(404).json({ error: "Task not found" });

  const role = getRole(task.project_id, req.session.userId);
  if (!role)
    return res.status(403).json({ error: "Not a member of this project" });

  const result = db
    .prepare(
      "INSERT INTO task_comments (task_id, user_id, content) VALUES (?, ?, ?)",
    )
    .run(req.params.id, req.session.userId, content.trim());

  broadcastBoardUpdate(
    task.project_id,
    `${getUserName(req.session.userId)} commented on "${task.title}"`,
  );
  res.json({ id: result.lastInsertRowid });
});

app.get("/api/tasks/:id/comments", requireLogin, (req, res) => {
  const comments = db
    .prepare(
      `
    SELECT task_comments.id, task_comments.content, task_comments.created_at,
           users.name AS author_name
    FROM task_comments
    JOIN users ON users.id = task_comments.user_id
    WHERE task_comments.task_id = ?
    ORDER BY task_comments.created_at ASC
  `,
    )
    .all(req.params.id);
  res.json(comments);
});

server.listen(PORT, () => {
  console.log(`Project tool running at http://localhost:${PORT}`);
});
