import 'dotenv/config'
import express from 'express'
import cors from 'cors'
import Database from 'better-sqlite3'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'
import nodemailer from 'nodemailer'
import fs from 'fs'
import path from 'path'
import { fileURLToPath } from 'url'

// ============================================================
// CONFIG INICIAL
// ============================================================
const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

const app = express()
app.use(cors({ origin: "http://localhost:5173", credentials: true }))
app.use(express.json())

// ============================================================
// BANCO DE DADOS SQLITE UNIFICADO
// ============================================================
const DB_FILE = process.env.DB_FILE || './data/app.db'
const dataDir = path.resolve(__dirname, path.dirname(DB_FILE))
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true })

const db = new Database(DB_FILE)
db.pragma('journal_mode = WAL')

// ============================================================
// TABELAS
// ============================================================
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS transactions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  userId INTEGER NOT NULL,
  description TEXT NOT NULL,
  category TEXT,
  type TEXT CHECK (type IN ('income','expense')) NOT NULL,
  amount REAL NOT NULL,
  date TEXT NOT NULL,
  FOREIGN KEY(userId) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_trans_user ON transactions(userId);
CREATE INDEX IF NOT EXISTS idx_trans_date ON transactions(date);

CREATE TABLE IF NOT EXISTS tasks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  userId INTEGER NOT NULL,
  title TEXT NOT NULL,
  email TEXT NOT NULL,
  datetime TEXT NOT NULL,
  completed INTEGER DEFAULT 0,
  remind_minutes_before INTEGER DEFAULT 0,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY(userId) REFERENCES users(id)
);
`)

console.log("Banco SQLite carregado:", DB_FILE)

// ============================================================
// AUTH MIDDLEWARE
// ============================================================
function auth(req, res, next) {
  const header = req.headers.authorization
  if (!header) return res.status(401).json({ error: "Token ausente" })

  const token = header.split(" ")[1]
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || "segredo123")
    req.user = decoded
    next()
  } catch {
    res.status(401).json({ error: "Token inválido" })
  }
}

// ============================================================
// E-MAIL
// ============================================================
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT || 587),
  secure: false,
  auth: process.env.SMTP_USER ? {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS
  } : undefined
})

// ============================================================
// TASK SCHEDULER
// ============================================================
const timers = new Map()

function scheduleTask(row) {
  const base = new Date(row.datetime).getTime()
  const when = base - Number(row.remind_minutes_before || 0) * 60000
  const now = Date.now()
  const delay = when - now

  if (delay <= 0) return

  if (timers.has(row.id)) clearTimeout(timers.get(row.id))

  const t = setTimeout(async () => {
    try {
      if (!process.env.SMTP_HOST) return
      await transporter.sendMail({
        from: process.env.SMTP_FROM || process.env.SMTP_USER,
        to: row.email,
        subject: `Lembrete: ${row.title}`,
        text: `Sua tarefa está marcada para agora: ${row.datetime}`
      })
      timers.delete(row.id)
    } catch (err) {
      console.error("Erro ao enviar email:", err)
    }
  }, delay)

  timers.set(row.id, t)
}

// Recarrega tarefas pendentes no boot
db.prepare("SELECT * FROM tasks").all().forEach(scheduleTask)

// ============================================================
// ROTAS DE AUTENTICAÇÃO
// ============================================================

// REGISTER
app.post("/api/auth/register", (req, res) => {
  const { name, email, password } = req.body

  const exists = db.prepare("SELECT * FROM users WHERE email = ?").get(email)
  if (exists) return res.status(400).json({ error: "E-mail já registrado" })

  const hash = bcrypt.hashSync(password, 10)
  db.prepare(`
    INSERT INTO users (name, email, password)
    VALUES (?, ?, ?)
  `).run(name, email, hash)

  res.json({ message: "Usuário criado com sucesso" })
})

// LOGIN
app.post("/api/auth/login", (req, res) => {
  const { email, password } = req.body

  const user = db.prepare("SELECT * FROM users WHERE email = ?").get(email)
  if (!user) return res.status(401).json({ error: "Credenciais inválidas" })

  const ok = bcrypt.compareSync(password, user.password)
  if (!ok) return res.status(401).json({ error: "Credenciais inválidas" })

  const token = jwt.sign(
    { id: user.id },
    process.env.JWT_SECRET || "segredo123",
    { expiresIn: "7d" }
  )

  res.json({ token })
})

// ============================================================
// ROTAS: TRANSAÇÕES FINANCEIRAS (com userId)
// ============================================================

// LISTAR
app.get("/api/transactions", auth, (req, res) => {
  const rows = db.prepare(`
    SELECT * FROM transactions
    WHERE userId = ?
    ORDER BY date DESC, id DESC
  `).all(req.user.id)

  res.json(rows)
})

// CRIAR
app.post("/api/transactions", auth, (req, res) => {
  const { description, category, type, amount, date } = req.body

  if (!description || !category || !type || amount == null || !date)
    return res.status(400).json({ error: "Campos obrigatórios ausentes" })

  const info = db.prepare(`
    INSERT INTO transactions (userId, description, category, type, amount, date)
    VALUES (?,?,?,?,?,?)
  `).run(req.user.id, description, category, type, Number(amount), date)

  res.json(db.prepare("SELECT * FROM transactions WHERE id=?").get(info.lastInsertRowid))
})

// EDITAR
app.put("/api/transactions/:id", auth, (req, res) => {
  const id = Number(req.params.id)
  const p = req.body

  const row = db.prepare("SELECT * FROM transactions WHERE id=? AND userId=?")
                .get(id, req.user.id)
  if (!row) return res.status(404).json({ error: "Not found" })

  db.prepare(`
    UPDATE transactions SET description=?, category=?, type=?, amount=?, date=?
    WHERE id=? AND userId=?
  `).run(p.description, p.category, p.type, p.amount, p.date, id, req.user.id)

  res.json({ ok: true })
})

// REMOVER
app.delete("/api/transactions/:id", auth, (req, res) => {
  db.prepare("DELETE FROM transactions WHERE id=? AND userId=?")
     .run(req.params.id, req.user.id)

  res.json({ ok: true })
})

// RESUMO
app.get("/api/summary", auth, (req, res) => {
  const items = db.prepare("SELECT * FROM transactions WHERE userId = ?")
                  .all(req.user.id)

  const income = items.filter(i => i.type === "income").reduce((a, b) => a + b.amount, 0)
  const expense = items.filter(i => i.type === "expense").reduce((a, b) => a + b.amount, 0)

  res.json({
    income,
    expense,
    balance: income - expense
  })
})

// ============================================================
// ROTAS: TASKS (com userId)
// ============================================================

// LISTAR
app.get("/api/tasks", auth, (req, res) => {
  res.json(
    db.prepare("SELECT * FROM tasks WHERE userId=? ORDER BY datetime ASC")
      .all(req.user.id)
  )
})

// CRIAR
app.post("/api/tasks", auth, (req, res) => {
  const { title, email, datetime } = req.body

  if (!title || !email || !datetime)
    return res.status(400).json({ error: "Campos obrigatórios ausentes" })

  const info = db.prepare(`
    INSERT INTO tasks (userId, title, email, datetime, remind_minutes_before)
    VALUES (?,?,?,?,?)
  `).run(
    req.user.id,
    title,
    email,
    datetime,
    Number(req.body.remind_minutes_before || 0)
  )

  const row = db.prepare("SELECT * FROM tasks WHERE id=?").get(info.lastInsertRowid)
  scheduleTask(row)

  res.json(row)
})

// PATCH
app.patch("/api/tasks/:id", auth, (req, res) => {
  const id = Number(req.params.id)
  const row = db.prepare("SELECT * FROM tasks WHERE id=? AND userId=?")
                .get(id, req.user.id)

  if (!row) return res.status(404).json({ error: "Not found" })

  const allowed = ["title", "email", "datetime", "completed", "remind_minutes_before"]
  const patch = req.body
  const set = []
  const params = []

  allowed.forEach(k => {
    if (k in patch) {
      set.push(`${k}=?`)
      params.push(k === "completed" ? Number(patch[k]) : patch[k])
    }
  })

  if (set.length) {
    params.push(id, req.user.id)
    db.prepare(`UPDATE tasks SET ${set.join(", ")} WHERE id=? AND userId=?`).run(...params)
  }

  // re-agendar se necessário
  if ("datetime" in patch || "remind_minutes_before" in patch || "email" in patch || "title" in patch) {
    const updated = db.prepare("SELECT * FROM tasks WHERE id=?").get(id)
    if (timers.has(id)) clearTimeout(timers.get(id))
    scheduleTask(updated)
  }

  res.json({ ok: true })
})

// REMOVER
app.delete("/api/tasks/:id", auth, (req, res) => {
  db.prepare("DELETE FROM tasks WHERE id=? AND userId=?").run(req.params.id, req.user.id)

  if (timers.has(req.params.id)) {
    clearTimeout(timers.get(req.params.id))
    timers.delete(req.params.id)
  }

  res.json({ ok: true })
})




// ENVIAR AGORA
app.post("/api/tasks/:id/sendNow", auth, async (req, res) => {
  const id = Number(req.params.id)
  const row = db.prepare("SELECT * FROM tasks WHERE id=? AND userId=?")
                .get(id, req.user.id)

  if (!row) return res.status(404).json({ error: "Not found" })

  try {
    await transporter.sendMail({
      from: process.env.SMTP_FROM || process.env.SMTP_USER,
      to: row.email,
      subject: `Lembrete: ${row.title}`,
      text: `Sua tarefa está marcada para ${row.datetime}`
    })

    res.json({ ok: true })
  } catch (err) {
    console.error(err)
    res.status(500).json({ error: "Falha no envio" })
  }
})

// ENVIAR PARA OUTRO EMAIL
app.post("/api/tasks/:id/sendTo", auth, async (req, res) => {
  const id = Number(req.params.id)
  const { email } = req.body

  if (!email) return res.status(400).json({ error: "email é obrigatório" })

  const row = db.prepare("SELECT * FROM tasks WHERE id=? AND userId=?")
                .get(id, req.user.id)

  if (!row) return res.status(404).json({ error: "Not found" })

  try {
    await transporter.sendMail({
      from: process.env.SMTP_FROM || process.env.SMTP_USER,
      to: email,
      subject: `Tarefa: ${row.title}`,
      text: `Tarefa: ${row.title}\nQuando: ${row.datetime}`
    })

    res.json({ ok: true })
  } catch (err) {
    console.error(err)
    res.status(500).json({ error: "Falha no envio" })
  }
})

// ============================================================
// HEALTHCHECK
// ============================================================
app.get("/api/health", (_, res) => res.json({ ok: true }))

// ============================================================
// SERVER
// ============================================================
const PORT = process.env.PORT || 4000
app.listen(PORT, () => {
  console.log(`Servidor unificado rodando em http://localhost:${PORT}`)
})