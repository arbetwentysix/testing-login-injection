import pkg from 'pg';
import dotenv from 'dotenv';

dotenv.config();

const { Pool } = pkg;

const db = new Pool({
  connectionString: process.env.DATABASE_URL, // ambil dari .env
  ssl: {
    rejectUnauthorized: false, // penting untuk koneksi ke Vercel Postgres/Neon
  },
});

export default db;
