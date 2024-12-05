import { PrismaClient } from '@prisma/client';
import dotenv from 'dotenv';

// Load the .env.test file
dotenv.config({ path: './.env.test' });
console.log(process.env.DATABASE_URL);

const prisma = new PrismaClient({
  datasources: {
    db: {
      url: process.env.DATABASE_URL, // Use .env.test's DATABASE_URL
    },
  },
});

export default prisma;
