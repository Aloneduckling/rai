import dotenv from 'dotenv';
dotenv.config({ path: './.env.test' });

/** @type {import('jest').Config} */
const config = {

  clearMocks: true,
  collectCoverage: false,
  coverageDirectory: "coverage",
  coverageProvider: "v8",
  preset: "ts-jest",
  testEnvironment: "node",
};

module.exports = config;