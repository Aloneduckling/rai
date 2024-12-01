import rateLimit from 'express-rate-limit';

const limiter = rateLimit({
    windowMs: 30 * 60 * 1000,
    max: 5,
    message: "Too many requests, please try again after 30 mins",
    standardHeaders: true,
    legacyHeaders: false

});

export default limiter;