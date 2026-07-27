// middleware/logger.js
// Lightweight custom logger layered on top of morgan; logs each audit request
// with a timestamp, method, path, and response time.

function requestLogger(req, res, next) {
  const start = Date.now();
  res.on('finish', () => {
    const duration = Date.now() - start;
    const timestamp = new Date().toISOString();
    console.log(
      `[${timestamp}] ${req.method} ${req.originalUrl} -> ${res.statusCode} (${duration}ms)`
    );
  });
  next();
}

module.exports = requestLogger;
