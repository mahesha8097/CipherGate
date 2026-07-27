// middleware/errorHandler.js
// Centralized Express error handler. Keeps error responses consistent
// and avoids leaking stack traces in production.

class AppError extends Error {
  constructor(message, statusCode = 500) {
    super(message);
    this.statusCode = statusCode;
    this.isOperational = true;
    Error.captureStackTrace(this, this.constructor);
  }
}

function notFoundHandler(req, res, next) {
  const err = new AppError(`Route not found: ${req.method} ${req.originalUrl}`, 404);
  next(err);
}

function errorHandler(err, req, res, next) {
  const statusCode = err.statusCode || 500;
  const isProd = process.env.NODE_ENV === 'production';

  console.error(`[ERROR] ${req.method} ${req.originalUrl} ->`, err.message);
  if (!isProd) console.error(err.stack);

  res.status(statusCode).json({
    success: false,
    error: {
      message: err.message || 'Internal Server Error',
      ...(isProd ? {} : { stack: err.stack }),
    },
  });
}

module.exports = { errorHandler, notFoundHandler, AppError };
