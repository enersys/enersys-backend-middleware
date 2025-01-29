package middleware

import (
	"log"
	"time"

	"github.com/gofiber/fiber/v2"
)

// LoggingMiddleware logs request details
func LoggingMiddleware(c *fiber.Ctx) error {
	start := time.Now()
	err := c.Next()
	log.Printf("%s - %s %s %d %s", c.IP(), c.Method(), c.Path(), c.Response().StatusCode(), time.Since(start))
	return err
}

// AuthMiddleware verifies authorization headers
func AuthMiddleware(c *fiber.Ctx) error {
	token := c.Get("Authorization")
	if token == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Unauthorized",
		})
	}

	// Perform token validation here (JWT, API Key, etc.)
	return c.Next()
}
