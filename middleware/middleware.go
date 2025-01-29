package middleware

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
)

type KeycloakClaim struct {
	Acr               string   `json:"acr"`
	AllowedOrigins    []string `json:"allowed-origins"`
	Aud               string   `json:"aud"`
	Azp               string   `json:"azp"`
	Email             string   `json:"email"`
	EmailVerified     bool     `json:"email_verified"`
	Exp               int      `json:"exp"`
	FamilyName        string   `json:"family_name"`
	GivenName         string   `json:"given_name"`
	Iat               int      `json:"iat"`
	Iss               string   `json:"iss"`
	Jti               string   `json:"jti"`
	Name              string   `json:"name"`
	PreferredUsername string   `json:"preferred_username"`
	RealmAccess       struct {
		Roles []string `json:"roles"`
	} `json:"realm_access"`
	ResourceAccess struct {
		Account struct {
			Roles []string `json:"roles"`
		} `json:"account"`
	} `json:"resource_access"`
	Scope        string `json:"scope"`
	SessionState string `json:"session_state"`
	Sid          string `json:"sid"`
	Sub          string `json:"sub"`
	Typ          string `json:"typ"`
}

// LoggingMiddleware logs request details
func LoggingMiddleware(c *fiber.Ctx) error {
	start := time.Now()
	err := c.Next()
	log.Printf("%s - %s %s %d %s", c.IP(), c.Method(), c.Path(), c.Response().StatusCode(), time.Since(start))
	return err
}

func AuthMiddleware(key []byte) fiber.Handler {
	return func(c *fiber.Ctx) error {
		token := c.Get("Authorization")
		//fmt.Println(" header Authorization =", token)
		if token == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Authorization token is missing",
			})
		}
		if strings.HasPrefix(token, "Bearer ") {
			token = strings.TrimPrefix(token, "Bearer ")
		}

		verified, err := verifyAccessToken(token, key)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": err.Error(),
			})
		}

		if claims, ok := verified.Claims.(jwt.MapClaims); ok && verified.Valid {
			//fmt.Printf("Token verified successfully! Claims: %v\n", claims)
			claimsJSON, _ := json.MarshalIndent(claims, "", "  ")
			// Print claims as JSON
			//	fmt.Println("claims js :", string(claimsJSON))
			claimBody := &KeycloakClaim{}
			err := json.Unmarshal(claimsJSON, claimBody)
			if err != nil {
				fmt.Println("unpack claims :", err.Error())
				return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
					"error": err.Error(),
				})
			}

			c.Locals("user", claimBody)
		} else {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Invalid token",
			})
		}

		return c.Next()
	}
}

func verifyAccessToken(tokenString string, keyPem []byte) (*jwt.Token, error) {
	// Parse and validate the JWT
	return jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Ensure the token uses the correct signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		// Provide the public key for signature verification
		return jwt.ParseRSAPublicKeyFromPEM(keyPem)
	})
}

func Test_call() {
	fmt.Println("Heloo")
}
