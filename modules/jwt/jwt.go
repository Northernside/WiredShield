package jwt

import (
	"time"
	"wired/modules/env"

	"github.com/golang-jwt/jwt/v5"
)

var signingKey []byte

func Init() {
	signingKey = []byte(env.GetEnv("JWT_SECRET", ""))
}

func CreateToken(discordId string) (string, error) {
	claims := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"discord_id": discordId,
		"exp":        time.Now().Add(time.Hour * 24 * 7).Unix(),
	})

	token, err := claims.SignedString(signingKey)
	if err != nil {
		return "", err
	}

	return token, nil
}

func ValidateToken(token string) (jwt.MapClaims, error) {
	tokenObj, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrSignatureInvalid
		}

		return signingKey, nil
	})

	if err != nil {
		return nil, err
	}

	claims, ok := tokenObj.Claims.(jwt.MapClaims)
	if !ok || !tokenObj.Valid {
		return nil, jwt.ErrSignatureInvalid
	}

	// check if expired
	exp, ok := claims["exp"].(float64)
	if !ok {
		return nil, jwt.ErrTokenExpired
	}

	if int64(exp) < time.Now().Unix() {
		return nil, jwt.ErrTokenExpired
	}

	return claims, nil
}
