package main

import (
	"encoding/base64"
	"go_security/tools"

	"github.com/gin-gonic/gin"
)

type BodyParam struct {
	Value string `json:"value"`
}

func main() {
	router := gin.Default()

	router.GET("gen_asymmetric_key", func(ctx *gin.Context) {
		key, err := tools.CreateAsymmectricEncription()
		if err != nil {
			ctx.JSON(500, err.Error())
		}

		ctx.JSON(200, key)
	})

	router.POST("encrypt", func(ctx *gin.Context) {
		body := BodyParam{}

		if err := ctx.ShouldBindJSON(&body); err != nil {
			ctx.JSON(500, err.Error())
			return
		}

		rest, err := tools.Encript(body.Value)
		if err != nil {
			ctx.JSON(500, err.Error())
			return
		}
		ctx.JSON(200, map[string]interface{}{"cipherText": rest})
	})

	router.POST("decrypt", func(ctx *gin.Context) {
		body := BodyParam{}

		if err := ctx.ShouldBindJSON(&body); err != nil {
			ctx.JSON(500, err.Error())
			return
		}

		ciphertext, err := base64.StdEncoding.DecodeString(body.Value)
		if err != nil {
			ctx.JSON(500, err.Error())
			return
		}

		rest, err := tools.Decrypt(ciphertext)
		if err != nil {
			ctx.JSON(500, err.Error())
			return
		}
		ctx.JSON(200, rest)
	})

	router.Run(":5002")
}
