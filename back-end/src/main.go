package main

import (
	"net/http"

	"github.com/globalsign/mgo"
	"github.com/globalsign/mgo/bson"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/dgrijalva/jwt-go"

	"fmt"
	"time"
)

type MongoClient struct {
	session *mgo.Session  // Mongo database session
	db      *mgo.Database // Mongo database
}

type UserInfo struct {
	UserName    string `bson:"username"`
	Password string `bson:"password"`
}


func main() {

	// Echo instance
	e := echo.New()

	// Middleware
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Static("/map", "/home/kim/data/map")
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins:     []string{"*"},
		AllowHeaders:     []string{"authorization", "Content-Type"},
		AllowCredentials: true,
		AllowMethods:     []string{echo.OPTIONS, echo.GET, echo.HEAD, echo.PUT, echo.PATCH, echo.POST, echo.DELETE},
	}))

	// Set Database
	mongoClient, err := newDbClient()
	if err != nil {
		e.Logger.Fatal(err)
		return
	}

	// Routes
	auth := e.Group("/api/auth")
	auth.POST("/signup", mongoClient.signup)
	auth.POST("/signin", mongoClient.signin)

	user := e.Group("/api/user")
	user.Use(middleware.JWT([]byte("secret")))
	user.GET("/userContent", mongoClient.userContent)

	// Start server
	e.Logger.Fatal(e.Start(":8080"))
}

// Return a pointer to the MongoClient
func newDbClient() (MongoClient, error) {
	m := MongoClient{}

	// Create the dial info for the Mongo session
	connectionString := "localhost:27017"
	mongoDBDialInfo := &mgo.DialInfo{
		Addrs:    []string{connectionString},
		Timeout:  time.Duration(5000) * time.Millisecond,
		Database: "mtss",
		Username: "",
		Password: "",
	}
	session, err := mgo.DialWithInfo(mongoDBDialInfo)
	if err != nil {
		return m, err
	}

	m.session = session
	m.db = session.DB("vuejs-login")

	fmt.Println("Connection mongo")

	return m, nil
}

func (mc MongoClient) getSessionCopy() *mgo.Session {
	return mc.session.Copy()
}

// Handler
func (mc MongoClient) userContent(c echo.Context) error {

	s := mc.getSessionCopy()
	defer s.Close()

	user := c.Get("user").(*jwt.Token)
	claims := user.Claims.(jwt.MapClaims)
	username := claims["username"].(string)

	var userInfo interface{}
	if err := s.DB(mc.db.Name).C("users").Find(bson.M{"username": username}).One(&userInfo); err != nil {
		return echo.ErrUnauthorized
	}

	return c.JSON(http.StatusOK, userInfo)
}

func (mc MongoClient) signup(c echo.Context) error {
	s := mc.getSessionCopy()
	defer s.Close()

	var user interface{}
	if err := c.Bind(&user); err != nil {
		return err
	}

	username := user.(interface{}).(map[string]interface{})["username"].(string)
	email := user.(interface{}).(map[string]interface{})["email"].(string)
	password := user.(interface{}).(map[string]interface{})["password"].(string)

	if err := s.DB(mc.db.Name).C("users").Insert(bson.M{"username": username, "email": email, "password": password}); err != nil {
		return c.String(http.StatusInternalServerError, "500 - InternalServerError")
	}

	return c.JSON(http.StatusOK, nil)
}

func (mc MongoClient) signin(c echo.Context) error {
	s := mc.getSessionCopy()
	defer s.Close()

	var user interface{}
	userInfo := UserInfo{}
	if err := c.Bind(&user); err != nil {
		return err
	}

	username := user.(interface{}).(map[string]interface{})["username"].(string)
	password := user.(interface{}).(map[string]interface{})["password"].(string)

	if err := s.DB(mc.db.Name).C("users").Find(bson.M{"username": username, "password": password}).One(&userInfo); err != nil {
		return echo.ErrUnauthorized
	}

	// Create token
	accessToken := jwt.New(jwt.SigningMethodHS256)

	// Set claims
	claims := accessToken.Claims.(jwt.MapClaims)
	claims["username"] = userInfo.UserName

	// Generate encoded token and send it as response.
	t, err := accessToken.SignedString([]byte("secret"))
	if err != nil {
		return err
	}

	return c.JSON(http.StatusOK, map[string]string{
		"accessToken": t,
	})
}