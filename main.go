package main

import (
	"log"
	"net/http"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
	"github.com/dgrijalva/jwt-go"
)

// User represents data about a user.
type User struct {
	ID       primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	Name     string             `bson:"name" json:"name"`
	Email    string             `bson:"email" json:"email"`
	Password string             `bson:"password" json:"password"`
	Date     time.Time          `bson:"date" json:"date"`
	TeamName string             `bson:"teamName" json:"teamName"`
	Money    int                `bson:"money" json:"money"`
}

// MongoDB configuration
const (
	MongoDBURI    ="mongodb+srv://umerfarooqdev:bigbang713@cbcteam.kgcnp1f.mongodb.net/?retryWrites=true&w=majority"
	DatabaseName  = "<database-name>"
	CollectionName = "<collection-name>"
)

// JWT configuration
const (
	SecretKey = "your-secret-key"
)

// Database connection
var (
	dbClient *mongo.Client
)

// Connect to MongoDB
func connectToMongoDB() (*mongo.Client, error) {
	clientOptions := options.Client().ApplyURI(MongoDBURI)
	client, err := mongo.Connect(nil, clientOptions)
	if err != nil {
		return nil, err
	}

	return client, nil
}

// HashPassword generates a hashed password using bcrypt
func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	return string(hash), nil
}

// ComparePassword compares a plain password with a hashed password
func ComparePassword(plainPassword, hashedPassword string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(plainPassword))
}

// GenerateJWT generates a JSON Web Token (JWT) for a user
func GenerateJWT(userID string) (string, error) {
	claims := jwt.MapClaims{
		"userId": userID,
		"exp":    time.Now().Add(time.Hour).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(SecretKey))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

// VerifyToken verifies the authenticity of a JWT
func VerifyToken(tokenString string) (*jwt.Token, error) {
	return jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte(SecretKey), nil
	})
}

func main() {
	router := gin.Default()

	// Connect to MongoDB
	var err error
	dbClient, err = connectToMongoDB()
	if err != nil {
		log.Fatal("Failed to connect to MongoDB:", err)
	}

	// CORS configuration
	router.Use(cors.Default())

	// Routes
	router.POST("/login", loginHandler)
	router.GET("/home", verifyTokenMiddleware, getUsersHandler)
	router.PATCH("/users/:userId", verifyTokenMiddleware, updateUserHandler)
	router.POST("/register", registerHandler)
	router.DELETE("/users/:userId", verifyTokenMiddleware, deleteUserHandler)

	// Start the server
	if err := router.Run(":4000"); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}

// Middleware to verify the authenticity of the JWT
func verifyTokenMiddleware(c *gin.Context) {
	tokenString := c.GetHeader("Authorization")
	if tokenString == "" {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"message": "Unauthorized"})
		return
	}

	token, err := VerifyToken(tokenString)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"message": "Unauthorized"})
		return
	}

	if !token.Valid {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"message": "Unauthorized"})
		return
	}

	c.Next()
}

// Login handler
func loginHandler(c *gin.Context) {
	var loginData struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := c.ShouldBindJSON(&loginData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	collection := dbClient.Database(DatabaseName).Collection(CollectionName)

	var user User
	if err := collection.FindOne(nil, bson.M{"email": loginData.Email}).Decode(&user); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"message": "User not found"})
		return
	}

	if err := ComparePassword(loginData.Password, user.Password); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "Invalid credentials"})
		return
	}

	token, err := GenerateJWT(user.ID.Hex())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to generate token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": token})
}

// Get users handler
func getUsersHandler(c *gin.Context) {
	collection := dbClient.Database(DatabaseName).Collection(CollectionName)

	var users []User
	cur, err := collection.Find(nil, bson.M{})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to fetch users"})
		return
	}
	defer cur.Close(nil)

	for cur.Next(nil) {
		var user User
		if err := cur.Decode(&user); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to decode user"})
			return
		}
		users = append(users, user)
	}

	c.JSON(http.StatusOK, users)
}

// Update user handler
func updateUserHandler(c *gin.Context) {
	userID := c.Param("userId")
	amount := c.PostForm("money")

	collection := dbClient.Database(DatabaseName).Collection(CollectionName)

	// Convert userID to ObjectID
	objID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid user ID"})
		return
	}

	filter := bson.M{"_id": objID}
	update := bson.M{"$inc": bson.M{"money": amount}}

	var updatedUser User
	if err := collection.FindOneAndUpdate(nil, filter, update).Decode(&updatedUser); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"message": "User not found"})
		return
	}

	c.JSON(http.StatusOK, updatedUser)
}

// Register handler
func registerHandler(c *gin.Context) {
	var registerData struct {
		Name     string `json:"name"`
		Email    string `json:"email"`
		Password string `json:"password"`
		Date     string `json:"date"`
		TeamName string `json:"teamName"`
		Money    int    `json:"money"`
	}

	if err := c.ShouldBindJSON(&registerData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	collection := dbClient.Database(DatabaseName).Collection(CollectionName)

	hashedPassword, err := HashPassword(registerData.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Something went wrong"})
		return
	}

	user := User{
		Name:     registerData.Name,
		Email:    registerData.Email,
		Password: hashedPassword,
		Date:     time.Now(),
		TeamName: registerData.TeamName,
		Money:    registerData.Money,
	}

	result, err := collection.InsertOne(nil, user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Something went wrong"})
		return
	}

	c.JSON(http.StatusOK, result.InsertedID)
}

// Delete user handler
func deleteUserHandler(c *gin.Context) {
	userID := c.Param("userId")
	password := c.PostForm("password")

	if password != "12345" {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "Unauthorized"})
		return
	}

	collection := dbClient.Database(DatabaseName).Collection(CollectionName)

	objID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid user ID"})
		return
	}

	filter := bson.M{"_id": objID}

	var deletedUser User
	if err := collection.FindOneAndDelete(nil, filter).Decode(&deletedUser); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"message": "User not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User deleted successfully"})
}
