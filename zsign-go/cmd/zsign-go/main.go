package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	_ "zsign-go/docs" // This is required for swag to find the generated docs
	"zsign-go/internal/signer"
	"zsign-go/internal/task"
)

const (
	storageDir = "temp_storage"
	numWorkers = 4
)

// @title zsign-go API
// @version 1.0
// @description This is an API server for signing iOS applications.
// @termsOfService http://swagger.io/terms/

// @contact.name API Support
// @contact.url http://www.swagger.io/support
// @contact.email support@swagger.io

// @license.name Apache 2.0
// @license.url http://www.apache.org/licenses/LICENSE-2.0.html

// @host localhost:8080
// @BasePath /
func main() {
	fmt.Println("zsign-go API server starting...")

	if err := os.MkdirAll(storageDir, 0755); err != nil {
		panic(fmt.Sprintf("failed to create storage directory: %v", err))
	}

	s := signer.NewSigner()
	tm := task.NewManager(s, storageDir, numWorkers)

	router := gin.Default()
	router.MaxMultipartMemory = 8 << 20 // 8 MiB

	router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	api := router.Group("/api")
	{
		api.POST("/sign", handleSign(tm))
		api.GET("/status/:task_id", handleStatus(tm))
		api.GET("/download/:file_id", handleDownload)
	}

	fmt.Println("Server is listening on :8080")
	router.Run(":8080")
}

// @Summary Start a new signing job
// @Description Upload an IPA file and associated credentials to start the signing process.
// @Accept  multipart/form-data
// @Produce  json
// @Param   ipa formData file true "The IPA file to sign"
// @Param   p12 formData file true "The .p12 file containing the certificate and private key"
// @Param   password formData string true "The password for the .p12 file"
// @Param   mobileprovision formData file true "The .mobileprovision file"
// @Success 202 {object} map[string]string "The ID of the newly created signing task"
// @Failure 400 {object} map[string]string
// @Router /api/sign [post]
func handleSign(tm *task.Manager) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Create a new task
		taskID := uuid.New().String()
		newTask := tm.CreateTask(taskID)

		// Create a directory for the task's files
		taskDir := filepath.Join(storageDir, taskID)
		if err := os.MkdirAll(taskDir, 0755); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create task directory"})
			return
		}

		// Save the uploaded files
		ipaFile, err := c.FormFile("ipa")
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "ipa file is required"})
			return
		}
		newTask.IPAPath = filepath.Join(taskDir, "source.ipa")
		if err := c.SaveUploadedFile(ipaFile, newTask.IPAPath); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save ipa file"})
			return
		}

		p12File, err := c.FormFile("p12")
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "p12 file is required"})
			return
		}
		newTask.P12Path = filepath.Join(taskDir, "cert.p12")
		if err := c.SaveUploadedFile(p12File, newTask.P12Path); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save p12 file"})
			return
		}

		provFile, err := c.FormFile("mobileprovision")
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "mobileprovision file is required"})
			return
		}
		newTask.ProvisionPath = filepath.Join(taskDir, "profile.mobileprovision")
		if err := c.SaveUploadedFile(provFile, newTask.ProvisionPath); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save mobileprovision file"})
			return
		}

		// Get the password
		newTask.Password = c.PostForm("password")
		if newTask.Password == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "password is required"})
			return
		}

		// Queue the task for processing
		tm.QueueTask(newTask)

		c.JSON(http.StatusAccepted, gin.H{
			"task_id": taskID,
		})
	}
}

// @Summary Get the status of a signing job
// @Description Get the status of a signing job by its task ID.
// @Produce  json
// @Param   task_id path string true "Task ID"
// @Success 200 {object} task.Task
// @Failure 404 {object} map[string]string
// @Router /api/status/{task_id} [get]
func handleStatus(tm *task.Manager) gin.HandlerFunc {
	return func(c *gin.Context) {
		taskID := c.Param("task_id")
		task, err := tm.GetTask(taskID)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, task)
	}
}

// @Summary Download a signed IPA file
// @Description Download a signed IPA file by its file ID (which is the task ID).
// @Produce  application/octet-stream
// @Param   file_id path string true "File ID"
// @Success 200 {file} file "The signed IPA file"
// @Failure 404
// @Router /api/download/{file_id} [get]
func handleDownload(c *gin.Context) {
	fileID := c.Param("file_id")
	filePath := filepath.Join(storageDir, fileID, "signed.ipa")
	c.File(filePath)
}