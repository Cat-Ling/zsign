package task

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"zsign-go/internal/signer"
)

// Status represents the status of a signing task.
type Status string

const (
	StatusPending   Status = "pending"
	StatusRunning   Status = "running"
	StatusSuccess   Status = "success"
	StatusFailed    Status = "failed"
)

// Task represents a single signing job.
type Task struct {
	ID            string    `json:"id"`
	Status        Status    `json:"status"`
	Error         string    `json:"error,omitempty"`
	DownloadURL   string    `json:"download_url,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	IPAPath       string    `json:"-"` // Path to the uploaded IPA
	P12Path       string    `json:"-"` // Path to the uploaded P12
	ProvisionPath string    `json:"-"` // Path to the uploaded mobileprovision
	Password      string    `json:"-"` // Password for the P12
}

// Manager orchestrates the signing tasks.
type Manager struct {
	tasks      map[string]*Task
	mu         sync.RWMutex
	jobQueue   chan *Task
	signer     *signer.Signer
	storageDir string
}

// NewManager creates and starts a new task manager.
func NewManager(signer *signer.Signer, storageDir string, numWorkers int) *Manager {
	m := &Manager{
		tasks:      make(map[string]*Task),
		jobQueue:   make(chan *Task, 100),
		signer:     signer,
		storageDir: storageDir,
	}

	for i := 0; i < numWorkers; i++ {
		go m.worker()
	}

	go m.cleanupWorker()

	return m
}

// CreateTask creates a new task and adds it to the manager.
func (m *Manager) CreateTask(id string) *Task {
	m.mu.Lock()
	defer m.mu.Unlock()

	task := &Task{
		ID:        id,
		Status:    StatusPending,
		CreatedAt: time.Now(),
	}
	m.tasks[id] = task
	return task
}

// QueueTask sends a task to the job queue for processing.
func (m *Manager) QueueTask(task *Task) {
	m.jobQueue <- task
}

// GetTask retrieves a task by its ID.
func (m *Manager) GetTask(id string) (*Task, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	task, ok := m.tasks[id]
	if !ok {
		return nil, errors.New("task not found")
	}
	return task, nil
}

// worker is a background goroutine that processes signing jobs.
func (m *Manager) worker() {
	for task := range m.jobQueue {
		m.updateTaskStatus(task.ID, StatusRunning, "", "")

		taskDir := filepath.Join(m.storageDir, task.ID)
		_, err := m.signer.Sign(task.IPAPath, task.P12Path, task.ProvisionPath, task.Password, taskDir)

		if err != nil {
			m.updateTaskStatus(task.ID, StatusFailed, err.Error(), "")
		} else {
			downloadURL := fmt.Sprintf("/api/download/%s", task.ID)
			m.updateTaskStatus(task.ID, StatusSuccess, "", downloadURL)
		}
	}
}

// cleanupWorker periodically removes old, completed tasks and their associated files.
func (m *Manager) cleanupWorker() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		m.mu.Lock()
		for id, task := range m.tasks {
			if (task.Status == StatusSuccess || task.Status == StatusFailed) && time.Since(task.CreatedAt) > 24*time.Hour {
				taskDir := filepath.Join(m.storageDir, task.ID)
				if err := os.RemoveAll(taskDir); err != nil {
					fmt.Printf("Error cleaning up task directory %s: %v\n", taskDir, err)
				}
				delete(m.tasks, id)
			}
		}
		m.mu.Unlock()
	}
}

// updateTaskStatus updates the status of a task in a thread-safe way.
func (m *Manager) updateTaskStatus(id string, status Status, errMsg string, downloadURL string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if task, ok := m.tasks[id]; ok {
		task.Status = status
		task.Error = errMsg
		task.DownloadURL = downloadURL
	}
}